package sbom

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// Some AI formating and setup for PROJECT_NAME and PROJECT_VERSION from SBOM report, even I don't have idea what did put here.
// Too lazy to add each project name and version with regex or providing static, I leave it to automaticly use the one from SBOM.
// Separate same project name with Parent or Tag, that do the trick just fine.
// Example:
// trivy image --format cyclonedx --output sbom.json nginx:latest
// kubectl get sbom nginx-sbom -o json > sbom-crd.json
type FormatProcessor struct {
	verbose bool
	log     *logrus.Logger
}

func NewFormatProcessor(verbose bool) *FormatProcessor {
	return &FormatProcessor{
		verbose: verbose,
		log:     logrus.New(),
	}
}

// DetectSBOMFormat detects the format of the SBOM
func (fp *FormatProcessor) DetectSBOMFormat(data []byte) (string, error) {
	var generic map[string]interface{}
	if err := json.Unmarshal(data, &generic); err != nil {
		return "", fmt.Errorf("invalid JSON: %v", err)
	}

	// Check for Trivy Operator format
	if apiVersion, ok := generic["apiVersion"].(string); ok {
		if strings.Contains(apiVersion, "aquasecurity.github.io") {
			return "trivy-cyclonedx", nil
		}
	}

	// Check for standard CycloneDX
	if bomFormat, ok := generic["bomFormat"].(string); ok {
		if strings.EqualFold(bomFormat, "CycloneDX") {
			return "cyclonedx", nil
		}
	}

	// Check for SPDX
	if spdxVersion, ok := generic["spdxVersion"].(string); ok {
		if strings.HasPrefix(spdxVersion, "SPDX-") {
			return "spdx", nil
		}
	}

	// Check for SPDX dataLicense as alternative indicator
	if dataLicense, ok := generic["dataLicense"].(string); ok {
		if strings.Contains(dataLicense, "CC0-1.0") {
			return "spdx", nil
		}
	}

	return "", fmt.Errorf("unknown SBOM format")
}

// ProcessSBOM processes the SBOM based on its detected format
func (fp *FormatProcessor) ProcessSBOM(rawSBOM []byte, nameTemplate, versionTemplate, fallbackProject string) (*SBOMProcessingResult, error) {
	format, err := fp.DetectSBOMFormat(rawSBOM)
	if err != nil {
		return nil, fmt.Errorf("failed to detect SBOM format: %v", err)
	}

	fp.log.WithFields(logrus.Fields{
		"format": format,
		"size":   len(rawSBOM),
	}).Info("Detected SBOM format")

	switch format {
	case "trivy-cyclonedx":
		return fp.processTrivyCycloneDX(rawSBOM, nameTemplate, versionTemplate, fallbackProject)
	case "cyclonedx":
		return fp.processStandardCycloneDX(rawSBOM, nameTemplate, versionTemplate, fallbackProject)
	case "spdx":
		return fp.processSPDX(rawSBOM, nameTemplate, versionTemplate, fallbackProject)
	default:
		return nil, fmt.Errorf("unsupported SBOM format: %s", format)
	}
}

// processTrivyCycloneDX processes Trivy Operator CycloneDX format
func (fp *FormatProcessor) processTrivyCycloneDX(rawSBOM []byte, nameTemplate, versionTemplate, fallbackProject string) (*SBOMProcessingResult, error) {
	var trivySBOM TrivySBOM
	if err := json.Unmarshal(rawSBOM, &trivySBOM); err != nil {
		return nil, fmt.Errorf("failed to parse Trivy SBOM: %v", err)
	}

	// Extract project information with enhanced fallback handling for Trivy Operator
	projectName, projectVersion, err := fp.extractProjectInfoWithFallbacks(trivySBOM, nameTemplate, versionTemplate, fallbackProject, rawSBOM)
	if err != nil {
		return nil, fmt.Errorf("failed to extract project info: %v", err)
	}

	// The "components" field in Trivy SBOM is actually the complete CycloneDX BOM
	var cycloneDXBOM map[string]interface{}
	switch components := trivySBOM.Report.Components.(type) {
	case map[string]interface{}:
		cycloneDXBOM = components
	default:
		return nil, fmt.Errorf("unexpected components type: %T", trivySBOM.Report.Components)
	}

	// Ensure we have the required CycloneDX fields
	if cycloneDXBOM["bomFormat"] == nil {
		cycloneDXBOM["bomFormat"] = "CycloneDX"
	}
	if cycloneDXBOM["specVersion"] == nil {
		cycloneDXBOM["specVersion"] = "1.6"
	}

	// Count components and dependencies
	componentsCount := 0
	dependenciesCount := 0

	if components, ok := cycloneDXBOM["components"].([]interface{}); ok {
		componentsCount = len(components)
		sanitizedComponents := fp.sanitizeComponents(components)
		cycloneDXBOM["components"] = sanitizedComponents
	}

	if dependencies, ok := cycloneDXBOM["dependencies"].([]interface{}); ok {
		dependenciesCount = len(dependencies)
	}

	// Convert to JSON
	output, err := json.Marshal(cycloneDXBOM)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CycloneDX BOM: %v", err)
	}

	if fp.verbose {
		fp.log.WithFields(logrus.Fields{
			"bom_format":      cycloneDXBOM["bomFormat"],
			"spec_version":    cycloneDXBOM["specVersion"],
			"components":      componentsCount,
			"dependencies":    dependenciesCount,
			"output_size":     len(output),
			"project_name":    projectName,
			"project_version": projectVersion,
		}).Debug("Processed Trivy CycloneDX BOM")
	}

	return &SBOMProcessingResult{
		BOMData:        output,
		ProjectName:    projectName,
		ProjectVersion: projectVersion,
		Format:         "cyclonedx",
		Components:     componentsCount,
		Dependencies:   dependenciesCount,
	}, nil
}

// extractProjectInfoWithFallbacks extracts project information with multiple fallback strategies
func (fp *FormatProcessor) extractProjectInfoWithFallbacks(trivySBOM TrivySBOM, nameTemplate, versionTemplate, fallbackProject string, rawSBOM []byte) (string, string, error) {
	var projectName, projectVersion string
	var err error

	// First attempt: Use template-based extraction
	projectName, projectVersion, err = fp.extractProjectInfo(trivySBOM, nameTemplate, versionTemplate, fallbackProject)
	if err == nil && projectName != "" && projectName != fallbackProject {
		return projectName, projectVersion, nil
	}

	// Second attempt: Extract from artifact repository
	if trivySBOM.Report.Artifact.Repository != "" {
		projectName = trivySBOM.Report.Artifact.Repository
		projectVersion = trivySBOM.Report.Artifact.Tag
		if projectVersion == "" {
			projectVersion = "latest"
		}
		fp.log.WithFields(logrus.Fields{
			"source":          "artifact.repository",
			"project_name":    projectName,
			"project_version": projectVersion,
		}).Warn("Used artifact repository as project name fallback")
		return projectName, projectVersion, nil
	}

	// Third attempt: Extract from Kubernetes metadata in raw SBOM
	if k8sName, k8sVersion := fp.extractFromKubernetesMetadata(rawSBOM); k8sName != "" {
		projectName = k8sName
		if k8sVersion != "" {
			projectVersion = k8sVersion
		} else {
			projectVersion = "unknown"
		}
		fp.log.WithFields(logrus.Fields{
			"source":          "kubernetes_metadata",
			"project_name":    projectName,
			"project_version": projectVersion,
		}).Warn("Used Kubernetes metadata as project name fallback")
		return projectName, projectVersion, nil
	}

	// Fourth attempt: Extract from CycloneDX components in the report
	if components, ok := trivySBOM.Report.Components.(map[string]interface{}); ok {
		if name, version := fp.extractFromCycloneDXComponents(components); name != "" {
			projectName = name
			projectVersion = version
			fp.log.WithFields(logrus.Fields{
				"source":          "cyclonedx_components",
				"project_name":    projectName,
				"project_version": projectVersion,
			}).Warn("Used CycloneDX components as project name fallback")
			return projectName, projectVersion, nil
		}
	}

	// Final fallback: Generate a name based on available context
	projectName = fp.generateContextualProjectName(trivySBOM, rawSBOM)
	projectVersion = "unknown"

	if projectName == "" {
		return "", "", fmt.Errorf("all fallback strategies failed to determine project name")
	}

	fp.log.WithFields(logrus.Fields{
		"source":          "contextual_generation",
		"project_name":    projectName,
		"project_version": projectVersion,
	}).Warn("Used contextual generation as final project name fallback")

	return projectName, projectVersion, nil
}

// extractFromKubernetesMetadata extracts project name from Kubernetes metadata in raw SBOM
func (fp *FormatProcessor) extractFromKubernetesMetadata(rawSBOM []byte) (string, string) {
	var generic map[string]interface{}
	if err := json.Unmarshal(rawSBOM, &generic); err != nil {
		return "", ""
	}

	// Check for Kubernetes metadata in Trivy Operator format
	if metadata, ok := generic["metadata"].(map[string]interface{}); ok {
		// Try to extract from labels
		if labels, ok := metadata["labels"].(map[string]interface{}); ok {
			if resourceName, ok := labels["trivy-operator.resource.name"].(string); ok {
				if resourceNamespace, ok := labels["trivy-operator.resource.namespace"].(string); ok {
					return fmt.Sprintf("%s-%s", resourceNamespace, resourceName), ""
				}
				return resourceName, ""
			}
		}

		// Try to extract from name and namespace
		if name, ok := metadata["name"].(string); ok {
			name = strings.TrimSuffix(name, "-sbom")
			name = strings.TrimSuffix(name, "-vulnerabilityreport")

			if namespace, ok := metadata["namespace"].(string); ok {
				return fmt.Sprintf("%s-%s", namespace, name), ""
			}
			return name, ""
		}
	}

	return "", ""
}

// extractFromCycloneDXComponents extracts project info from CycloneDX components
func (fp *FormatProcessor) extractFromCycloneDXComponents(components map[string]interface{}) (string, string) {
	// Check metadata component first
	if metadata, ok := components["metadata"].(map[string]interface{}); ok {
		if component, ok := metadata["component"].(map[string]interface{}); ok {
			if name, ok := component["name"].(string); ok && name != "" {
				version := ""
				if ver, ok := component["version"].(string); ok {
					version = ver
				}
				return name, version
			}
		}
	}

	// Check first component in components array
	if comps, ok := components["components"].([]interface{}); ok && len(comps) > 0 {
		if firstComp, ok := comps[0].(map[string]interface{}); ok {
			if name, ok := firstComp["name"].(string); ok && name != "" {
				// Clean up common component names to use as project name
				if !isCommonDependencyName(name) {
					return name, ""
				}
			}
		}
	}

	return "", ""
}

// generateContextualProjectName generates a project name based on available context
func (fp *FormatProcessor) generateContextualProjectName(trivySBOM TrivySBOM, rawSBOM []byte) string {
	// Try to extract from report type or other contextual information
	if trivySBOM.Kind != "" {
		// Remove "Report" suffix and convert to lowercase
		kind := strings.TrimSuffix(trivySBOM.Kind, "Report")
		kind = strings.ToLower(kind)
		return fmt.Sprintf("k8s-%s-%d", kind, time.Now().Unix())
	}

	// Final fallback with timestamp
	return fmt.Sprintf("unknown-k8s-project-%d", time.Now().Unix())
}

// isCommonDependencyName checks if a name is likely a dependency rather than a main project
func isCommonDependencyName(name string) bool {
	commonDeps := []string{
		"golang", "node", "python", "java", "rust", "cargo",
		"openssl", "zlib", "libc", "glibc", "musl",
		"busybox", "alpine", "debian", "ubuntu", "centos",
	}

	lowerName := strings.ToLower(name)
	for _, dep := range commonDeps {
		if strings.Contains(lowerName, dep) {
			return true
		}
	}
	return false
}

// extractProjectInfo extracts project information from Trivy SBOM (original implementation)
func (fp *FormatProcessor) extractProjectInfo(trivySBOM TrivySBOM, nameTemplate, versionTemplate, fallbackProject string) (string, string, error) {
	// Extract project name
	projectName := fallbackProject
	if nameTemplate == "[[.sbomReport.report.artifact.repository]]" {
		if trivySBOM.Report.Artifact.Repository == "" {
			return "", "", fmt.Errorf("repository not found in SBOM")
		}
		projectName = trivySBOM.Report.Artifact.Repository
	} else if nameTemplate != "" && nameTemplate != fallbackProject {
		// Handle other template patterns if needed
		projectName = nameTemplate
	}

	// Extract project version
	projectVersion := "unknown"
	if versionTemplate == "[[.sbomReport.report.artifact.tag]]" {
		if trivySBOM.Report.Artifact.Tag != "" {
			projectVersion = trivySBOM.Report.Artifact.Tag
		}
	} else if versionTemplate != "" && versionTemplate != "unknown" {
		// Handle other template patterns if needed
		projectVersion = versionTemplate
	}

	// Clean up the project name
	projectName = strings.TrimSpace(projectName)
	projectVersion = strings.TrimSpace(projectVersion)

	if projectName == "" {
		return "", "", fmt.Errorf("project name is empty")
	}

	if fp.verbose {
		fp.log.WithFields(logrus.Fields{
			"project_name":     projectName,
			"project_version":  projectVersion,
			"repository":       trivySBOM.Report.Artifact.Repository,
			"tag":              trivySBOM.Report.Artifact.Tag,
			"template_name":    nameTemplate,
			"template_version": versionTemplate,
			"format":           "trivy-operator",
		}).Debug("Extracted project information from Trivy Operator format")
	}

	return projectName, projectVersion, nil
}

// processStandardCycloneDX processes standard CycloneDX format with enhanced project name handling
func (fp *FormatProcessor) processStandardCycloneDX(rawSBOM []byte, nameTemplate, versionTemplate, fallbackProject string) (*SBOMProcessingResult, error) {
	var cycloneDXBOM map[string]interface{}
	if err := json.Unmarshal(rawSBOM, &cycloneDXBOM); err != nil {
		return nil, fmt.Errorf("failed to parse CycloneDX BOM: %v", err)
	}

	// Normalize the BOM structure
	if err := fp.normalizeCycloneDXBOM(cycloneDXBOM); err != nil {
		return nil, fmt.Errorf("failed to normalize CycloneDX BOM: %v", err)
	}

	// Extract project information from CycloneDX metadata with fallbacks
	projectName, projectVersion := fp.extractProjectFromCycloneDXMapWithFallbacks(cycloneDXBOM, nameTemplate, versionTemplate, fallbackProject, rawSBOM)

	// Count components and dependencies
	componentsCount := 0
	dependenciesCount := 0

	if components, ok := cycloneDXBOM["components"].([]interface{}); ok {
		componentsCount = len(components)
		sanitizedComponents := fp.sanitizeComponents(components)
		cycloneDXBOM["components"] = sanitizedComponents
	}

	if dependencies, ok := cycloneDXBOM["dependencies"].([]interface{}); ok {
		dependenciesCount = len(dependencies)
	}

	// Convert back to JSON
	output, err := json.Marshal(cycloneDXBOM)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CycloneDX BOM: %v", err)
	}

	if fp.verbose {
		fp.log.WithFields(logrus.Fields{
			"bom_format":      cycloneDXBOM["bomFormat"],
			"spec_version":    cycloneDXBOM["specVersion"],
			"components":      componentsCount,
			"dependencies":    dependenciesCount,
			"output_size":     len(output),
			"project_name":    projectName,
			"project_version": projectVersion,
		}).Debug("Processed standard CycloneDX BOM")
	}

	return &SBOMProcessingResult{
		BOMData:        output,
		ProjectName:    projectName,
		ProjectVersion: projectVersion,
		Format:         "cyclonedx",
		Components:     componentsCount,
		Dependencies:   dependenciesCount,
	}, nil
}

// extractProjectFromCycloneDXMapWithFallbacks extracts project info with multiple fallback strategies
func (fp *FormatProcessor) extractProjectFromCycloneDXMapWithFallbacks(bom map[string]interface{}, nameTemplate, versionTemplate, fallbackProject string, rawSBOM []byte) (string, string) {
	projectName := fallbackProject
	projectVersion := "unknown"

	// First attempt: Extract from metadata component
	if metadata, ok := bom["metadata"].(map[string]interface{}); ok {
		if component, ok := metadata["component"].(map[string]interface{}); ok {
			// Extract name from metadata.component.name (e.g., "nginx:1.28.0")
			if name, ok := component["name"].(string); ok && name != "" {
				projectName = name

				// If name contains version (like "nginx:1.28.0"), split it
				if strings.Contains(projectName, ":") {
					parts := strings.Split(projectName, ":")
					if len(parts) == 2 {
						projectName = parts[0] // "nginx"
						if projectVersion == "unknown" {
							projectVersion = parts[1] // "1.28.0"
						}
					}
				}
			}

			// Extract version from metadata.component.version (direct version field)
			if version, ok := component["version"].(string); ok && version != "" {
				projectVersion = version
			}

			// Also check for version in purl if available
			if purl, ok := component["purl"].(string); ok && projectVersion == "unknown" {
				if version := extractVersionFromPURL(purl); version != "" {
					projectVersion = version
				}
			}
		}
	}

	// Second attempt: If still using fallback, try to extract from components
	if projectName == fallbackProject || projectName == "" {
		if components, ok := bom["components"].([]interface{}); ok && len(components) > 0 {
			// Look for the main application component (not a library/dependency)
			for _, comp := range components {
				if compMap, ok := comp.(map[string]interface{}); ok {
					if name, ok := compMap["name"].(string); ok && name != "" {
						if !isCommonDependencyName(name) {
							projectName = name + "-app"
							if version, ok := compMap["version"].(string); ok {
								projectVersion = version
							}
							break
						}
					}
				}
			}
		}
	}

	// Handle template patterns
	projectName, projectVersion = fp.applyTemplates(projectName, projectVersion, nameTemplate, versionTemplate, fallbackProject)

	// Final fallback if still empty
	if projectName == "" || projectName == fallbackProject {
		projectName = "cyclonedx-project"
		fp.log.WithFields(logrus.Fields{
			"fallback_reason": "no_project_name_detected",
			"project_name":    projectName,
		}).Warn("Using default project name for CycloneDX BOM")
	}

	// Clean up
	projectName = strings.TrimSpace(projectName)
	projectVersion = strings.TrimSpace(projectVersion)

	if fp.verbose {
		fp.log.WithFields(logrus.Fields{
			"project_name":     projectName,
			"project_version":  projectVersion,
			"template_name":    nameTemplate,
			"template_version": versionTemplate,
			"format":           "cyclonedx",
			"source":           "metadata.component",
		}).Debug("Extracted project information from CycloneDX format")
	}

	return projectName, projectVersion
}

// applyTemplates applies name and version templates with proper handling
func (fp *FormatProcessor) applyTemplates(projectName, projectVersion, nameTemplate, versionTemplate, fallbackProject string) (string, string) {
	resultName := projectName
	resultVersion := projectVersion

	// Handle name template
	if nameTemplate == "[[.sbomReport.report.artifact.repository]]" {
		// This template is for Trivy Operator format, not standard CycloneDX
		// Keep the name we already extracted
		if resultName == "" || resultName == fallbackProject {
			resultName = "cyclonedx-project"
		}
	} else if nameTemplate != "" && nameTemplate != fallbackProject {
		resultName = nameTemplate
	}

	// Handle version template
	if versionTemplate == "[[.sbomReport.report.artifact.tag]]" {
		// This template is for Trivy Operator format
		// Keep the version we already extracted
	} else if versionTemplate != "" && versionTemplate != "unknown" {
		resultVersion = versionTemplate
	}

	return resultName, resultVersion
}

// normalizeCycloneDXBOM normalizes the CycloneDX BOM structure to handle variations
func (fp *FormatProcessor) normalizeCycloneDXBOM(bom map[string]interface{}) error {
	// Ensure we have the required CycloneDX fields
	if bom["bomFormat"] == nil {
		bom["bomFormat"] = "CycloneDX"
	}
	if bom["specVersion"] == nil {
		bom["specVersion"] = "1.4"
	}

	// Normalize metadata if it exists
	if metadata, ok := bom["metadata"].(map[string]interface{}); ok {
		// Normalize tools field - handle both object and array formats
		if tools, exists := metadata["tools"]; exists {
			normalizedTools, err := fp.normalizeToolsField(tools)
			if err != nil {
				fp.log.WithError(err).Warn("Failed to normalize tools field, removing it")
				delete(metadata, "tools")
			} else {
				metadata["tools"] = normalizedTools
			}
		}

		// Normalize component if it exists
		if component, exists := metadata["component"]; exists {
			if componentMap, ok := component.(map[string]interface{}); ok {
				fp.normalizeComponent(componentMap)
			}
		}
	}

	// Normalize components array
	if components, ok := bom["components"].([]interface{}); ok {
		for _, component := range components {
			if componentMap, ok := component.(map[string]interface{}); ok {
				fp.normalizeComponent(componentMap)
			}
		}
	}

	return nil
}

// normalizeToolsField handles both object and array formats for tools
func (fp *FormatProcessor) normalizeToolsField(tools interface{}) ([]map[string]interface{}, error) {
	switch t := tools.(type) {
	case []interface{}:
		// Already an array, normalize each tool
		result := make([]map[string]interface{}, 0, len(t))
		for _, tool := range t {
			if toolMap, ok := tool.(map[string]interface{}); ok {
				normalizedTool := fp.normalizeTool(toolMap)
				result = append(result, normalizedTool)
			}
		}
		return result, nil

	case map[string]interface{}:
		// Single tool object, convert to array
		normalizedTool := fp.normalizeTool(t)
		return []map[string]interface{}{normalizedTool}, nil

	default:
		return nil, fmt.Errorf("unexpected tools type: %T", tools)
	}
}

// normalizeTool ensures a tool has the expected structure
func (fp *FormatProcessor) normalizeTool(tool map[string]interface{}) map[string]interface{} {
	normalized := make(map[string]interface{})

	// Copy expected fields
	if vendor, ok := tool["vendor"].(string); ok {
		normalized["vendor"] = vendor
	}
	if name, ok := tool["name"].(string); ok {
		normalized["name"] = name
	}
	if version, ok := tool["version"].(string); ok {
		normalized["version"] = version
	}

	// If it's a Trivy tool, ensure proper structure
	if name, _ := tool["name"].(string); name == "trivy" {
		normalized["vendor"] = "aquasecurity"
		normalized["name"] = "trivy"
		if version, ok := tool["version"].(string); !ok || version == "" {
			normalized["version"] = "unknown"
		}
	}

	return normalized
}

// normalizeComponent ensures a component has the expected structure
// Fix for: https://github.com/aquasecurity/trivy-operator/issues/2735
func (fp *FormatProcessor) normalizeComponent(component map[string]interface{}) {
	// Ensure purl is properly formatted
	if purl, ok := component["purl"].(string); ok {
		cleanedPurl := strings.ReplaceAll(purl, "%3A", ":")
		cleanedPurl = strings.ReplaceAll(cleanedPurl, "%2F", "/")
		cleanedPurl = strings.ReplaceAll(cleanedPurl, "%40", "@")
		component["purl"] = cleanedPurl
	}

	// Ensure bom-ref is properly formatted
	if bomRef, ok := component["bom-ref"].(string); ok {
		cleanedBomRef := strings.ReplaceAll(bomRef, "%3A", ":")
		cleanedBomRef = strings.ReplaceAll(cleanedBomRef, "%2F", "/")
		cleanedBomRef = strings.ReplaceAll(cleanedBomRef, "%40", "@")
		component["bom-ref"] = cleanedBomRef
	}

	// Fix invalid license structures - SPECIFIC CASE: expression with empty license object
	if licenses, ok := component["licenses"].([]interface{}); ok {
		normalizedLicenses := make([]interface{}, 0, len(licenses))

		for _, license := range licenses {
			if licenseMap, ok := license.(map[string]interface{}); ok {
				// Check for the specific invalid case: both expression AND empty license object
				expression, hasExpression := licenseMap["expression"].(string)
				licenseObj, hasLicenseObj := licenseMap["license"].(map[string]interface{})

				if hasExpression && expression != "" && hasLicenseObj && len(licenseObj) == 0 {
					// This is the invalid case: remove the empty license object, keep the expression
					delete(licenseMap, "license")
					normalizedLicenses = append(normalizedLicenses, map[string]interface{}{
						"expression": expression,
					})
					fp.log.WithFields(logrus.Fields{
						"expression": expression,
					}).Debug("Fixed invalid license: removed empty license object, kept expression")
				} else if hasExpression && expression != "" && (!hasLicenseObj || len(licenseObj) > 0) {
					// Valid case: expression with no license object or with non-empty license object
					normalizedLicenses = append(normalizedLicenses, licenseMap)
				} else if hasLicenseObj && len(licenseObj) > 0 {
					// Valid case: license object with content
					normalizedLicenses = append(normalizedLicenses, licenseMap)
				} else {
					// Other cases: preserve the original
					normalizedLicenses = append(normalizedLicenses, licenseMap)
				}
			} else {
				// Preserve non-map license entries
				normalizedLicenses = append(normalizedLicenses, license)
			}
		}

		// Update the licenses array with normalized entries
		if len(normalizedLicenses) > 0 {
			component["licenses"] = normalizedLicenses
		}
	}
}

// extractVersionFromPURL extracts version from Package URL
func extractVersionFromPURL(purl string) string {
	// Example: pkg:oci/nginx@sha256%3A10f4f3e09ace179005137b811167c8dc03c089b60059236d45c340f1f1e56ac3?arch=amd64&repository_url=index.docker.io%2Flibrary%2Fnginx
	// Or: pkg:oci/nginx@1.28.0

	// Look for @version pattern
	atIndex := strings.LastIndex(purl, "@")
	if atIndex == -1 {
		return ""
	}

	// Get the part after @
	afterAt := purl[atIndex+1:]

	// Remove query parameters if present
	if questionIndex := strings.Index(afterAt, "?"); questionIndex != -1 {
		afterAt = afterAt[:questionIndex]
	}

	// Remove sha256 hashes (they start with sha256:)
	if strings.HasPrefix(afterAt, "sha256:") {
		return ""
	}

	// If it looks like a version (contains numbers and dots), return it
	if containsVersionChars(afterAt) {
		return afterAt
	}

	return ""
}

// containsVersionChars checks if a string contains version-like characters
func containsVersionChars(s string) bool {
	// Version strings typically contain numbers, dots, dashes
	for _, char := range s {
		if (char >= '0' && char <= '9') || char == '.' || char == '-' {
			return true
		}
	}
	return false
}

// processSPDX processes SPDX format
func (fp *FormatProcessor) processSPDX(rawSBOM []byte, nameTemplate, versionTemplate, fallbackProject string) (*SBOMProcessingResult, error) {
	var spdxDoc SPDXDocument
	if err := json.Unmarshal(rawSBOM, &spdxDoc); err != nil {
		return nil, fmt.Errorf("failed to parse SPDX document: %v", err)
	}

	// Extract project information from SPDX - handle templates appropriately
	projectName, projectVersion := fp.extractProjectFromSPDX(spdxDoc, nameTemplate, versionTemplate, fallbackProject)
	// Count packages
	packagesCount := len(spdxDoc.Packages)

	if fp.verbose {
		fp.log.WithFields(logrus.Fields{
			"spdx_version":    spdxDoc.SPDXVersion,
			"document_name":   spdxDoc.Name,
			"packages":        packagesCount,
			"project_name":    projectName,
			"project_version": projectVersion,
		}).Debug("Processed SPDX document")
	}

	// For SPDX, we just pass through the original data since DependencyTrack supports SPDX
	return &SBOMProcessingResult{
		BOMData:        rawSBOM,
		ProjectName:    projectName,
		ProjectVersion: projectVersion,
		Format:         "spdx",
		Components:     packagesCount,
		Dependencies:   0, // SPDX doesn't have explicit dependencies like CycloneDX
	}, nil
}

// extractProjectFromSPDX extracts project info from SPDX document
func (fp *FormatProcessor) extractProjectFromSPDX(doc SPDXDocument, nameTemplate, versionTemplate, fallbackProject string) (string, string) {
	projectName := fallbackProject
	projectVersion := "unknown"

	// Try to extract from document name
	if projectName == "" || projectName == fallbackProject {
		projectName = doc.Name
	}

	// Handle template patterns for SPDX format
	if nameTemplate == "[[.sbomReport.report.artifact.repository]]" {
		// This template is for Trivy Operator format, not SPDX
		// Use document name or fallback
		if projectName == fallbackProject {
			projectName = "spdx-document"
		}
	} else if nameTemplate != "" && nameTemplate != fallbackProject {
		projectName = nameTemplate
	}

	if versionTemplate == "[[.sbomReport.report.artifact.tag]]" {
		// This template is for Trivy Operator format
		// Use "unknown" or extracted version
	} else if versionTemplate != "" && versionTemplate != "unknown" {
		projectVersion = versionTemplate
	}

	// Clean up
	projectName = strings.TrimSpace(projectName)
	projectVersion = strings.TrimSpace(projectVersion)

	if projectName == "" {
		projectName = "unknown-project"
	}

	if fp.verbose {
		fp.log.WithFields(logrus.Fields{
			"project_name":     projectName,
			"project_version":  projectVersion,
			"template_name":    nameTemplate,
			"template_version": versionTemplate,
			"format":           "spdx",
		}).Debug("Extracted project information from SPDX format")
	}

	return projectName, projectVersion
}

func (fp *FormatProcessor) sanitizeComponents(arr []interface{}) []interface{} {
	out := make([]interface{}, 0, len(arr))
	for _, raw := range arr {
		cm, ok := raw.(map[string]interface{})
		if !ok {
			out = append(out, raw)
			continue
		}

		// Clean up licenses - FIX SPECIFIC INVALID CASE
		if licRaw, ok := cm["licenses"]; ok {
			if licArr, ok := licRaw.([]interface{}); ok {
				newLic := make([]interface{}, 0)
				for _, l := range licArr {
					if lm, ok := l.(map[string]interface{}); ok {
						// Check for the specific invalid case: expression with empty license object
						expression, hasExpression := lm["expression"].(string)
						licenseObj, hasLicenseObj := lm["license"].(map[string]interface{})

						if hasExpression && expression != "" && hasLicenseObj && len(licenseObj) == 0 {
							// Invalid case: remove empty license object, keep expression
							delete(lm, "license")
							newLic = append(newLic, map[string]interface{}{
								"expression": expression,
							})
							fp.log.WithFields(logrus.Fields{
								"expression": expression,
							}).Debug("Sanitized: removed empty license object, kept expression")
						} else {
							// All other cases: preserve as-is
							newLic = append(newLic, l)
						}
					} else {
						// Non-map license entries: preserve as-is
						newLic = append(newLic, l)
					}
				}
				if len(newLic) > 0 {
					cm["licenses"] = newLic
				}
			}
		}

		// Ensure purl is properly formatted
		if purl, ok := cm["purl"].(string); ok {
			cleanedPurl := strings.ReplaceAll(purl, "%3A", ":")
			cleanedPurl = strings.ReplaceAll(cleanedPurl, "%2F", "/")
			cleanedPurl = strings.ReplaceAll(cleanedPurl, "%40", "@")
			cm["purl"] = cleanedPurl
		}

		// Ensure bom-ref is properly formatted
		if bomRef, ok := cm["bom-ref"].(string); ok {
			cleanedBomRef := strings.ReplaceAll(bomRef, "%3A", ":")
			cleanedBomRef = strings.ReplaceAll(cleanedBomRef, "%2F", "/")
			cleanedBomRef = strings.ReplaceAll(cleanedBomRef, "%40", "@")
			cm["bom-ref"] = cleanedBomRef
		}

		// Clean up properties if they exist
		if properties, ok := cm["properties"].([]interface{}); ok {
			cleanedProperties := make([]interface{}, 0)
			for _, prop := range properties {
				if propMap, ok := prop.(map[string]interface{}); ok {
					// Clean up property values
					if value, ok := propMap["value"].(string); ok {
						propMap["value"] = strings.ReplaceAll(value, "%3A", ":")
						propMap["value"] = strings.ReplaceAll(propMap["value"].(string), "%2F", "/")
					}
					cleanedProperties = append(cleanedProperties, propMap)
				} else {
					cleanedProperties = append(cleanedProperties, prop)
				}
			}
			cm["properties"] = cleanedProperties
		}

		out = append(out, cm)
	}
	return out
}
