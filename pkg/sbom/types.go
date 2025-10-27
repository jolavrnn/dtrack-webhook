package sbom

// Use this structure for Trivy-specific SBOMs.
type TrivySBOM struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name      string            `json:"name"`
		Namespace string            `json:"namespace"`
		Labels    map[string]string `json:"labels"`
	} `json:"metadata"`
	Report struct {
		Artifact struct {
			Repository string `json:"repository"`
			Tag        string `json:"tag"`
			Digest     string `json:"digest"`
		} `json:"artifact"`
		Registry struct {
			Server string `json:"server"`
		} `json:"registry"`
		Scanner struct {
			Name    string `json:"name"`
			Vendor  string `json:"vendor"`
			Version string `json:"version"`
		} `json:"scanner"`
		Components interface{} `json:"components"` // This contains the actual CycloneDX BOM
		Summary    struct {
			ComponentsCount   int `json:"componentsCount"`
			DependenciesCount int `json:"dependenciesCount"`
		} `json:"summary"`
		UpdateTimestamp string `json:"updateTimestamp"`
	} `json:"report"`
}
type CycloneDXBOM struct {
	BOMFormat    string                `json:"bomFormat"`
	SpecVersion  string                `json:"specVersion"`
	SerialNumber string                `json:"serialNumber,omitempty"`
	Version      int                   `json:"version,omitempty"`
	Metadata     *CycloneDXMetadata    `json:"metadata,omitempty"`
	Components   []CycloneDXComponent  `json:"components,omitempty"`
	Dependencies []CycloneDXDependency `json:"dependencies,omitempty"`
	Properties   []CycloneDXProperty   `json:"properties,omitempty"`
}

type CycloneDXMetadata struct {
	Timestamp string `json:"timestamp,omitempty"`
	// Most important, so you can use both Trivy and Trivy Operator generated SBOMs.
	Tools     interface{}         `json:"tools,omitempty"`
	Component *CycloneDXComponent `json:"component,omitempty"`
}

type CycloneDXTool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

type CycloneDXComponent struct {
	Type       string              `json:"type"`
	Name       string              `json:"name"`
	Version    string              `json:"version,omitempty"`
	Group      string              `json:"group,omitempty"`
	PURL       string              `json:"purl,omitempty"`
	BOMRef     string              `json:"bom-ref,omitempty"`
	Licenses   []CycloneDXLicense  `json:"licenses,omitempty"`
	Properties []CycloneDXProperty `json:"properties,omitempty"`
}

type CycloneDXLicense struct {
	License struct {
		ID string `json:"id,omitempty"`
	} `json:"license,omitempty"`
	Expression string `json:"expression,omitempty"`
}

type CycloneDXDependency struct {
	Ref          string   `json:"ref"`
	Dependencies []string `json:"dependsOn,omitempty"`
}

type CycloneDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// SPDX format
type SPDXDocument struct {
	SPDXVersion       string           `json:"spdxVersion"`
	DataLicense       string           `json:"dataLicense"`
	SPDXID            string           `json:"SPDXID"`
	Name              string           `json:"name"`
	DocumentNamespace string           `json:"documentNamespace"`
	CreationInfo      SPDXCreationInfo `json:"creationInfo"`
	Packages          []SPDXPackage    `json:"packages,omitempty"`
}

// SPDX format informations, for parsing it to DependencyTrack, as for some reason it doesn't show.
type SPDXCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type SPDXPackage struct {
	SPDXID           string `json:"SPDXID"`
	Name             string `json:"name"`
	VersionInfo      string `json:"versionInfo,omitempty"`
	PackageFileName  string `json:"packageFileName,omitempty"`
	Supplier         string `json:"supplier,omitempty"`
	DownloadLocation string `json:"downloadLocation,omitempty"`
	LicenseConcluded string `json:"licenseConcluded,omitempty"`
	LicenseDeclared  string `json:"licenseDeclared,omitempty"`
	CopyrightText    string `json:"copyrightText,omitempty"`
}

// Get result of SBOM conversion, due to SPDX and CycloneDX support from DependencyTrack.
// https://github.com/DependencyTrack/dependency-track/discussions/1222
type SBOMProcessingResult struct {
	BOMData        []byte
	ProjectName    string
	ProjectVersion string
	Format         string
	Components     int
	Dependencies   int
}
