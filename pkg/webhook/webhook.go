package webhook

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"dtrack-webhook/pkg/cache"
	"dtrack-webhook/pkg/config"
	"dtrack-webhook/pkg/sbom"
	"dtrack-webhook/pkg/upload"
)

type WebhookHandler struct {
	config        *config.Config
	cache         *cache.CacheManager
	sbomProcessor *sbom.FormatProcessor
	uploader      *upload.DTrackUploader
	log           *logrus.Logger
}

func NewWebhookHandler(cfg *config.Config, cacheManager *cache.CacheManager) *WebhookHandler {
	return &WebhookHandler{
		config:        cfg,
		cache:         cacheManager,
		sbomProcessor: sbom.NewFormatProcessor(cfg.Verbose),
		uploader:      upload.NewDTrackUploader(),
		log:           logrus.New(),
	}
}

func (wh *WebhookHandler) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		wh.log.WithError(err).Error("Failed to read webhook body")
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}

	// Check SBOM format and prepare for upload, due to Trivy validation check.
	result, err := wh.sbomProcessor.ProcessSBOM(body,
		wh.config.ProjectNameTemplate,
		wh.config.ProjectVersionTemplate,
		wh.config.DtrackProject)
	if err != nil {
		wh.log.WithError(err).Warn("Failed to process SBOM")
		http.Error(w, "Failed to process SBOM", http.StatusBadRequest)
		return
	}

	key := fmt.Sprintf("%d", time.Now().UnixNano())
	wh.cache.Set(key, result.BOMData)

	// Upload asynchronously to not block webhook response, as Dependency-Track may take time to process SBOMs.
	// Will this work?
	go wh.processUploadAsync(key, result, start)

	w.WriteHeader(http.StatusAccepted)
	fmt.Fprintf(w, "Received SBOM (key=%s, project=%s, version=%s, format=%s, components=%d)\n",
		key, result.ProjectName, result.ProjectVersion, result.Format, result.Components)

	wh.log.WithFields(logrus.Fields{
		"key":          key,
		"size":         len(result.BOMData),
		"project":      result.ProjectName,
		"version":      result.ProjectVersion,
		"parent":       wh.config.ProjectParent,
		"tags":         wh.config.ProjectTags,
		"format":       result.Format,
		"components":   result.Components,
		"dependencies": result.Dependencies,
	}).Info("Webhook received SBOM")
}

func (wh *WebhookHandler) processUploadAsync(key string, result *sbom.SBOMProcessingResult, start time.Time) {
	// Make sure parent project exists to not override existing project.
	if wh.config.ProjectParent != "" {
		if err := wh.uploader.EnsureParentProjectExists(
			wh.config.DtrackURL,
			wh.config.DtrackAPIKey,
			wh.config.ProjectParent,
			wh.config.ProjectTags); err != nil {
			wh.log.WithFields(logrus.Fields{
				"key":    key,
				"parent": wh.config.ProjectParent,
				"err":    err,
				"time":   time.Since(start).String(),
			}).Error("Failed to ensure parent project exists")
			return
		}
		wh.log.WithFields(logrus.Fields{
			"key":    key,
			"parent": wh.config.ProjectParent,
			"tags":   wh.config.ProjectTags,
		}).Debug("Parent project ensured")
	}

	if err := wh.uploader.UploadToDependencyTrack(
		wh.config.DtrackURL,
		wh.config.DtrackAPIKey,
		result.ProjectName,
		result.ProjectVersion,
		wh.config.ProjectTags,
		wh.config.ProjectParent,
		result.BOMData); err != nil {
		wh.log.WithFields(logrus.Fields{
			"key":     key,
			"project": result.ProjectName,
			"version": result.ProjectVersion,
			"parent":  wh.config.ProjectParent,
			"tags":    wh.config.ProjectTags,
			"format":  result.Format,
			"err":     err,
			"time":    time.Since(start).String(),
		}).Error("Upload failed")
		return
	}
	wh.log.WithFields(logrus.Fields{
		"key":          key,
		"project":      result.ProjectName,
		"version":      result.ProjectVersion,
		"parent":       wh.config.ProjectParent,
		"tags":         wh.config.ProjectTags,
		"format":       result.Format,
		"components":   result.Components,
		"dependencies": result.Dependencies,
		"time":         time.Since(start).String(),
	}).Info("SBOM uploaded to DependencyTrack")
	// Wait for BOM processing to complete, then trigger analysis as with new version(4.13.2) it didn't trigger automatically.
	go wh.waitAndTriggerAnalysis(wh.config.DtrackURL, wh.config.DtrackAPIKey, wh.config.DtrackAPIKey, result.ProjectName, result.ProjectVersion)
}

func (wh *WebhookHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "healthy",
		"timestamp":  time.Now().UTC(),
		"cache_size": wh.cache.Size(),
	})
}

// Scan Vuln
func (du *WebhookHandler) waitAndTriggerAnalysis(base, apiKey, token, project, version string) {
	// Wait a bit for BOM processing to complete
	time.Sleep(10 * time.Second)

	// Get project UUID to use project name.
	projectUUID, err := du.getProjectUUID(base, apiKey, project, version)
	if err != nil {
		du.log.WithError(err).Warn("Failed to get project UUID for analysis trigger")
		return
	}

	// Start scan for vulnerabilities
	du.triggerVulnerabilityAnalysis(base, apiKey, projectUUID, project, version)
}

// Get the UUID for a project by name and version, as normal people do not remember or use UUIDs.
func (du *WebhookHandler) getProjectUUID(base, apiKey, project, version string) (string, error) {
	url := fmt.Sprintf("%s/api/v1/project/lookup?name=%s&version=%s",
		strings.TrimRight(base, "/"), project, version)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Api-Key", apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get project: %d", resp.StatusCode)
	}

	var projectInfo struct {
		UUID string `json:"uuid"`
	}

	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &projectInfo); err != nil {
		return "", err
	}

	return projectInfo.UUID, nil
}

// Start scan for vulnerabilities for a project
func (du *WebhookHandler) triggerVulnerabilityAnalysis(base, apiKey, projectUUID, project, version string) {
	url := fmt.Sprintf("%s/api/v1/analysis/project/%s", strings.TrimRight(base, "/"), projectUUID)

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		du.log.WithError(err).Warn("Failed to create analysis request")
		return
	}
	req.Header.Set("X-Api-Key", apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		du.log.WithError(err).Warn("Failed to trigger analysis")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		du.log.WithFields(logrus.Fields{
			"project": project,
			"version": version,
			"uuid":    projectUUID,
		}).Info("Vulnerability analysis triggered")
	} else {
		body, _ := io.ReadAll(resp.Body)
		du.log.WithFields(logrus.Fields{
			"project":  project,
			"version":  version,
			"status":   resp.StatusCode,
			"response": string(body),
		}).Warn("Failed to trigger vulnerability analysis")
	}
}
