package upload

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// ProjectCreateRequest represents the structure for creating a new project
type ProjectCreateRequest struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Parent  string `json:"parent,omitempty"`
	Tags    []Tag  `json:"tags,omitempty"`
}

// Tag represents a DependencyTrack tag
type Tag struct {
	Name string `json:"name"`
}

// DTrackUploader handles DependencyTrack API interactions
type DTrackUploader struct {
	log *logrus.Logger
}

func NewDTrackUploader() *DTrackUploader {
	return &DTrackUploader{
		log: logrus.New(),
	}
}

// parseTags converts comma-separated tags string to array of Tag objects
func (du *DTrackUploader) parseTags(tagsString string) []Tag {
	if tagsString == "" {
		return nil
	}

	tags := make([]Tag, 0)
	tagNames := strings.Split(tagsString, ",")

	for _, tagName := range tagNames {
		tagName = strings.TrimSpace(tagName)
		if tagName != "" {
			tags = append(tags, Tag{Name: tagName})
		}
	}

	return tags
}

// Check if project exists by name
func (du *DTrackUploader) CheckProjectExistsByName(serverURL, apiKey, projectName string) (bool, error) {
	url := fmt.Sprintf("%s/api/v1/project/lookup?name=%s",
		strings.TrimRight(serverURL, "/"),
		projectName)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return true, nil // Project exists
	} else if resp.StatusCode == http.StatusNotFound {
		return false, nil // Project doesn't exist
	} else {
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("failed to check project existence, status code: %d, response: %s", resp.StatusCode, string(body))
	}
}

// Create a parent project (without version)
func (du *DTrackUploader) CreateParentProject(serverURL, apiKey, projectName, projectTags string) error {
	url := strings.TrimRight(serverURL, "/") + "/api/v1/project"

	projectReq := ProjectCreateRequest{
		Name:    projectName,
		Version: "", // Parent projects typically don't have versions
		Tags:    du.parseTags(projectTags),
	}

	jsonData, err := json.Marshal(projectReq)
	if err != nil {
		return fmt.Errorf("error marshaling project data: %v", err)
	}

	du.log.WithFields(logrus.Fields{
		"url":     url,
		"request": string(jsonData),
	}).Debug("Creating parent project")

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusCreated {
		du.log.WithFields(logrus.Fields{
			"parent_name": projectName,
			"tags":        projectTags,
		}).Info("Created new parent project in DependencyTrack")
		return nil
	} else {
		return fmt.Errorf("failed to create parent project, status code: %d, response: %s", resp.StatusCode, string(body))
	}
}

// Ensure parent project exists, create it if it doesn't
func (du *DTrackUploader) EnsureParentProjectExists(serverURL, apiKey, parentName, projectTags string) error {
	// Check if parent project exists
	exists, err := du.CheckProjectExistsByName(serverURL, apiKey, parentName)
	if err != nil {
		return fmt.Errorf("failed to check parent project existence: %v", err)
	}

	// If parent project doesn't exist, create it
	if !exists {
		if err := du.CreateParentProject(serverURL, apiKey, parentName, projectTags); err != nil {
			return fmt.Errorf("failed to create parent project: %v", err)
		}
		du.log.WithFields(logrus.Fields{
			"parent_name": parentName,
			"tags":        projectTags,
		}).Info("Created new parent project in DependencyTrack")
	} else {
		du.log.WithFields(logrus.Fields{
			"parent_name": parentName,
			"tags":        projectTags,
		}).Debug("Parent project already exists in DependencyTrack")
	}

	return nil
}

func (du *DTrackUploader) UploadToDependencyTrack(base, apiKey, project, version, projectTags, projectParent string, bom []byte) error {
	url := strings.TrimRight(base, "/") + "/api/v1/bom"

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Use projectName and projectVersion fields - DependencyTrack will handle project creation automatically
	writer.WriteField("projectName", project)
	writer.WriteField("projectVersion", version)
	writer.WriteField("autoCreate", "true")

	// For BOM upload, tags are still passed as comma-separated string
	if projectTags != "" {
		writer.WriteField("tags", projectTags)
	}
	if projectParent != "" {
		// Use parentName instead of parentUUID
		writer.WriteField("parentName", projectParent)
	}

	fw, _ := writer.CreateFormFile("bom", "bom.json")
	fw.Write(bom)
	writer.Close()

	req, err := http.NewRequest("POST", url, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-Key", apiKey)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{Timeout: 120 * time.Second} // Increased timeout for large BOMs
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// Log the response for debugging
	du.log.WithFields(logrus.Fields{
		"project":       project,
		"version":       version,
		"parent":        projectParent,
		"tags":          projectTags,
		"status":        resp.StatusCode,
		"response_size": len(body),
	}).Debug("DependencyTrack API response")

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("DependencyTrack: %d %s", resp.StatusCode, string(body))
	}

	// Parse successful response to get more details
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err == nil {
		if token, ok := response["token"].(string); ok {
			du.log.WithFields(logrus.Fields{
				"project": project,
				"version": version,
				"parent":  projectParent,
				"tags":    projectTags,
				"token":   token,
			}).Info("BOM processing started")
		}
	}

	return nil
}
