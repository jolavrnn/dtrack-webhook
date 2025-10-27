package config

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Port                   string
	DtrackURL              string
	DtrackAPIKey           string
	DtrackProject          string
	ProjectNameTemplate    string
	ProjectVersionTemplate string
	ProjectTags            string
	ProjectParent          string
	TTLSeconds             int
	LogLevel               string
	LogFormat              string
	Verbose                bool
}

// LoadConfig loads configuration from environment variables for K8s and Docker setup.
// TODO: Switch to flag based configuration, and argument passing for CLI, also extend to allow override with custom parameters.
func LoadConfig() *Config {
	cfg := &Config{
		Port:                   getenv("PORT", "8080"),
		DtrackURL:              os.Getenv("DTRACK_URL"),
		DtrackAPIKey:           os.Getenv("DTRACK_API_KEY"),
		DtrackProject:          os.Getenv("DTRACK_PROJECT"),
		ProjectNameTemplate:    os.Getenv("DT_PROJECT_NAME"),
		ProjectVersionTemplate: os.Getenv("DT_PROJECT_VERSION"),
		ProjectTags:            os.Getenv("DT_PROJECT_TAGS"),
		ProjectParent:          os.Getenv("DT_PROJECT_PARENT"),
		LogLevel:               strings.ToLower(getenv("LOG_LEVEL", "info")),
		LogFormat:              strings.ToLower(getenv("LOG_FORMAT", "text")),
		Verbose:                os.Getenv("VERBOSE") == "true" || os.Getenv("VERBOSE") == "1",
		TTLSeconds:             300,
	}

	if os.Getenv("TTL_SECONDS") != "" {
		if ttl, err := strconv.Atoi(os.Getenv("TTL_SECONDS")); err == nil {
			cfg.TTLSeconds = ttl
		}
	}

	return cfg
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
