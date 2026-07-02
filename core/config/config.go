package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port         string
	DBPath       string
	SyncOnStart  bool
	SyncInterval time.Duration
	NVDAPIKey    string
	ManifestDir  string

	CFAccountID    string
	CFAPIToken     string
	CFD1APIToken   string
	CFD1DatabaseID string

	// CLI / report defaults
	Output   string
	OutputDir string
	FailOn   string

	// Slack integration
	SlackWebhook     string
	SlackToken       string
	SlackChannel     string
	SlackDisableFile bool
}

func Load() Config {
	return Config{
		Port:           envOr("PORT", "8080"),
		DBPath:         envOr("DB_PATH", "./data/k8sradar.db"),
		SyncOnStart:    envBool("SYNC_ON_START", false),
		SyncInterval:   envDuration("SYNC_INTERVAL", 6*time.Hour),
		NVDAPIKey:      os.Getenv("NVD_API_KEY"),
		ManifestDir:    envOr("MANIFEST_DIR", "./data/manifests"),
		CFAccountID:    os.Getenv("CF_ACCOUNT_ID"),
		CFAPIToken:     os.Getenv("CF_API_TOKEN"),
		CFD1APIToken:   os.Getenv("CF_D1_API_TOKEN"),
		CFD1DatabaseID: os.Getenv("CF_D1_DATABASE_ID"),

		Output:           envOr("K8SRADAR_OUTPUT", "table"),
		OutputDir:        envOr("K8SRADAR_OUTPUT_DIR", "."),
		FailOn:           os.Getenv("K8SRADAR_FAIL_ON"),
		SlackWebhook:     os.Getenv("K8SRADAR_SLACK_WEBHOOK"),
		SlackToken:       os.Getenv("K8SRADAR_SLACK_TOKEN"),
		SlackChannel:     os.Getenv("K8SRADAR_SLACK_CHANNEL"),
		SlackDisableFile: envBool("K8SRADAR_SLACK_DISABLE_FILE", false),
	}
}

func (c Config) UseD1() bool {
	return c.CFAccountID != "" && c.CFD1DatabaseID != "" && c.D1Token() != ""
}

func (c Config) D1Token() string {
	if c.CFD1APIToken != "" {
		return c.CFD1APIToken
	}
	return c.CFAPIToken
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
