package slack

import (
	"context"
	"fmt"
)

// Config selects how (and whether) to notify Slack.
type Config struct {
	Webhook        string
	Token          string
	Channel        string
	DisableFile    bool
}

// Notifier sends a scan summary and optionally uploads report files.
type Notifier interface {
	// Notify posts the summary and uploads files if supported.
	// It returns paths that were uploaded and any error.
	Notify(ctx context.Context, summary Summary, files []string) error
}

// Summary carries the human-readable scan result posted to Slack.
type Summary struct {
	Title             string
	ScannedAt         string
	Provider          string
	K8sVersion        string
	TotalCVEs         int
	KEVCount          int
	MaxEPSS           float64
	MaxEPSSPercentile float64
	SeverityCounts    map[string]int
	Gate              string
	GateBreached      bool
	TopFindings       []FindingLine
}

// FindingLine is a compact CVE line for the Slack summary.
type FindingLine struct {
	ID          string
	Severity    string
	Component   string
	EPSS        float64
	InKEV       bool
}

// New returns a Notifier based on Config.
// Webhook-only notifications cannot upload files. Token+channel notifications
// can upload files. If both are supplied, the bot path is preferred and the
// webhook is ignored.
func New(cfg Config) (Notifier, error) {
	if cfg.Token != "" && cfg.Channel != "" {
		return newBotNotifier(cfg.Token, cfg.Channel, cfg.DisableFile), nil
	}
	if cfg.Webhook != "" {
		return newWebhookNotifier(cfg.Webhook), nil
	}
	return nil, fmt.Errorf("no Slack configuration: set webhook or both token and channel")
}
