package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type webhookNotifier struct {
	url    string
	client *http.Client
}

func newWebhookNotifier(url string) *webhookNotifier {
	return &webhookNotifier{
		url:    url,
		client: &http.Client{},
	}
}

func (w *webhookNotifier) Notify(ctx context.Context, summary Summary, files []string) error {
	payload, err := json.MarshalIndent(webhookMessage{
		Text:   summary.Title,
		Blocks: buildBlocks(summary, files, false),
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal slack payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("post to slack webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("slack webhook returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	if len(files) > 0 {
		// Incoming webhooks cannot upload files; the files have already been written locally.
		return fmt.Errorf("slack webhook cannot upload files (%d skipped); use a bot token to upload", len(files))
	}
	return nil
}

type webhookMessage struct {
	Text   string       `json:"text"`
	Blocks []slackBlock `json:"blocks,omitempty"`
}
