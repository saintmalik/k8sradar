package slack

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestWebhookNotifier(t *testing.T) {
	var got []byte
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n := newWebhookNotifier(server.URL)
	summary := Summary{
		Title:     "k8sradar test",
		TotalCVEs: 3,
		KEVCount:  1,
		SeverityCounts: map[string]int{"Critical": 1, "High": 2},
	}
	if err := n.Notify(context.Background(), summary, nil); err != nil {
		t.Fatalf("notify: %v", err)
	}

	mu.Lock()
	body := string(got)
	mu.Unlock()

	if !strings.Contains(body, "k8sradar test") {
		t.Errorf("missing title in body: %s", body)
	}

	var msg webhookMessage
	if err := json.Unmarshal(got, &msg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if msg.Text != summary.Title {
		t.Errorf("text: got %q", msg.Text)
	}
	if len(msg.Blocks) == 0 {
		t.Error("expected blocks")
	}
}

func TestWebhookCannotUploadFiles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n := newWebhookNotifier(server.URL)
	summary := Summary{Title: "test"}
	err := n.Notify(context.Background(), summary, []string{"/tmp/report.json"})
	if err == nil {
		t.Fatal("expected error when files cannot be uploaded")
	}
	if !strings.Contains(err.Error(), "cannot upload files") {
		t.Errorf("unexpected error: %v", err)
	}
}
