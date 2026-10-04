package security

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSandboxSkipsWhenDisabled(t *testing.T) {
	t.Parallel()
	client := NewSandboxClient(false, "", "", 5)
	res, err := client.AnalyzeAttachments(t.Context(), []map[string]any{{"filename": "a.exe"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Verdict != "skipped" {
		t.Fatalf("expected skipped verdict, got %s", res.Verdict)
	}
}

func TestSandboxReturnsErrorOnRemoteFailure(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := NewSandboxClient(true, srv.URL, "", 5)
	_, err := client.AnalyzeAttachments(t.Context(), []map[string]any{{"filename": "a.exe"}})
	if err == nil {
		t.Fatal("expected sandbox error when remote endpoint fails")
	}
}
