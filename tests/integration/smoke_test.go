//go:build integration

package integration

import (
	"bufio"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAPIMetricsAndMessagesEndpoints(t *testing.T) {
	base := os.Getenv("MAILWARDEN_BASE_URL")
	token := os.Getenv("MAILWARDEN_BEARER_TOKEN")
	if base == "" || token == "" {
		t.Skip("MAILWARDEN_BASE_URL and MAILWARDEN_BEARER_TOKEN are required")
	}

	client := &http.Client{Timeout: 10 * time.Second}
	for _, path := range []string{"/api/v1/metrics", "/api/v1/messages", "/api/v1/events"} {
		req, err := http.NewRequest(http.MethodGet, strings.TrimRight(base, "/")+path, nil)
		if err != nil {
			t.Fatalf("create request %s: %v", path, err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("do request %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 400 {
			t.Fatalf("unexpected status for %s: %d", path, resp.StatusCode)
		}
	}
}

func TestPostfixPolicySocketResponds(t *testing.T) {
	addr := os.Getenv("POSTFIX_POLICY_ADDR")
	if addr == "" {
		addr = "127.0.0.1:10031"
	}
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Skipf("postfix policy socket not reachable: %v", err)
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte("sender=attacker@example.net\nrecipient=user@example.com\nclient_address=203.0.113.5\n\n"))

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read policy response: %v", err)
	}
	if !strings.HasPrefix(line, "action=") {
		t.Fatalf("unexpected policy response: %q", line)
	}
}
