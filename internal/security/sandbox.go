package security

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type SandboxClient struct {
	enabled  bool
	endpoint string
	apiKey   string
	http     *http.Client
}

type SandboxResult struct {
	Verdict   string   `json:"verdict"`
	Malicious bool     `json:"malicious"`
	Reasons   []string `json:"reasons"`
}

func NewSandboxClient(enabled bool, endpoint, apiKey string, timeoutSec int) *SandboxClient {
	if timeoutSec <= 0 {
		timeoutSec = 10
	}
	return &SandboxClient{
		enabled:  enabled,
		endpoint: endpoint,
		apiKey:   apiKey,
		http: &http.Client{
			Timeout: time.Duration(timeoutSec) * time.Second,
		},
	}
}

func (c *SandboxClient) AnalyzeAttachments(ctx context.Context, attachments []map[string]any) (SandboxResult, error) {
	if !c.enabled || c.endpoint == "" || len(attachments) == 0 {
		return SandboxResult{Verdict: "skipped", Malicious: false}, nil
	}
	body := map[string]any{
		"attachments": attachments,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return SandboxResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(raw))
	if err != nil {
		return SandboxResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return SandboxResult{}, fmt.Errorf("sandbox request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return SandboxResult{}, fmt.Errorf("sandbox status %d", resp.StatusCode)
	}
	var out SandboxResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return SandboxResult{}, fmt.Errorf("decode sandbox response: %w", err)
	}
	return out, nil
}
