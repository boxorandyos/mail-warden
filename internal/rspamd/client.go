package rspamd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	baseURL string
	http    *http.Client
}

type CheckRequest struct {
	RawMessage []byte
	FromIP     string
	Helo       string
	From       string
	Recipient  string
}

type CheckResult struct {
	Score             float64 `json:"score"`
	RequiredScore     float64 `json:"required_score"`
	Action            string  `json:"action"`
	Spam              bool    `json:"spam"`
	MaliciousURL      bool    `json:"malicious_url"`
	MalwareDetected   bool    `json:"malware_detected"`
	PhishingLikely    bool    `json:"phishing_likely"`
	ResponseTimestamp string  `json:"response_timestamp"`
}

type rawRspamdResponse struct {
	Default struct {
		Score         float64                       `json:"score"`
		RequiredScore float64                       `json:"required_score"`
		Action        string                        `json:"action"`
		Symbols       map[string]rawRspamdSymbolRef `json:"symbols"`
	} `json:"default"`
}

type rawRspamdSymbolRef struct {
	Name    string  `json:"name"`
	Score   float64 `json:"score"`
	Options any     `json:"options"`
}

func NewClient(baseURL string, timeoutSeconds int) *Client {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 5
	}
	return &Client{
		baseURL: baseURL,
		http: &http.Client{
			Timeout: time.Duration(timeoutSeconds) * time.Second,
		},
	}
}

func (c *Client) Check(ctx context.Context, req CheckRequest) (CheckResult, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/checkv2", bytes.NewReader(req.RawMessage))
	if err != nil {
		return CheckResult{}, fmt.Errorf("create rspamd request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "message/rfc822")
	httpReq.Header.Set("IP", req.FromIP)
	httpReq.Header.Set("Helo", req.Helo)
	httpReq.Header.Set("From", req.From)
	httpReq.Header.Set("Rcpt", req.Recipient)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return CheckResult{}, fmt.Errorf("rspamd request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return CheckResult{}, fmt.Errorf("read rspamd response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return CheckResult{}, fmt.Errorf("rspamd error: status=%d body=%s", resp.StatusCode, string(body))
	}

	var raw rawRspamdResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return CheckResult{}, fmt.Errorf("decode rspamd response: %w", err)
	}
	return normalize(raw), nil
}

func normalize(raw rawRspamdResponse) CheckResult {
	out := CheckResult{
		Score:             raw.Default.Score,
		RequiredScore:     raw.Default.RequiredScore,
		Action:            raw.Default.Action,
		Spam:              raw.Default.Action == "reject" || raw.Default.Score >= raw.Default.RequiredScore,
		ResponseTimestamp: time.Now().UTC().Format(time.RFC3339),
	}
	for symbolName := range raw.Default.Symbols {
		switch symbolName {
		case "MALICIOUS_URL", "PHISHED_URL":
			out.MaliciousURL = true
			out.PhishingLikely = true
		case "CLAM_VIRUS":
			out.MalwareDetected = true
		case "PHISHING":
			out.PhishingLikely = true
		}
	}
	return out
}
