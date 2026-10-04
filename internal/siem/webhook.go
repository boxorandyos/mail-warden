package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Forwarder struct {
	enabled bool
	url     string
	token   string
	http    *http.Client
}

func NewForwarder(enabled bool, url, token string, timeoutSec int) *Forwarder {
	if timeoutSec <= 0 {
		timeoutSec = 5
	}
	return &Forwarder{
		enabled: enabled,
		url:     url,
		token:   token,
		http: &http.Client{
			Timeout: time.Duration(timeoutSec) * time.Second,
		},
	}
}

func (f *Forwarder) Send(ctx context.Context, event map[string]any) error {
	if !f.enabled || f.url == "" {
		return nil
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if f.token != "" {
		req.Header.Set("Authorization", "Bearer "+f.token)
	}
	resp, err := f.http.Do(req)
	if err != nil {
		return fmt.Errorf("siem forward failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("siem forward status=%d", resp.StatusCode)
	}
	return nil
}
