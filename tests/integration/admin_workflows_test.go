//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAdminProviderWorkflow(t *testing.T) {
	base, token := integrationEnv(t)
	client := &http.Client{Timeout: 10 * time.Second}

	payload := map[string]any{
		"name":     "staging-ldap-provider",
		"type":     "ldap",
		"enabled":  true,
		"priority": 50,
		"config": map[string]any{
			"url":           "ldaps://ldap.internal.local:636",
			"search_base":   "dc=internal,dc=local",
			"search_filter": "(&(objectClass=user)(sAMAccountName={{username}}))",
		},
	}
	raw, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(base, "/")+"/api/v1/identity/providers", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("create provider request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("create provider call: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusServiceUnavailable {
		t.Skip("provider repository unavailable in this environment")
	}
	if resp.StatusCode == http.StatusForbidden {
		t.Skip("admin token required for provider workflow")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create provider unexpected status: %d", resp.StatusCode)
	}

	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode provider response: %v", err)
	}
	if created.ID == "" {
		t.Fatal("created provider id is empty")
	}

	deleteReq, err := http.NewRequest(http.MethodDelete, strings.TrimRight(base, "/")+"/api/v1/identity/providers/"+created.ID, nil)
	if err != nil {
		t.Fatalf("build delete request: %v", err)
	}
	deleteReq.Header.Set("Authorization", "Bearer "+token)
	delResp, err := client.Do(deleteReq)
	if err != nil {
		t.Fatalf("delete provider call: %v", err)
	}
	defer delResp.Body.Close()
	if delResp.StatusCode != http.StatusOK {
		t.Fatalf("delete provider unexpected status: %d", delResp.StatusCode)
	}
}

func TestAdminPolicyRollbackWorkflow(t *testing.T) {
	base, token := integrationEnv(t)
	client := &http.Client{Timeout: 10 * time.Second}

	createReqBody := bytes.NewBufferString(`{"label":"integration-rollback-check"}`)
	createReq, err := http.NewRequest(http.MethodPost, strings.TrimRight(base, "/")+"/api/v1/policy/versions", createReqBody)
	if err != nil {
		t.Fatalf("build create version request: %v", err)
	}
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Authorization", "Bearer "+token)
	createResp, err := client.Do(createReq)
	if err != nil {
		t.Fatalf("create version call: %v", err)
	}
	defer createResp.Body.Close()
	if createResp.StatusCode == http.StatusServiceUnavailable {
		t.Skip("policy repository unavailable in this environment")
	}
	if createResp.StatusCode == http.StatusForbidden {
		t.Skip("admin token required for policy rollback workflow")
	}
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create policy version unexpected status: %d", createResp.StatusCode)
	}

	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode policy version response: %v", err)
	}
	if created.ID <= 0 {
		t.Fatalf("invalid created policy version id: %d", created.ID)
	}

	rollbackReq, err := http.NewRequest(http.MethodPost, strings.TrimRight(base, "/")+"/api/v1/policy/rollback?id="+jsonInt(created.ID), nil)
	if err != nil {
		t.Fatalf("build rollback request: %v", err)
	}
	rollbackReq.Header.Set("Authorization", "Bearer "+token)
	rollbackResp, err := client.Do(rollbackReq)
	if err != nil {
		t.Fatalf("rollback call: %v", err)
	}
	defer rollbackResp.Body.Close()
	if rollbackResp.StatusCode != http.StatusOK {
		t.Fatalf("rollback unexpected status: %d", rollbackResp.StatusCode)
	}
}

func integrationEnv(t *testing.T) (base string, token string) {
	t.Helper()
	base = strings.TrimSpace(os.Getenv("MAILWARDEN_BASE_URL"))
	token = strings.TrimSpace(os.Getenv("MAILWARDEN_BEARER_TOKEN"))
	if base == "" || token == "" {
		t.Skip("MAILWARDEN_BASE_URL and MAILWARDEN_BEARER_TOKEN are required")
	}
	return base, token
}

func jsonInt(v int64) string {
	return strconv.FormatInt(v, 10)
}
