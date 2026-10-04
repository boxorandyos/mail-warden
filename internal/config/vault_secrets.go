package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func applyVaultOverrides(cfg *ServiceConfig) error {
	addr := strings.TrimSpace(os.Getenv("MAILWARDEN_VAULT_ADDR"))
	if addr == "" {
		return nil
	}
	token := strings.TrimSpace(os.Getenv("MAILWARDEN_VAULT_TOKEN"))
	if token == "" {
		return fmt.Errorf("MAILWARDEN_VAULT_TOKEN is required when MAILWARDEN_VAULT_ADDR is set")
	}
	path := strings.TrimSpace(os.Getenv("MAILWARDEN_VAULT_SECRET_PATH"))
	if path == "" {
		path = "secret/data/mailwarden"
	}

	url := strings.TrimRight(addr, "/") + "/v1/" + strings.TrimLeft(path, "/")
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build vault request: %w", err)
	}
	req.Header.Set("X-Vault-Token", token)
	client := &http.Client{Timeout: 6 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vault request failed status=%d body=%s", resp.StatusCode, string(b))
	}

	var payload struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return fmt.Errorf("decode vault response: %w", err)
	}
	if payload.Data.Data == nil {
		return nil
	}

	overrideIfSet(payload.Data.Data, "postgres_dsn", &cfg.Stores.PostgresDSN)
	overrideIfSet(payload.Data.Data, "redis_addr", &cfg.Stores.RedisAddr)
	overrideIfSet(payload.Data.Data, "access_secret", &cfg.Auth.AccessSecret)
	overrideIfSet(payload.Data.Data, "refresh_secret", &cfg.Auth.RefreshSecret)
	overrideIfSet(payload.Data.Data, "bootstrap_admin_password", &cfg.Auth.BootstrapAdminPassword)
	overrideIfSet(payload.Data.Data, "ldap_bind_password", &cfg.LDAP.BindPassword)
	overrideIfSet(payload.Data.Data, "oidc_client_secret", &cfg.Auth.OIDC.ClientSecret)
	overrideIfSet(payload.Data.Data, "sandbox_api_key", &cfg.Sandbox.APIKey)
	overrideIfSet(payload.Data.Data, "siem_bearer_token", &cfg.SIEM.BearerToken)
	return nil
}

func overrideIfSet(data map[string]string, key string, target *string) {
	if v, ok := data[key]; ok && strings.TrimSpace(v) != "" {
		*target = strings.TrimSpace(v)
	}
}
