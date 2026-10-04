package config

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestApplyVaultOverrides(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"data":{"access_secret":"vault-a","refresh_secret":"vault-r"}}}`))
	}))
	defer srv.Close()

	t.Setenv("MAILWARDEN_VAULT_ADDR", srv.URL)
	t.Setenv("MAILWARDEN_VAULT_TOKEN", "token")
	t.Setenv("MAILWARDEN_VAULT_SECRET_PATH", "secret/data/mailwarden")

	cfg := ServiceConfig{}
	if err := applyVaultOverrides(&cfg); err != nil {
		t.Fatalf("apply vault overrides: %v", err)
	}
	if cfg.Auth.AccessSecret != "vault-a" || cfg.Auth.RefreshSecret != "vault-r" {
		t.Fatalf("unexpected secrets from vault: %#v", cfg.Auth)
	}
}
