package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPolicyConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	content := `
policy:
  inbound:
    reject: -30
    quarantine: -10
  outbound:
    reject: -35
    quarantine: -12
    throttle:
      recipients_per_hour: 5000
      unique_domains_per_hour: 500
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write test config: %v", err)
	}

	cfg, err := LoadPolicyConfig(path)
	if err != nil {
		t.Fatalf("load policy config: %v", err)
	}

	if got, want := cfg.Policy.Inbound.Reject, -30.0; got != want {
		t.Fatalf("inbound reject got %.2f want %.2f", got, want)
	}
	if got, want := cfg.Policy.Outbound.Throttle.RecipientsPerHour, 5000; got != want {
		t.Fatalf("outbound recipients_per_hour got %d want %d", got, want)
	}
}

func TestValidateRuntimeSafetyAllowsBootstrapDefaults(t *testing.T) {
	t.Parallel()
	cfg := ServiceConfig{}
	cfg.Service.Mode = "bootstrap"
	cfg.Auth.AccessSecret = "change-me-access-secret"
	cfg.Auth.RefreshSecret = "change-me-refresh-secret"
	if err := cfg.ValidateRuntimeSafety(); err != nil {
		t.Fatalf("bootstrap safety validation should allow defaults: %v", err)
	}
}

func TestValidateRuntimeSafetyRejectsDefaultSecretsOutsideBootstrap(t *testing.T) {
	t.Parallel()
	cfg := ServiceConfig{}
	cfg.Service.Mode = "production"
	cfg.Stores.PostgresDSN = "postgres://mailwarden:pw@db/mailwarden?sslmode=require"
	cfg.Auth.AccessSecret = "change-me-access-secret"
	cfg.Auth.RefreshSecret = "change-me-refresh-secret"
	cfg.Auth.BootstrapAdminPassword = "change-this-password"

	err := cfg.ValidateRuntimeSafety()
	if err == nil {
		t.Fatal("expected runtime safety validation to fail")
	}
}
