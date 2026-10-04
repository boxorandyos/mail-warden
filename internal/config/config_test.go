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

func TestLoadPolicyConfigReadsCapsAndHardBlocks(t *testing.T) {
	t.Parallel()
	cfg, err := LoadPolicyConfig("../../configs/policy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.HardBlocks) != 3 {
		t.Fatalf("hard blocks: %+v", cfg.HardBlocks)
	}
	cap, ok := cfg.Caps["malware"]
	if !ok || cap.Min != -50 || cap.Max != 0 {
		t.Fatalf("malware cap: %+v ok=%v", cap, ok)
	}
}

func TestMergeServicePutKeepsBlankSecrets(t *testing.T) {
	t.Parallel()
	current := ServiceConfig{}
	current.Service.Listen = ":8080"
	current.Auth.AccessSecret = "keep-me"
	current.Stores.PostgresDSN = "postgres://keep"
	var put ServicePut
	put.Service.Listen = ":9090"
	put.Service.Mode = "bootstrap"
	put.Rspamd.Endpoint = "http://rspamd:11334"
	put.Secrets.AccessSecret = ""
	next, restart := MergeServicePut(current, put)
	if next.Auth.AccessSecret != "keep-me" || next.Stores.PostgresDSN != "postgres://keep" {
		t.Fatalf("blank secrets were overwritten: %+v", next.Auth)
	}
	if next.Service.Listen != ":9090" {
		t.Fatal("listen was not updated")
	}
	found := false
	for _, field := range restart {
		if field == "service.listen" {
			found = true
		}
	}
	if !found {
		t.Fatalf("restart fields: %v", restart)
	}
	view := next.PublicView()
	if view.Auth.AccessSecretSet != true || view.Service.Listen != ":9090" {
		t.Fatalf("public view leaked or dropped data: %+v", view.Auth)
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
