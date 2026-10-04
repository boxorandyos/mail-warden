package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnvOrFilePrefersEnvValue(t *testing.T) {
	t.Setenv("MW_SECRET", "from-env")
	t.Setenv("MW_SECRET_FILE", "")
	got := envOrFile("MW_SECRET", "MW_SECRET_FILE", "fallback")
	if got != "from-env" {
		t.Fatalf("expected env value, got %q", got)
	}
}

func TestEnvOrFileReadsFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(p, []byte("from-file\n"), 0o600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}
	t.Setenv("MW_SECRET", "")
	t.Setenv("MW_SECRET_FILE", p)
	got := envOrFile("MW_SECRET", "MW_SECRET_FILE", "fallback")
	if got != "from-file" {
		t.Fatalf("expected file value, got %q", got)
	}
}
