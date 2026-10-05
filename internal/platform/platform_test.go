package platform

import (
	"strings"
	"testing"
	"time"
)

func TestServiceAccountTokenIsNotListed(t *testing.T) {
	store := NewMemory()
	created, err := store.CreateAccount("backup", "viewer", "env-default")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.Token, "mw_") {
		t.Fatalf("token = %s", created.Token)
	}
	for _, item := range store.PublicAccounts() {
		if strings.Contains(item.Token, created.Token) || item.Token != "" {
			t.Fatal("token leaked")
		}
	}
	found, ok := store.FindAccount(created.Token)
	if !ok || found.Name != "backup" {
		t.Fatalf("lookup = %+v %v", found, ok)
	}
}

func TestViolationsMetricsAndSnapshot(t *testing.T) {
	store := NewMemory()
	store.Signals.AdminsWithoutMFA = []string{"root"}
	store.Signals.Nodes = []NodeSignal{{ID: "n1", Name: "standby"}}
	if _, err := store.AddRunbook("Failover", "Promote the standby", "env-default"); err != nil {
		t.Fatal(err)
	}
	violations := store.Violations(time.Now())
	if !containsDetail(violations, "MFA") || !containsDetail(violations, "heartbeat") || !containsDetail(violations, "backup") {
		t.Fatalf("violations = %+v", violations)
	}
	text := Prometheus(map[string]int{"succeeded": 1}, 1, len(store.Rules))
	if !strings.Contains(text, "warden_up 1") {
		t.Fatal(text)
	}
	snapshot := store.Capture("admin")
	store.Runbooks = nil
	if err := store.Apply(snapshot.ID); err != nil {
		t.Fatal(err)
	}
	if len(store.Runbooks) != 1 {
		t.Fatalf("runbooks = %d", len(store.Runbooks))
	}
	csv := ExportCSV([]AuditRow{{Actor: "admin", Action: "login", Detail: "ok", CreatedAt: time.Unix(0, 0).UTC()}})
	if !strings.Contains(csv, "login") {
		t.Fatal(csv)
	}
}

func containsDetail(items []Violation, part string) bool {
	for _, item := range items {
		if strings.Contains(item.Detail, part) {
			return true
		}
	}
	return false
}
