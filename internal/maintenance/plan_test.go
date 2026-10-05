package maintenance

import (
	"strings"
	"testing"
)

func TestPlanSlaveUpgrades(t *testing.T) {
	calls, err := PlanSlaveUpgrades("primary", []Node{
		{Name: "standby", Address: "10.1.0.8:8080", Role: "standby"},
		{Name: "self", Address: "10.1.0.7:8080", Role: "primary"},
	}, Packages)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 {
		t.Fatalf("calls = %d", len(calls))
	}
	if calls[0].URL != "http://10.1.0.8:8080/api/v1/maintenance/apply" {
		t.Fatalf("url = %s", calls[0].URL)
	}
	if _, err := PlanSlaveUpgrades("standby", nil, Product); err == nil {
		t.Fatal("standby should not trigger upgrades")
	}
	if _, err := maintenanceURL("10.1.0.8"); err == nil {
		t.Fatal("expected host:port")
	}
}

func TestPlanRuntime(t *testing.T) {
	executed, detail, err := PlanRuntime("postgres", false)
	if err != nil || executed {
		t.Fatalf("executed=%v err=%v", executed, err)
	}
	if !strings.Contains(detail, "upgrade-postgres.sh 18") {
		t.Fatal(detail)
	}
	if _, _, err := PlanRuntime("rspamd", true); err == nil {
		t.Fatal("rspamd is a new-install image pin, not a live upgrade")
	}
	rows := RuntimeCatalog()
	if len(rows) != 4 || rows[0]["newInstall"] != "18" || rows[1]["newInstall"] != "8.2" {
		t.Fatalf("catalog = %#v", rows)
	}
}

func TestKeyMatches(t *testing.T) {
	if !KeyMatches("dw-secret", "dw-secret") {
		t.Fatal("expected match")
	}
	if KeyMatches("dw-secret", "dw-secreT") || KeyMatches("", "x") {
		t.Fatal("expected mismatch")
	}
}
