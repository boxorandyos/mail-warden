package maintenance

import "testing"

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

func TestKeyMatches(t *testing.T) {
	if !KeyMatches("dw-secret", "dw-secret") {
		t.Fatal("expected match")
	}
	if KeyMatches("dw-secret", "dw-secreT") || KeyMatches("", "x") {
		t.Fatal("expected mismatch")
	}
}
