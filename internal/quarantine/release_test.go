package quarantine

import (
	"testing"
	"time"

	"github.com/boxorandyos/mail-warden/internal/scoring"
)

func TestDecideReleaseRescanKeepsQuarantine(t *testing.T) {
	t.Parallel()
	input := scoring.NormalizedDecisionObject{
		Envelope:   scoring.EnvelopeFacts{From: "a@x.test", Recipients: []string{"b@y.test"}},
		ObservedAt: time.Now().UTC(),
		Content:    scoring.ContentFacts{MalwareConfirmed: true},
	}
	engine := scoring.NewEngine(scoring.DefaultEngineConfig())
	deliver, decision, err := DecideRelease(ModeRescan, "inbound", input, engine.EvaluateForDirection)
	if err != nil {
		t.Fatal(err)
	}
	if deliver {
		t.Fatal("malware rescan must not release")
	}
	if decision.Action != scoring.ActionReject && decision.Action != scoring.ActionQuarantine {
		t.Fatalf("expected a blocking action, got %s", decision.Action)
	}
}

func TestDecideReleaseRescanAllowsAccept(t *testing.T) {
	t.Parallel()
	input := scoring.NormalizedDecisionObject{
		Envelope:   scoring.EnvelopeFacts{From: "a@x.test", Recipients: []string{"b@y.test"}},
		ObservedAt: time.Now().UTC(),
		Identity:   scoring.IdentityFacts{SenderReputation: 8, DomainReputation: 8},
	}
	engine := scoring.NewEngine(scoring.DefaultEngineConfig())
	deliver, decision, err := DecideRelease(ModeRescan, "inbound", input, engine.EvaluateForDirection)
	if err != nil {
		t.Fatal(err)
	}
	if !deliver || decision.Action != scoring.ActionAccept {
		t.Fatalf("expected accept delivery, got %s deliver=%v", decision.Action, deliver)
	}
}

func TestDecideReleaseBypassSkipsEvaluate(t *testing.T) {
	t.Parallel()
	called := false
	deliver, decision, err := DecideRelease(ModeBypass, "inbound", scoring.NormalizedDecisionObject{}, func(string, scoring.NormalizedDecisionObject) scoring.Decision {
		called = true
		return scoring.Decision{Action: scoring.ActionReject}
	})
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("bypass must not evaluate")
	}
	if !deliver || decision.Reason != "operator bypass" {
		t.Fatalf("unexpected bypass result: %+v deliver=%v", decision, deliver)
	}
}

func TestDecideReleaseRejectsUnknownMode(t *testing.T) {
	t.Parallel()
	_, _, err := DecideRelease("drop", "inbound", scoring.NormalizedDecisionObject{}, func(string, scoring.NormalizedDecisionObject) scoring.Decision {
		return scoring.Decision{}
	})
	if err == nil {
		t.Fatal("expected invalid mode error")
	}
}
