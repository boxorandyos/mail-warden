package scoring

import "testing"

func TestEvaluateHardSignalWins(t *testing.T) {
	e := NewEngine(DefaultEngineConfig())

	d := e.Evaluate(NormalizedDecisionObject{
		Content: ContentFacts{
			MalwareConfirmed: true,
		},
	})

	if d.Action != ActionReject {
		t.Fatalf("expected reject, got %s", d.Action)
	}
}

func TestEvaluateScoreBasedQuarantine(t *testing.T) {
	e := NewEngine(DefaultEngineConfig())

	d := e.Evaluate(NormalizedDecisionObject{
		Identity: IdentityFacts{
			SenderReputation: 2,
			DomainReputation: 1,
		},
		Relationship: RelationshipFacts{
			KnownCorrespondent: true,
			InteractionCount:   80,
		},
		Authentication: AuthenticationFacts{
			SPF:   "fail",
			DKIM:  "fail",
			DMARC: "fail",
		},
		Envelope: EnvelopeFacts{
			InvalidRatio: 0.35,
		},
		Content: ContentFacts{
			RspamdScore:  12,
			MaliciousURL: false,
		},
	})

	if d.Action != ActionQuarantine {
		t.Fatalf("expected quarantine, got %s with score %.2f", d.Action, d.Score)
	}
}

func TestCapsClampSenderHistory(t *testing.T) {
	cfg := DefaultEngineConfig()
	cfg.Caps = map[string]SignalBounds{
		"sender_history": {Min: -1, Max: 1},
	}
	d := NewEngine(cfg).Evaluate(NormalizedDecisionObject{
		Identity: IdentityFacts{SenderReputation: 100},
	})
	var found bool
	for _, signal := range d.Signals {
		if signal.Name == "sender_reputation" {
			found = true
			if signal.Bounded() != 1 {
				t.Fatalf("cap did not clamp sender reputation, bounded=%v", signal.Bounded())
			}
		}
	}
	if !found {
		t.Fatal("missing sender reputation signal")
	}
}

func TestHardBlockListDisablesMalwareGate(t *testing.T) {
	cfg := DefaultEngineConfig()
	cfg.HardBlocks = []string{"exploit_confirmed"}
	d := NewEngine(cfg).Evaluate(NormalizedDecisionObject{
		Content:  ContentFacts{MalwareConfirmed: true},
		Identity: IdentityFacts{SenderReputation: 10, DomainReputation: 10},
	})
	if d.Action == ActionReject && len(d.HardSignals) > 0 {
		t.Fatal("malware must not hard-reject when it is absent from hard_blocks")
	}
	exploit := NewEngine(cfg).Evaluate(NormalizedDecisionObject{
		Content: ContentFacts{ExploitConfirmed: true},
	})
	if exploit.Action != ActionReject {
		t.Fatalf("exploit hard block should reject, got %s", exploit.Action)
	}
}

func TestEvaluateOutboundCanThrottle(t *testing.T) {
	e := NewEngine(DefaultEngineConfig())

	d := e.EvaluateForDirection("outbound", NormalizedDecisionObject{
		Behavior: BehaviorFacts{
			SendingVelocityLevel: "critical",
			RecipientDiversity:   0.95,
		},
	})

	if d.Action != ActionThrottle {
		t.Fatalf("expected throttle, got %s", d.Action)
	}
}
