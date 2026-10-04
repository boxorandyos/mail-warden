package regression

import (
	"testing"

	"github.com/boxorandyos/mail-warden/internal/scoring"
)

func TestHardMalwareAlwaysOverridesTrust(t *testing.T) {
	e := scoring.NewEngine(scoring.DefaultEngineConfig())
	d := e.Evaluate(scoring.NormalizedDecisionObject{
		Identity: scoring.IdentityFacts{
			SenderReputation: 10,
			DomainReputation: 10,
		},
		Relationship: scoring.RelationshipFacts{
			KnownCorrespondent: true,
			InteractionCount:   120,
		},
		Content: scoring.ContentFacts{
			MalwareConfirmed: true,
		},
	})

	if d.Action != scoring.ActionReject {
		t.Fatalf("malware hard gate regression: expected reject, got %s", d.Action)
	}
}

func TestOutboundCriticalBurstThrottles(t *testing.T) {
	e := scoring.NewEngine(scoring.DefaultEngineConfig())
	d := e.EvaluateForDirection("outbound", scoring.NormalizedDecisionObject{
		Behavior: scoring.BehaviorFacts{
			SendingVelocityLevel: "critical",
			RecipientDiversity:   0.95,
		},
	})
	if d.Action != scoring.ActionThrottle {
		t.Fatalf("outbound burst regression: expected throttle, got %s", d.Action)
	}
}
