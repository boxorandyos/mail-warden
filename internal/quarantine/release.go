package quarantine

import (
	"fmt"
	"strings"

	"github.com/boxorandyos/mail-warden/internal/scoring"
)

const (
	ModeRescan = "rescan"
	ModeBypass = "bypass"
)

func DecideRelease(mode, direction string, input scoring.NormalizedDecisionObject, evaluate func(string, scoring.NormalizedDecisionObject) scoring.Decision) (bool, scoring.Decision, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if direction == "" {
		direction = "inbound"
	}
	switch mode {
	case "", ModeRescan:
		if DecisionInputMissing(input) {
			return false, scoring.Decision{}, fmt.Errorf("stored decision input is missing")
		}
		decision := evaluate(direction, input)
		return decision.Action == scoring.ActionAccept, decision, nil
	case ModeBypass:
		return true, scoring.Decision{
			Action:    scoring.ActionAccept,
			Reason:    "operator bypass",
			Direction: direction,
		}, nil
	default:
		return false, scoring.Decision{}, fmt.Errorf("invalid release mode")
	}
}

func DecisionInputMissing(input scoring.NormalizedDecisionObject) bool {
	return strings.TrimSpace(input.Envelope.From) == "" &&
		len(input.Envelope.Recipients) == 0 &&
		input.ObservedAt.IsZero()
}
