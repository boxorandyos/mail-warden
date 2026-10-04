package policy

import (
	"strings"
	"testing"
)

func TestDecodeAndEvaluateDirectionRequest(t *testing.T) {
	t.Parallel()

	engine := NewEngine(DefaultEngineConfig())
	body := `{
	  "direction":"outbound",
	  "message":{
	    "behavior":{"sending_velocity_level":"critical","recipient_diversity":0.95}
	  }
	}`

	resp, err := DecodeAndEvaluate(strings.NewReader(body), engine)
	if err != nil {
		t.Fatalf("decode and evaluate: %v", err)
	}
	if resp.Direction != "outbound" {
		t.Fatalf("expected outbound direction, got %s", resp.Direction)
	}
	if resp.Decision.Action != "throttle" {
		t.Fatalf("expected throttle action, got %s", resp.Decision.Action)
	}
}
