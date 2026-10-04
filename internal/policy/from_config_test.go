package policy

import (
	"testing"

	"github.com/boxorandyos/mail-warden/internal/config"
)

func TestEngineConfigFromReadsCapsAndHardBlocks(t *testing.T) {
	t.Parallel()
	var cfg config.PolicyConfig
	cfg.Policy.Inbound.Reject = -30
	cfg.Policy.Inbound.Quarantine = -10
	cfg.Policy.Outbound.Reject = -35
	cfg.Policy.Outbound.Quarantine = -12
	cfg.HardBlocks = []string{"malware_confirmed"}
	cfg.Caps = map[string]config.SignalCap{
		"sender_history": {Min: -2, Max: 2},
	}
	out := EngineConfigFrom(cfg)
	if len(out.HardBlocks) != 1 || out.HardBlocks[0] != "malware_confirmed" {
		t.Fatalf("hard blocks: %+v", out.HardBlocks)
	}
	cap, ok := out.Caps["sender_history"]
	if !ok || cap.Min != -2 || cap.Max != 2 {
		t.Fatalf("caps: %+v", out.Caps)
	}
	if out.InboundRejectThreshold != -30 {
		t.Fatalf("threshold %v", out.InboundRejectThreshold)
	}
}
