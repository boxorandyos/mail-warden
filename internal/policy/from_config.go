package policy

import "github.com/boxorandyos/mail-warden/internal/config"
import "github.com/boxorandyos/mail-warden/internal/scoring"

func EngineConfigFrom(cfg config.PolicyConfig) scoring.EngineConfig {
	out := DefaultEngineConfig()
	out.InboundRejectThreshold = cfg.Policy.Inbound.Reject
	out.InboundQuarantineThreshold = cfg.Policy.Inbound.Quarantine
	out.OutboundRejectThreshold = cfg.Policy.Outbound.Reject
	out.OutboundQuarantineThreshold = cfg.Policy.Outbound.Quarantine
	if cfg.HardBlocks != nil {
		out.HardBlocks = append([]string(nil), cfg.HardBlocks...)
	}
	if len(cfg.Caps) > 0 {
		out.Caps = make(map[string]scoring.SignalBounds, len(cfg.Caps))
		for key, cap := range cfg.Caps {
			out.Caps[key] = scoring.SignalBounds{Min: cap.Min, Max: cap.Max}
		}
	}
	return out
}
