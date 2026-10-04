package scoring

import (
	"math"
	"strings"
)

type SignalBounds struct {
	Min float64
	Max float64
}

type EngineConfig struct {
	InboundRejectThreshold      float64
	InboundQuarantineThreshold  float64
	OutboundRejectThreshold     float64
	OutboundQuarantineThreshold float64
	// HardBlocks nil keeps the historical gates. An empty slice disables every hard gate.
	HardBlocks []string
	Caps       map[string]SignalBounds
}

func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		InboundRejectThreshold:      -30,
		InboundQuarantineThreshold:  -10,
		OutboundRejectThreshold:     -35,
		OutboundQuarantineThreshold: -12,
	}
}

type Engine struct {
	cfg EngineConfig
}

func NewEngine(cfg EngineConfig) *Engine {
	return &Engine{cfg: cfg}
}

func (e *Engine) Evaluate(n NormalizedDecisionObject) Decision {
	return e.EvaluateForDirection("inbound", n)
}

func (e *Engine) EvaluateForDirection(direction string, n NormalizedDecisionObject) Decision {
	hardSignals := e.collectHardSignals(n)
	if len(hardSignals) > 0 {
		return Decision{
			Action:      hardSignalAction(hardSignals),
			Reason:      "hard security gate triggered",
			Direction:   direction,
			HardSignals: hardSignals,
		}
	}

	signals := buildSignals(direction, n, e.cfg)

	var trust, risk float64
	explanation := Explanation{}
	for _, s := range signals {
		v := s.Bounded()
		if v >= 0 {
			trust += v
		} else {
			risk += math.Abs(v)
		}
		addExplainability(&explanation, s.Category, v)
	}

	score := trust - risk
	explanation.FinalBoundedSum = score

	if direction == "outbound" && n.Behavior.SendingVelocityLevel == "critical" && n.Behavior.RecipientDiversity >= 0.9 {
		return Decision{
			Action:      ActionThrottle,
			Score:       score,
			TrustScore:  trust,
			RiskScore:   risk,
			Reason:      "outbound behavioral threshold exceeded",
			Direction:   direction,
			Signals:     signals,
			HardSignals: nil,
			Explanation: explanation,
		}
	}

	return Decision{
		Action:      e.actionFromScore(direction, score),
		Score:       score,
		TrustScore:  trust,
		RiskScore:   risk,
		Reason:      "score-based policy",
		Direction:   direction,
		Signals:     signals,
		HardSignals: nil,
		Explanation: explanation,
	}
}

func (e *Engine) actionFromScore(direction string, score float64) Action {
	if direction == "outbound" {
		switch {
		case score <= e.cfg.OutboundRejectThreshold:
			return ActionReject
		case score <= e.cfg.OutboundQuarantineThreshold:
			return ActionQuarantine
		default:
			return ActionAccept
		}
	}

	switch {
	case score <= e.cfg.InboundRejectThreshold:
		return ActionReject
	case score <= e.cfg.InboundQuarantineThreshold:
		return ActionQuarantine
	default:
		return ActionAccept
	}
}

func (e *Engine) collectHardSignals(n NormalizedDecisionObject) []HardSignal {
	var out []HardSignal
	if n.Content.MalwareConfirmed && e.hardEnabled(HardMalwareConfirmed) {
		out = append(out, HardMalwareConfirmed)
	}
	if n.Content.ExploitConfirmed && e.hardEnabled(HardExploitConfirmed) {
		out = append(out, HardExploitConfirmed)
	}
	if n.Content.MaliciousURL && n.Content.MaliciousURLConfidence == "critical" && e.hardEnabled(HardMaliciousURLCritical) {
		out = append(out, HardMaliciousURLCritical)
	}
	if n.Behavior.EnumerationLikely && n.Envelope.InvalidRatio >= 0.8 && e.hardEnabled(HardProtocolAbuse) {
		out = append(out, HardProtocolAbuse)
	}
	return out
}

func (e *Engine) hardEnabled(name HardSignal) bool {
	if e.cfg.HardBlocks == nil {
		switch name {
		case HardMalwareConfirmed, HardMaliciousURLCritical, HardProtocolAbuse:
			return true
		default:
			return false
		}
	}
	for _, h := range e.cfg.HardBlocks {
		if HardSignal(strings.TrimSpace(h)) == name {
			return true
		}
	}
	return false
}

func hardSignalAction(hardSignals []HardSignal) Action {
	for _, h := range hardSignals {
		if h == HardMalwareConfirmed || h == HardExploitConfirmed {
			return ActionReject
		}
	}
	return ActionQuarantine
}

func (cfg EngineConfig) bounds(min, max float64, keys ...string) (float64, float64) {
	if len(cfg.Caps) == 0 {
		return min, max
	}
	for _, key := range keys {
		b, ok := cfg.Caps[key]
		if !ok {
			continue
		}
		lo, hi := b.Min, b.Max
		if lo > hi {
			lo, hi = hi, lo
		}
		return lo, hi
	}
	return min, max
}

func (cfg EngineConfig) signal(name, category string, value, min, max float64, keys ...string) Signal {
	lo, hi := cfg.bounds(min, max, append([]string{name}, keys...)...)
	return Signal{Name: name, Category: category, Value: value, Min: lo, Max: hi}
}

func buildSignals(direction string, n NormalizedDecisionObject, cfg EngineConfig) []Signal {
	signals := []Signal{
		cfg.signal("sender_reputation", "identity", n.Identity.SenderReputation, -10, 10, "sender_history"),
		cfg.signal("domain_reputation", "identity", n.Identity.DomainReputation, -10, 10, "domain_history"),
		cfg.signal("known_correspondent", "relationship", correspondentScore(n.Relationship.KnownCorrespondent, n.Relationship.InteractionCount), -10, 10, "correspondent_history"),
		cfg.signal("invalid_recipient_ratio", "behavior", invalidRecipientPenalty(n.Envelope.InvalidRatio), -15, 5, "recipient_behavior"),
		cfg.signal("spf", "authentication", protocolScore(n.Authentication.SPF, -3, 1), -10, 5),
		cfg.signal("dkim", "authentication", protocolScore(n.Authentication.DKIM, -3, 1), -10, 5),
		cfg.signal("dmarc", "authentication", protocolScore(n.Authentication.DMARC, -4, 2), -15, 5),
		cfg.signal("rspamd_score", "content", rspamdScoreAdjustment(n.Content.RspamdScore), -20, 5),
		cfg.signal("malicious_url", "content", maliciousURLPenalty(n.Content.MaliciousURL), -30, 0),
		cfg.signal("phishing", "content", phishingPenalty(n.Content.PhishingConfidenceLevel), -30, 5),
		cfg.signal("malware", "content", malwareScore(n.Content.MalwareConfirmed), -50, 0),
		cfg.signal("ip_reputation", "connection", n.Connection.IPReputation, -15, 15),
		cfg.signal("asn_reputation", "infrastructure", n.Connection.ASNReputation, -10, 10),
	}

	if direction == "outbound" {
		signals = append(signals,
			cfg.signal("sending_velocity", "behavior", outboundVelocityPenalty(n.Behavior.SendingVelocityLevel), -15, 5, "velocity"),
			cfg.signal("recipient_diversity", "behavior", recipientDiversityPenalty(n.Behavior.RecipientDiversity), -10, 5, "recipient_behavior"),
		)
	}

	return signals
}

func correspondentScore(known bool, interactions int) float64 {
	if !known {
		return 0
	}
	switch {
	case interactions >= 100:
		return 10
	case interactions >= 50:
		return 9
	case interactions >= 25:
		return 8
	case interactions >= 10:
		return 6
	case interactions >= 5:
		return 4
	default:
		return 1
	}
}

func invalidRecipientPenalty(ratio float64) float64 {
	switch {
	case ratio >= 0.8:
		return -10
	case ratio >= 0.6:
		return -9
	case ratio >= 0.3:
		return -7
	case ratio >= 0.1:
		return -3
	case ratio > 0:
		return -1
	default:
		return 0
	}
}

func protocolScore(result string, fail, pass float64) float64 {
	switch result {
	case "fail":
		return fail
	case "pass":
		return pass
	default:
		return 0
	}
}

func phishingPenalty(level string) float64 {
	switch level {
	case "critical":
		return -30
	case "high":
		return -15
	case "medium":
		return -8
	default:
		return 0
	}
}

func malwareScore(confirmed bool) float64 {
	if confirmed {
		return -50
	}
	return 0
}

func authScore(a AuthenticationFacts) float64 {
	score := 0.0
	if a.SPF == "fail" {
		score -= 3
	} else if a.SPF == "pass" {
		score += 1
	}
	if a.DKIM == "fail" {
		score -= 3
	} else if a.DKIM == "pass" {
		score += 1
	}
	if a.DMARC == "fail" {
		score -= 4
	} else if a.DMARC == "pass" {
		score += 2
	}
	return score
}

func rspamdScoreAdjustment(score float64) float64 {
	switch {
	case score >= 15:
		return -20
	case score >= 10:
		return -15
	case score >= 5:
		return -8
	case score >= 2:
		return -3
	case score < 0:
		return 2
	default:
		return 0
	}
}

func maliciousURLPenalty(detected bool) float64 {
	if detected {
		return -10
	}
	return 0
}

func outboundVelocityPenalty(level string) float64 {
	switch level {
	case "critical":
		return -15
	case "high":
		return -8
	case "elevated":
		return -4
	default:
		return 0
	}
}

func recipientDiversityPenalty(v float64) float64 {
	switch {
	case v >= 0.9:
		return -10
	case v >= 0.7:
		return -7
	case v >= 0.5:
		return -4
	case v >= 0.3:
		return -2
	default:
		return 0
	}
}

func addExplainability(e *Explanation, category string, bounded float64) {
	switch category {
	case "connection":
		e.Connection += bounded
	case "infrastructure":
		e.Infrastructure += bounded
	case "identity":
		e.Identity += bounded
	case "relationship":
		e.Relationship += bounded
	case "behavior":
		e.Behavior += bounded
	case "content":
		e.Content += bounded
	case "authentication":
		e.Authentication += bounded
	}
}
