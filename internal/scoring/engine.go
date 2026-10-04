package scoring

import "math"

type EngineConfig struct {
	InboundRejectThreshold      float64
	InboundQuarantineThreshold  float64
	OutboundRejectThreshold     float64
	OutboundQuarantineThreshold float64
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
	hardSignals := collectHardSignals(n)
	if len(hardSignals) > 0 {
		return Decision{
			Action:      hardSignalAction(hardSignals),
			Reason:      "hard security gate triggered",
			Direction:   direction,
			HardSignals: hardSignals,
		}
	}

	signals := buildSignals(direction, n)

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

func collectHardSignals(n NormalizedDecisionObject) []HardSignal {
	var out []HardSignal
	if n.Content.MalwareConfirmed {
		out = append(out, HardMalwareConfirmed)
	}
	if n.Content.MaliciousURL && n.Content.MaliciousURLConfidence == "critical" {
		out = append(out, HardMaliciousURLCritical)
	}
	if n.Behavior.EnumerationLikely && n.Envelope.InvalidRatio >= 0.8 {
		out = append(out, HardProtocolAbuse)
	}
	return out
}

func hardSignalAction(hardSignals []HardSignal) Action {
	for _, h := range hardSignals {
		if h == HardMalwareConfirmed {
			return ActionReject
		}
	}
	return ActionQuarantine
}

func buildSignals(direction string, n NormalizedDecisionObject) []Signal {
	signals := []Signal{
		{
			Name:     "sender_reputation",
			Category: "identity",
			Value:    n.Identity.SenderReputation,
			Min:      -10,
			Max:      10,
		},
		{
			Name:     "domain_reputation",
			Category: "identity",
			Value:    n.Identity.DomainReputation,
			Min:      -10,
			Max:      10,
		},
		{
			Name:     "known_correspondent",
			Category: "relationship",
			Value:    correspondentScore(n.Relationship.KnownCorrespondent, n.Relationship.InteractionCount),
			Min:      -10,
			Max:      10,
		},
		{
			Name:     "invalid_recipient_ratio",
			Category: "behavior",
			Value:    invalidRecipientPenalty(n.Envelope.InvalidRatio),
			Min:      -15,
			Max:      5,
		},
		{
			Name:     "authentication",
			Category: "authentication",
			Value:    authScore(n.Authentication),
			Min:      -15,
			Max:      5,
		},
		{
			Name:     "rspamd_score",
			Category: "content",
			Value:    rspamdScoreAdjustment(n.Content.RspamdScore),
			Min:      -20,
			Max:      5,
		},
		{
			Name:     "malicious_url",
			Category: "content",
			Value:    maliciousURLPenalty(n.Content.MaliciousURL),
			Min:      -30,
			Max:      0,
		},
	}

	if direction == "outbound" {
		signals = append(signals,
			Signal{
				Name:     "sending_velocity",
				Category: "behavior",
				Value:    outboundVelocityPenalty(n.Behavior.SendingVelocityLevel),
				Min:      -15,
				Max:      5,
			},
			Signal{
				Name:     "recipient_diversity",
				Category: "behavior",
				Value:    recipientDiversityPenalty(n.Behavior.RecipientDiversity),
				Min:      -10,
				Max:      5,
			},
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
