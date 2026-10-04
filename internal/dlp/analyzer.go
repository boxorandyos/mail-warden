package dlp

import (
	"regexp"
	"strings"
)

type Finding struct {
	Rule       string `json:"rule"`
	Confidence string `json:"confidence"`
}

type Result struct {
	Matched   bool      `json:"matched"`
	Findings  []Finding `json:"findings"`
	RiskScore int       `json:"risk_score"`
}

var (
	reSecretToken = regexp.MustCompile(`(?i)(api[_-]?key|secret|token)\s*[:=]\s*[A-Za-z0-9_\-]{8,}`)
	reCreditCard  = regexp.MustCompile(`\b(?:\d[ -]*?){13,16}\b`)
	reIBAN        = regexp.MustCompile(`\b[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}\b`)
)

func Analyze(raw string, attachments []string) Result {
	rawLower := strings.ToLower(raw)
	out := Result{
		Findings: make([]Finding, 0, 4),
	}

	if reSecretToken.MatchString(raw) {
		out.Findings = append(out.Findings, Finding{Rule: "secret_token_pattern", Confidence: "high"})
		out.RiskScore += 25
	}
	if reCreditCard.MatchString(raw) {
		out.Findings = append(out.Findings, Finding{Rule: "payment_card_pattern", Confidence: "medium"})
		out.RiskScore += 15
	}
	if reIBAN.MatchString(raw) {
		out.Findings = append(out.Findings, Finding{Rule: "iban_pattern", Confidence: "medium"})
		out.RiskScore += 12
	}
	for _, f := range attachments {
		lf := strings.ToLower(strings.TrimSpace(f))
		if strings.HasSuffix(lf, ".pem") || strings.HasSuffix(lf, ".p12") || strings.HasSuffix(lf, ".key") || strings.HasSuffix(lf, ".env") {
			out.Findings = append(out.Findings, Finding{Rule: "sensitive_attachment_type", Confidence: "high"})
			out.RiskScore += 20
		}
		if strings.Contains(rawLower, "confidential") || strings.Contains(rawLower, "do not share") {
			out.RiskScore += 5
		}
	}
	out.Matched = len(out.Findings) > 0
	return out
}
