package config

import (
	"fmt"
	"math"
	"strings"
)

var allowedHardBlocks = map[string]struct{}{
	"malware_confirmed":      {},
	"exploit_confirmed":      {},
	"malicious_url_critical": {},
	"protocol_abuse":         {},
}

var allowedCaps = map[string]struct{}{
	"correspondent_history":   {},
	"sender_history":          {},
	"domain_history":          {},
	"ip_reputation":           {},
	"asn_reputation":          {},
	"spf":                     {},
	"dkim":                    {},
	"dmarc":                   {},
	"recipient_behavior":      {},
	"velocity":                {},
	"phishing":                {},
	"malware":                 {},
	"sender_reputation":       {},
	"domain_reputation":       {},
	"known_correspondent":     {},
	"invalid_recipient_ratio": {},
	"sending_velocity":        {},
	"recipient_diversity":     {},
	"rspamd_score":            {},
	"malicious_url":           {},
}

func ValidatePolicy(cfg PolicyConfig) error {
	if err := validateThresholds("inbound", cfg.Policy.Inbound.Reject, cfg.Policy.Inbound.Quarantine); err != nil {
		return err
	}
	if err := validateThresholds("outbound", cfg.Policy.Outbound.Reject, cfg.Policy.Outbound.Quarantine); err != nil {
		return err
	}
	if cfg.Policy.Outbound.Throttle.RecipientsPerHour < 0 || cfg.Policy.Outbound.Throttle.UniqueDomainsPerHour < 0 {
		return fmt.Errorf("outbound throttle limits must be zero or positive")
	}
	for _, name := range cfg.HardBlocks {
		if _, ok := allowedHardBlocks[strings.TrimSpace(name)]; !ok {
			return fmt.Errorf("unknown hard block %q", name)
		}
	}
	for key, cap := range cfg.Caps {
		if _, ok := allowedCaps[key]; !ok {
			return fmt.Errorf("unknown signal cap %q", key)
		}
		if math.IsNaN(cap.Min) || math.IsNaN(cap.Max) || math.IsInf(cap.Min, 0) || math.IsInf(cap.Max, 0) {
			return fmt.Errorf("signal cap %q must be a finite number", key)
		}
	}
	return nil
}

func validateThresholds(direction string, reject, quarantine float64) error {
	if math.IsNaN(reject) || math.IsNaN(quarantine) || math.IsInf(reject, 0) || math.IsInf(quarantine, 0) {
		return fmt.Errorf("%s thresholds must be finite numbers", direction)
	}
	if quarantine < reject {
		return fmt.Errorf("%s quarantine threshold must be greater than or equal to the reject threshold", direction)
	}
	return nil
}
