package policy

type Config struct {
	Inbound  DecisionThresholds `json:"inbound"`
	Outbound DecisionThresholds `json:"outbound"`
}

type DecisionThresholds struct {
	Reject     float64 `json:"reject" yaml:"reject"`
	Quarantine float64 `json:"quarantine" yaml:"quarantine"`
}
