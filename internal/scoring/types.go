package scoring

import "time"

type Action string

const (
	ActionAccept      Action = "accept"
	ActionQuarantine  Action = "quarantine"
	ActionReject      Action = "reject"
	ActionThrottle    Action = "throttle"
	ActionTempFailure Action = "temporary_failure"
)

type Signal struct {
	Name     string  `json:"name"`
	Category string  `json:"category"`
	Value    float64 `json:"value"`
	Min      float64 `json:"min"`
	Max      float64 `json:"max"`
}

func (s Signal) Bounded() float64 {
	if s.Value < s.Min {
		return s.Min
	}
	if s.Value > s.Max {
		return s.Max
	}
	return s.Value
}

type HardSignal string

const (
	HardMalwareConfirmed     HardSignal = "malware_confirmed"
	HardExploitConfirmed     HardSignal = "exploit_confirmed"
	HardMaliciousURLCritical HardSignal = "malicious_url_critical"
	HardProtocolAbuse        HardSignal = "protocol_abuse"
)

type NormalizedDecisionObject struct {
	Connection     ConnectionFacts     `json:"connection"`
	Envelope       EnvelopeFacts       `json:"envelope"`
	Authentication AuthenticationFacts `json:"authentication"`
	Identity       IdentityFacts       `json:"identity"`
	Relationship   RelationshipFacts   `json:"relationship"`
	Behavior       BehaviorFacts       `json:"behavior"`
	Content        ContentFacts        `json:"content"`
	ObservedAt     time.Time           `json:"observed_at"`
}

type ConnectionFacts struct {
	IP                string  `json:"ip"`
	ASN               int     `json:"asn"`
	RDNS              string  `json:"rdns"`
	ConnectionRatePer float64 `json:"connection_rate_per_minute"`
	IPReputation      float64 `json:"ip_reputation,omitempty"`
	ASNReputation     float64 `json:"asn_reputation,omitempty"`
}

type EnvelopeFacts struct {
	From           string   `json:"from"`
	Recipients     []string `json:"recipients"`
	InvalidRatio   float64  `json:"invalid_recipient_ratio"`
	RecipientBurst bool     `json:"recipient_burst"`
}

type AuthenticationFacts struct {
	SPF   string `json:"spf"`
	DKIM  string `json:"dkim"`
	DMARC string `json:"dmarc"`
	ARC   string `json:"arc"`
}

type IdentityFacts struct {
	SenderReputation float64 `json:"sender_reputation"`
	DomainReputation float64 `json:"domain_reputation"`
}

type RelationshipFacts struct {
	KnownCorrespondent   bool    `json:"known_correspondent"`
	InteractionCount     int     `json:"interaction_count"`
	HistoricalScoreHint  float64 `json:"historical_score_hint"`
	LastSeenDaysAgo      int     `json:"last_seen_days_ago"`
	InfrastructureStable bool    `json:"infrastructure_stable"`
}

type BehaviorFacts struct {
	SendingVelocityLevel string  `json:"sending_velocity_level"`
	RecipientDiversity   float64 `json:"recipient_diversity"`
	EnumerationLikely    bool    `json:"enumeration_likely"`
}

type ContentFacts struct {
	RspamdScore             float64 `json:"rspamd_score"`
	MaliciousURL            bool    `json:"malicious_url"`
	MaliciousURLConfidence  string  `json:"malicious_url_confidence"`
	MalwareConfirmed        bool    `json:"malware_confirmed"`
	ExploitConfirmed        bool    `json:"exploit_confirmed"`
	PhishingConfidenceLevel string  `json:"phishing_confidence_level"`
}

type Decision struct {
	Action      Action       `json:"action"`
	Score       float64      `json:"score"`
	TrustScore  float64      `json:"trust_score"`
	RiskScore   float64      `json:"risk_score"`
	Reason      string       `json:"reason"`
	Direction   string       `json:"direction"`
	Signals     []Signal     `json:"signals"`
	HardSignals []HardSignal `json:"hard_signals"`
	Explanation Explanation  `json:"explanation"`
}

type Explanation struct {
	Connection      float64 `json:"connection"`
	Infrastructure  float64 `json:"infrastructure"`
	Identity        float64 `json:"identity"`
	Relationship    float64 `json:"relationship"`
	Behavior        float64 `json:"behavior"`
	Content         float64 `json:"content"`
	Authentication  float64 `json:"authentication"`
	FinalBoundedSum float64 `json:"final_bounded_sum"`
}
