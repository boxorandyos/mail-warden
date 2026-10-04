package events

import "time"

type Type string

const (
	SMTPConnection             Type = "SMTP_CONNECTION"
	SMTPDisconnect             Type = "SMTP_DISCONNECT"
	SMTPCommand                Type = "SMTP_COMMAND"
	SMTPReject                 Type = "SMTP_REJECT"
	EnvelopeReceived           Type = "ENVELOPE_RECEIVED"
	RecipientValid             Type = "RECIPIENT_VALID"
	RecipientInvalid           Type = "RECIPIENT_INVALID"
	MessageReceived            Type = "MESSAGE_RECEIVED"
	MessageScanned             Type = "MESSAGE_SCANNED"
	MessageAccepted            Type = "MESSAGE_ACCEPTED"
	MessageRejected            Type = "MESSAGE_REJECTED"
	MessageQuarantined         Type = "MESSAGE_QUARANTINED"
	SPFResult                  Type = "SPF_RESULT"
	DKIMResult                 Type = "DKIM_RESULT"
	DMARCResult                Type = "DMARC_RESULT"
	MalwareDetected            Type = "MALWARE_DETECTED"
	PhishingDetected           Type = "PHISHING_DETECTED"
	URLDetected                Type = "URL_DETECTED"
	RateLimit                  Type = "RATE_LIMIT"
	DirectoryEnumeration       Type = "DIRECTORY_ENUMERATION"
	AccountCompromiseSuspected Type = "ACCOUNT_COMPROMISE_SUSPECTED"
	RelationshipCreated        Type = "RELATIONSHIP_CREATED"
	RelationshipUpdated        Type = "RELATIONSHIP_UPDATED"
	ReputationChanged          Type = "REPUTATION_CHANGED"
	PolicyDecision             Type = "POLICY_DECISION"
)

type Event struct {
	Type      Type              `json:"type"`
	Timestamp time.Time         `json:"timestamp"`
	EntityID  string            `json:"entity_id"`
	Metadata  map[string]string `json:"metadata"`
}
