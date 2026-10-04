package telemetry

import (
	"fmt"
	"strings"
	"sync/atomic"
)

type Snapshot struct {
	MessagesReceived      int64 `json:"messages_received"`
	MessagesAccepted      int64 `json:"messages_accepted"`
	MessagesRejected      int64 `json:"messages_rejected"`
	MessagesQuarantined   int64 `json:"messages_quarantined"`
	SMTPConnections       int64 `json:"smtp_connections"`
	InvalidRecipients     int64 `json:"invalid_recipients"`
	EnumerationDetections int64 `json:"enumeration_detections"`
}

type Tracker struct {
	messagesReceived      atomic.Int64
	messagesAccepted      atomic.Int64
	messagesRejected      atomic.Int64
	messagesQuarantined   atomic.Int64
	smtpConnections       atomic.Int64
	invalidRecipients     atomic.Int64
	enumerationDetections atomic.Int64
}

func NewTracker() *Tracker                      { return &Tracker{} }
func (t *Tracker) IncMessagesReceived()         { t.messagesReceived.Add(1) }
func (t *Tracker) IncMessagesAccepted()         { t.messagesAccepted.Add(1) }
func (t *Tracker) IncMessagesRejected()         { t.messagesRejected.Add(1) }
func (t *Tracker) IncMessagesQuarantined()      { t.messagesQuarantined.Add(1) }
func (t *Tracker) IncSMTPConnections()          { t.smtpConnections.Add(1) }
func (t *Tracker) AddInvalidRecipients(n int64) { t.invalidRecipients.Add(n) }
func (t *Tracker) IncEnumerationDetections()    { t.enumerationDetections.Add(1) }

func (t *Tracker) Snapshot() Snapshot {
	return Snapshot{
		MessagesReceived:      t.messagesReceived.Load(),
		MessagesAccepted:      t.messagesAccepted.Load(),
		MessagesRejected:      t.messagesRejected.Load(),
		MessagesQuarantined:   t.messagesQuarantined.Load(),
		SMTPConnections:       t.smtpConnections.Load(),
		InvalidRecipients:     t.invalidRecipients.Load(),
		EnumerationDetections: t.enumerationDetections.Load(),
	}
}

func (t *Tracker) PrometheusText() string {
	s := t.Snapshot()
	lines := []string{
		fmt.Sprintf("mailwarden_messages_received %d", s.MessagesReceived),
		fmt.Sprintf("mailwarden_messages_accepted %d", s.MessagesAccepted),
		fmt.Sprintf("mailwarden_messages_rejected %d", s.MessagesRejected),
		fmt.Sprintf("mailwarden_messages_quarantined %d", s.MessagesQuarantined),
		fmt.Sprintf("mailwarden_smtp_connections %d", s.SMTPConnections),
		fmt.Sprintf("mailwarden_invalid_recipients %d", s.InvalidRecipients),
		fmt.Sprintf("mailwarden_directory_enumeration_detections %d", s.EnumerationDetections),
	}
	return strings.Join(lines, "\n") + "\n"
}
