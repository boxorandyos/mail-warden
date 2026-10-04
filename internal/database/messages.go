package database

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type MessageRecord struct {
	ID            int64           `json:"id"`
	Direction     string          `json:"direction"`
	Sender        string          `json:"sender"`
	Recipients    []string        `json:"recipients"`
	SourceIP      string          `json:"source_ip"`
	PolicyAction  string          `json:"policy_action"`
	PolicyScore   float64         `json:"policy_score"`
	ObservedAt    time.Time       `json:"observed_at"`
	Quarantined   bool            `json:"quarantined"`
	Subject       string          `json:"subject,omitempty"`
	QueueID       string          `json:"queue_id,omitempty"`
	Decision      json.RawMessage `json:"decision,omitempty"`
	DecisionInput json.RawMessage `json:"decision_input,omitempty"`
}

func (p *Postgres) InsertMessage(ctx context.Context, orgID int64, rec MessageRecord) (int64, error) {
	var id int64
	err := p.pool.QueryRow(ctx, `
		INSERT INTO messages (organization_id, direction, sender, recipients, source_ip, policy_action, policy_score, observed_at, quarantined, subject, queue_id, decision, decision_input)
		VALUES ($1, $2, $3, $4, NULLIF($5,''), $6, $7, $8, $9, $10, $11, $12::jsonb, $13::jsonb)
		RETURNING id
	`, orgID, rec.Direction, rec.Sender, rec.Recipients, rec.SourceIP, rec.PolicyAction, rec.PolicyScore, rec.ObservedAt, rec.Quarantined, rec.Subject, rec.QueueID, jsonbOrEmpty(rec.Decision), jsonbOrEmpty(rec.DecisionInput)).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert message: %w", err)
	}
	return id, nil
}

func (p *Postgres) ListMessages(ctx context.Context, orgID int64, direction string, limit int) ([]MessageRecord, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := p.pool.Query(ctx, `
		SELECT id, direction, sender, recipients, COALESCE(source_ip::text,''), policy_action, policy_score, observed_at, quarantined
		  FROM messages
		 WHERE organization_id = $1
		   AND ($2 = '' OR direction = $2)
		 ORDER BY observed_at DESC
		 LIMIT $3
	`, orgID, direction, limit)
	if err != nil {
		return nil, fmt.Errorf("query messages: %w", err)
	}
	defer rows.Close()

	out := make([]MessageRecord, 0, limit)
	for rows.Next() {
		var m MessageRecord
		if err := rows.Scan(&m.ID, &m.Direction, &m.Sender, &m.Recipients, &m.SourceIP, &m.PolicyAction, &m.PolicyScore, &m.ObservedAt, &m.Quarantined); err != nil {
			return nil, fmt.Errorf("scan message row: %w", err)
		}
		out = append(out, m)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("iterate messages: %w", rows.Err())
	}
	return out, nil
}

func (p *Postgres) ListMessagesVisible(ctx context.Context, orgID int64, direction, email string, all bool, limit int) ([]MessageRecord, error) {
	if limit <= 0 {
		limit = 200
	}
	viewer := ""
	if !all {
		viewer = strings.TrimSpace(email)
		if viewer == "" {
			return []MessageRecord{}, nil
		}
	}
	rows, err := p.pool.Query(ctx, `
		SELECT id, direction, sender, recipients, COALESCE(source_ip::text,''), policy_action, policy_score, observed_at, quarantined,
		       COALESCE(subject, ''), COALESCE(queue_id, '')
		  FROM messages
		 WHERE organization_id = $1
		   AND ($2 = '' OR direction = $2)
		   AND ($3 = '' OR lower(sender) = lower($3) OR EXISTS (
		        SELECT 1 FROM unnest(recipients) AS recipient WHERE lower(recipient) = lower($3)
		   ))
		 ORDER BY observed_at DESC
		 LIMIT $4
	`, orgID, direction, viewer, limit)
	if err != nil {
		return nil, fmt.Errorf("query visible messages: %w", err)
	}
	defer rows.Close()
	out := make([]MessageRecord, 0, limit)
	for rows.Next() {
		var m MessageRecord
		if err := rows.Scan(&m.ID, &m.Direction, &m.Sender, &m.Recipients, &m.SourceIP, &m.PolicyAction, &m.PolicyScore, &m.ObservedAt, &m.Quarantined, &m.Subject, &m.QueueID); err != nil {
			return nil, fmt.Errorf("scan message row: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (p *Postgres) GetMessage(ctx context.Context, orgID, id int64) (MessageRecord, error) {
	var m MessageRecord
	err := p.pool.QueryRow(ctx, `
		SELECT id, direction, sender, recipients, COALESCE(source_ip::text,''), policy_action, policy_score, observed_at, quarantined,
		       COALESCE(subject, ''), COALESCE(queue_id, ''), COALESCE(decision, '{}'::jsonb), COALESCE(decision_input, '{}'::jsonb)
		  FROM messages
		 WHERE organization_id = $1 AND id = $2
	`, orgID, id).Scan(&m.ID, &m.Direction, &m.Sender, &m.Recipients, &m.SourceIP, &m.PolicyAction, &m.PolicyScore, &m.ObservedAt, &m.Quarantined, &m.Subject, &m.QueueID, &m.Decision, &m.DecisionInput)
	if err != nil {
		return MessageRecord{}, fmt.Errorf("get message: %w", err)
	}
	return m, nil
}

func jsonbOrEmpty(raw []byte) []byte {
	if len(raw) == 0 {
		return []byte(`{}`)
	}
	return raw
}
