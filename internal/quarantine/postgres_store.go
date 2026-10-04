package quarantine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/boxorandyos/mail-warden/internal/identity"
	"github.com/boxorandyos/mail-warden/internal/scoring"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const quarantineSelect = `
	id, sender, recipients, subject, reason, decision, status, created_at, released_at,
	COALESCE(queue_id, ''), COALESCE(direction, ''), COALESCE(decision_input, '{}'::jsonb)
`

type PostgresStore struct {
	pool           *pgxpool.Pool
	organizationID int64
}

func NewPostgresStore(pool *pgxpool.Pool, organizationID int64) *PostgresStore {
	return &PostgresStore{
		pool:           pool,
		organizationID: organizationID,
	}
}

func (s *PostgresStore) Add(ctx context.Context, msg Message) (Message, error) {
	if msg.ReceivedAt.IsZero() {
		msg.ReceivedAt = time.Now().UTC()
	}
	if msg.Status == "" {
		msg.Status = StatusQuarantined
	}
	decisionBytes, err := json.Marshal(msg.Decision)
	if err != nil {
		return Message{}, fmt.Errorf("marshal decision: %w", err)
	}
	inputBytes, err := json.Marshal(msg.DecisionInput)
	if err != nil {
		return Message{}, fmt.Errorf("marshal decision input: %w", err)
	}

	var id int64
	err = s.pool.QueryRow(ctx, `
		INSERT INTO quarantine_messages
		    (organization_id, sender, recipients, subject, reason, decision, status, created_at, queue_id, direction, decision_input)
		VALUES
		    ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10, $11::jsonb)
		RETURNING id
	`, s.organizationID, msg.From, msg.To, msg.Subject, msg.Reason, decisionBytes, string(msg.Status), msg.ReceivedAt, msg.QueueID, msg.Direction, inputBytes).Scan(&id)
	if err != nil {
		return Message{}, fmt.Errorf("insert quarantine message: %w", err)
	}
	msg.ID = fmt.Sprintf("qmsg-%d", id)
	return msg, nil
}

func (s *PostgresStore) List(ctx context.Context, limit int) ([]Message, error) {
	return s.list(ctx, limit, "")
}

func (s *PostgresStore) ListScoped(ctx context.Context, limit int, email string) ([]Message, error) {
	if strings.TrimSpace(email) == "" {
		return []Message{}, nil
	}
	return s.list(ctx, limit, email)
}

func (s *PostgresStore) list(ctx context.Context, limit int, email string) ([]Message, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT `+quarantineSelect+`
		  FROM quarantine_messages
		 WHERE organization_id = $1
		   AND ($2 = '' OR lower(sender) = lower($2) OR EXISTS (
		        SELECT 1 FROM unnest(recipients) AS recipient WHERE lower(recipient) = lower($2)
		   ))
		 ORDER BY created_at DESC
		 LIMIT $3
	`, s.organizationID, strings.TrimSpace(email), limit)
	if err != nil {
		return nil, fmt.Errorf("list quarantine messages: %w", err)
	}
	defer rows.Close()

	out := make([]Message, 0, limit)
	for rows.Next() {
		msg, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		if email != "" && !identity.OwnsMail(email, msg.From, msg.To) {
			continue
		}
		out = append(out, msg)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("iterate quarantine rows: %w", rows.Err())
	}
	return out, nil
}

func (s *PostgresStore) Get(ctx context.Context, id string) (Message, error) {
	innerID, err := parsePrefixedID(id)
	if err != nil {
		return Message{}, err
	}
	row := s.pool.QueryRow(ctx, `
		SELECT `+quarantineSelect+`
		  FROM quarantine_messages
		 WHERE organization_id = $1
		   AND id = $2
	`, s.organizationID, innerID)
	return scanMessage(row)
}

func (s *PostgresStore) Release(ctx context.Context, id string) (Message, error) {
	return s.UpdateAfterRescan(ctx, id, scoring.Decision{}, "", true)
}

func (s *PostgresStore) UpdateAfterRescan(ctx context.Context, id string, decision scoring.Decision, reason string, release bool) (Message, error) {
	innerID, err := parsePrefixedID(id)
	if err != nil {
		return Message{}, err
	}
	current, err := s.Get(ctx, id)
	if err != nil {
		return Message{}, err
	}
	if decision.Action != "" || decision.Reason != "" || len(decision.Signals) > 0 {
		current.Decision = decision
	}
	if reason != "" {
		current.Reason = reason
	}
	decisionBytes, err := json.Marshal(current.Decision)
	if err != nil {
		return Message{}, fmt.Errorf("marshal decision: %w", err)
	}
	status := string(StatusQuarantined)
	if release {
		status = string(StatusReleased)
	}
	row := s.pool.QueryRow(ctx, `
		UPDATE quarantine_messages
		   SET status = $3,
		       reason = $4,
		       decision = $5::jsonb,
		       released_at = CASE WHEN $6 THEN NOW() ELSE released_at END
		 WHERE organization_id = $1
		   AND id = $2
		RETURNING `+quarantineSelect+`
	`, s.organizationID, innerID, status, current.Reason, decisionBytes, release)
	return scanMessage(row)
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanMessage(s rowScanner) (Message, error) {
	var (
		id          int64
		from        string
		to          []string
		subject     *string
		reason      string
		decisionRaw []byte
		statusRaw   string
		createdAt   time.Time
		releasedAt  *time.Time
		queueID     string
		direction   string
		inputRaw    []byte
	)
	err := s.Scan(&id, &from, &to, &subject, &reason, &decisionRaw, &statusRaw, &createdAt, &releasedAt, &queueID, &direction, &inputRaw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Message{}, ErrNotFound
		}
		return Message{}, fmt.Errorf("scan quarantine message: %w", err)
	}

	var decision scoring.Decision
	if len(decisionRaw) > 0 {
		if err := json.Unmarshal(decisionRaw, &decision); err != nil {
			return Message{}, fmt.Errorf("unmarshal decision: %w", err)
		}
	}
	var input scoring.NormalizedDecisionObject
	if len(inputRaw) > 0 {
		_ = json.Unmarshal(inputRaw, &input)
	}
	msg := Message{
		ID:            fmt.Sprintf("qmsg-%d", id),
		From:          from,
		To:            to,
		Reason:        reason,
		Decision:      decision,
		DecisionInput: input,
		QueueID:       queueID,
		Direction:     direction,
		ReceivedAt:    createdAt,
		Status:        Status(statusRaw),
		ReleasedAt:    releasedAt,
	}
	if subject != nil {
		msg.Subject = *subject
	}
	return msg, nil
}

func parsePrefixedID(id string) (int64, error) {
	clean := strings.TrimSpace(strings.TrimPrefix(id, "qmsg-"))
	parsed, err := strconv.ParseInt(clean, 10, 64)
	if err != nil || parsed <= 0 {
		return 0, ErrNotFound
	}
	return parsed, nil
}
