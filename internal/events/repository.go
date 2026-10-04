package events

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

func (r *Repository) AddMessageEvent(ctx context.Context, messageID int64, eventType Type, metadata map[string]string) error {
	meta := metadata
	if meta == nil {
		meta = map[string]string{}
	}
	j, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal message event metadata: %w", err)
	}
	_, err = r.pool.Exec(ctx, `
		INSERT INTO message_events (message_id, event_type, metadata)
		VALUES ($1, $2, $3::jsonb)
	`, messageID, string(eventType), j)
	if err != nil {
		return fmt.Errorf("insert message event: %w", err)
	}
	return nil
}

func (r *Repository) ListMessageEvents(ctx context.Context, limit int) ([]Event, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id, event_type, event_time, metadata
		  FROM message_events
		 ORDER BY event_time DESC
		 LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("query message events: %w", err)
	}
	defer rows.Close()

	out := make([]Event, 0, limit)
	for rows.Next() {
		var (
			id        int64
			eventType string
			at        time.Time
			rawMeta   []byte
		)
		if err := rows.Scan(&id, &eventType, &at, &rawMeta); err != nil {
			return nil, fmt.Errorf("scan event row: %w", err)
		}
		meta := map[string]string{}
		_ = json.Unmarshal(rawMeta, &meta)
		out = append(out, Event{
			Type:      Type(eventType),
			Timestamp: at,
			EntityID:  fmt.Sprintf("message-event-%d", id),
			Metadata:  meta,
		})
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("iterate events: %w", rows.Err())
	}
	return out, nil
}

func (r *Repository) AddAuditEvent(ctx context.Context, orgID int64, actorUserID, eventType, objectType, objectID string, detail map[string]any) error {
	if detail == nil {
		detail = map[string]any{}
	}
	j, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("marshal audit detail: %w", err)
	}
	_, err = r.pool.Exec(ctx, `
		INSERT INTO audit_events (organization_id, actor_user_id, event_type, object_type, object_id, detail)
		VALUES ($1, NULLIF($2,''), $3, $4, NULLIF($5,''), $6::jsonb)
	`, orgID, actorUserID, eventType, objectType, objectID, j)
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}
