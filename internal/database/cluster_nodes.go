package database

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type ClusterNode struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	AdvertisedAddr string          `json:"advertised_addr"`
	Status         string          `json:"status"`
	Role           string          `json:"role"`
	LastSeenAt     *time.Time      `json:"last_seen_at,omitempty"`
	Metadata       json.RawMessage `json:"metadata"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

func (p *Postgres) UpsertClusterNodeHeartbeat(ctx context.Context, orgID int64, name, addr, role string, metadata map[string]any) (ClusterNode, error) {
	if name == "" {
		name = "unnamed-node"
	}
	if role == "" {
		role = "secondary"
	}
	raw, err := json.Marshal(metadata)
	if err != nil {
		return ClusterNode{}, fmt.Errorf("marshal cluster metadata: %w", err)
	}
	var node ClusterNode
	err = p.pool.QueryRow(ctx, `
		INSERT INTO cluster_nodes (id, organization_id, name, advertised_addr, status, role, last_seen_at, metadata)
		VALUES ($1, $2, $3, $4, 'online', $5, NOW(), $6::jsonb)
		ON CONFLICT (organization_id, name)
		DO UPDATE SET
		    advertised_addr = EXCLUDED.advertised_addr,
		    status = 'online',
		    role = EXCLUDED.role,
		    last_seen_at = NOW(),
		    metadata = EXCLUDED.metadata,
		    updated_at = NOW()
		RETURNING id::text, name, advertised_addr, status, role, last_seen_at, metadata, updated_at
	`, uuid.NewString(), orgID, name, addr, role, raw).
		Scan(&node.ID, &node.Name, &node.AdvertisedAddr, &node.Status, &node.Role, &node.LastSeenAt, &node.Metadata, &node.UpdatedAt)
	if err != nil {
		return ClusterNode{}, fmt.Errorf("upsert cluster node: %w", err)
	}
	return node, nil
}

func (p *Postgres) ListClusterNodes(ctx context.Context, orgID int64) ([]ClusterNode, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT id::text, name, advertised_addr, status, role, last_seen_at, metadata, updated_at
		  FROM cluster_nodes
		 WHERE organization_id = $1
		 ORDER BY name
	`, orgID)
	if err != nil {
		return nil, fmt.Errorf("list cluster nodes query: %w", err)
	}
	defer rows.Close()
	out := make([]ClusterNode, 0, 8)
	for rows.Next() {
		var n ClusterNode
		if err := rows.Scan(&n.ID, &n.Name, &n.AdvertisedAddr, &n.Status, &n.Role, &n.LastSeenAt, &n.Metadata, &n.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan cluster node: %w", err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
