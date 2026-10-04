package database

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

type PolicyVersion struct {
	ID           int64           `json:"id"`
	VersionLabel string          `json:"version_label"`
	PolicyJSON   json.RawMessage `json:"policy_json"`
	CreatedBy    string          `json:"created_by"`
	CreatedAt    time.Time       `json:"created_at"`
}

type ConfigSnapshot struct {
	ID           int64           `json:"id"`
	SnapshotType string          `json:"snapshot_type"`
	ConfigJSON   json.RawMessage `json:"config_json"`
	CreatedBy    string          `json:"created_by"`
	CreatedAt    time.Time       `json:"created_at"`
}

func (p *Postgres) SavePolicyVersion(ctx context.Context, orgID int64, label string, policy any, createdBy string) (PolicyVersion, error) {
	raw, err := json.Marshal(policy)
	if err != nil {
		return PolicyVersion{}, fmt.Errorf("marshal policy: %w", err)
	}
	var out PolicyVersion
	err = p.pool.QueryRow(ctx, `
		INSERT INTO policy_versions (organization_id, version_label, policy_json, created_by)
		VALUES ($1, $2, $3::jsonb, NULLIF($4,'')::uuid)
		RETURNING id, version_label, policy_json, COALESCE(created_by::text,''), created_at
	`, orgID, label, raw, createdBy).
		Scan(&out.ID, &out.VersionLabel, &out.PolicyJSON, &out.CreatedBy, &out.CreatedAt)
	if err != nil {
		return PolicyVersion{}, fmt.Errorf("insert policy version: %w", err)
	}
	return out, nil
}

func (p *Postgres) ListPolicyVersions(ctx context.Context, orgID int64, limit int) ([]PolicyVersion, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := p.pool.Query(ctx, `
		SELECT id, version_label, policy_json, COALESCE(created_by::text,''), created_at
		  FROM policy_versions
		 WHERE organization_id = $1
		 ORDER BY created_at DESC
		 LIMIT $2
	`, orgID, limit)
	if err != nil {
		return nil, fmt.Errorf("query policy versions: %w", err)
	}
	defer rows.Close()
	out := make([]PolicyVersion, 0, limit)
	for rows.Next() {
		var pv PolicyVersion
		if err := rows.Scan(&pv.ID, &pv.VersionLabel, &pv.PolicyJSON, &pv.CreatedBy, &pv.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan policy version: %w", err)
		}
		out = append(out, pv)
	}
	return out, rows.Err()
}

func (p *Postgres) GetPolicyVersion(ctx context.Context, orgID int64, id int64) (PolicyVersion, error) {
	var out PolicyVersion
	err := p.pool.QueryRow(ctx, `
		SELECT id, version_label, policy_json, COALESCE(created_by::text,''), created_at
		  FROM policy_versions
		 WHERE organization_id = $1 AND id = $2
	`, orgID, id).
		Scan(&out.ID, &out.VersionLabel, &out.PolicyJSON, &out.CreatedBy, &out.CreatedAt)
	if err != nil {
		return PolicyVersion{}, fmt.Errorf("get policy version: %w", err)
	}
	return out, nil
}

func (p *Postgres) SaveConfigSnapshot(ctx context.Context, orgID int64, snapshotType string, config any, createdBy string) (ConfigSnapshot, error) {
	raw, err := json.Marshal(config)
	if err != nil {
		return ConfigSnapshot{}, fmt.Errorf("marshal snapshot: %w", err)
	}
	var out ConfigSnapshot
	err = p.pool.QueryRow(ctx, `
		INSERT INTO config_snapshots (organization_id, snapshot_type, config_json, created_by)
		VALUES ($1, $2, $3::jsonb, NULLIF($4,'')::uuid)
		RETURNING id, snapshot_type, config_json, COALESCE(created_by::text,''), created_at
	`, orgID, snapshotType, raw, createdBy).
		Scan(&out.ID, &out.SnapshotType, &out.ConfigJSON, &out.CreatedBy, &out.CreatedAt)
	if err != nil {
		return ConfigSnapshot{}, fmt.Errorf("insert config snapshot: %w", err)
	}
	return out, nil
}

func (p *Postgres) GetConfigSnapshot(ctx context.Context, orgID, id int64) (ConfigSnapshot, error) {
	var out ConfigSnapshot
	err := p.pool.QueryRow(ctx, `
		SELECT id, snapshot_type, config_json, COALESCE(created_by::text,''), created_at
		  FROM config_snapshots
		 WHERE organization_id = $1 AND id = $2
	`, orgID, id).Scan(&out.ID, &out.SnapshotType, &out.ConfigJSON, &out.CreatedBy, &out.CreatedAt)
	if err != nil {
		return ConfigSnapshot{}, fmt.Errorf("get config snapshot: %w", err)
	}
	return out, nil
}

func (p *Postgres) ListConfigSnapshots(ctx context.Context, orgID int64, snapshotType string, limit int) ([]ConfigSnapshot, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := p.pool.Query(ctx, `
		SELECT id, snapshot_type, config_json, COALESCE(created_by::text,''), created_at
		  FROM config_snapshots
		 WHERE organization_id = $1
		   AND ($2 = '' OR snapshot_type = $2)
		 ORDER BY created_at DESC
		 LIMIT $3
	`, orgID, snapshotType, limit)
	if err != nil {
		return nil, fmt.Errorf("query snapshots: %w", err)
	}
	defer rows.Close()
	out := make([]ConfigSnapshot, 0, limit)
	for rows.Next() {
		var s ConfigSnapshot
		if err := rows.Scan(&s.ID, &s.SnapshotType, &s.ConfigJSON, &s.CreatedBy, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan snapshot: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
