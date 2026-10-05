package database

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/boxorandyos/mail-warden/internal/platform"
	"github.com/google/uuid"
)

func contains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

type PlatformRepo struct {
	pg    *Postgres
	orgID int64
}

func NewPlatformRepo(pg *Postgres, orgID int64) *PlatformRepo {
	return &PlatformRepo{pg: pg, orgID: orgID}
}

func (r *PlatformRepo) Seed(ctx context.Context) error {
	var count int
	if err := r.pg.pool.QueryRow(ctx, `SELECT COUNT(*) FROM platform_environments WHERE organization_id = $1`, r.orgID).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		if _, err := r.pg.pool.Exec(ctx, `INSERT INTO platform_environments (id, organization_id, name, description) VALUES ('env-default', $1, 'default', 'Initial environment')`, r.orgID); err != nil {
			return err
		}
	}
	defaults := []struct {
		name, kind string
		threshold  int
	}{
		{"Availability", "availability", 1},
		{"Backup age", "backup_age", 24},
		{"Node heartbeat", "node_stale", 120},
		{"Failed jobs", "job_failed", 0},
	}
	for _, item := range defaults {
		if _, err := r.pg.pool.Exec(ctx, `
			INSERT INTO platform_alert_rules (id, organization_id, name, kind, threshold, enabled)
			SELECT $1, $2, $3, $4, $5, TRUE
			WHERE NOT EXISTS (SELECT 1 FROM platform_alert_rules WHERE organization_id = $2 AND kind = $4)
		`, uuid.NewString(), r.orgID, item.name, item.kind, item.threshold); err != nil {
			return err
		}
	}
	policies := []struct {
		name, kind string
		threshold  *int
	}{
		{"Require MFA", "require_mfa", nil},
		{"Backup maximum age", "backup_max_age", intPtr(24)},
		{"Node heartbeat age", "node_heartbeat_max_age", intPtr(120)},
	}
	for _, item := range policies {
		if _, err := r.pg.pool.Exec(ctx, `
			INSERT INTO platform_policies (id, organization_id, name, kind, threshold, enabled)
			SELECT $1, $2, $3, $4, $5, TRUE
			WHERE NOT EXISTS (SELECT 1 FROM platform_policies WHERE organization_id = $2 AND kind = $4)
		`, uuid.NewString(), r.orgID, item.name, item.kind, item.threshold); err != nil {
			return err
		}
	}
	return nil
}

func (r *PlatformRepo) ListEnvironments(ctx context.Context) ([]platform.Environment, error) {
	if err := r.Seed(ctx); err != nil {
		return nil, err
	}
	rows, err := r.pg.pool.Query(ctx, `SELECT id, name, description, created_at FROM platform_environments WHERE organization_id = $1 ORDER BY name`, r.orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []platform.Environment{}
	for rows.Next() {
		var item platform.Environment
		if err := rows.Scan(&item.ID, &item.Name, &item.Description, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (r *PlatformRepo) CreateEnvironment(ctx context.Context, name, description string) (platform.Environment, error) {
	item := platform.Environment{ID: uuid.NewString(), Name: name, Description: description, CreatedAt: time.Now().UTC()}
	_, err := r.pg.pool.Exec(ctx, `INSERT INTO platform_environments (id, organization_id, name, description, created_at) VALUES ($1, $2, $3, $4, $5)`, item.ID, r.orgID, item.Name, item.Description, item.CreatedAt)
	return item, err
}

func (r *PlatformRepo) ListAccounts(ctx context.Context) ([]platform.Account, error) {
	rows, err := r.pg.pool.Query(ctx, `SELECT id, name, role, COALESCE(environment_id, ''), created_at FROM platform_service_accounts WHERE organization_id = $1 ORDER BY name`, r.orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []platform.Account{}
	for rows.Next() {
		var item platform.Account
		if err := rows.Scan(&item.ID, &item.Name, &item.Role, &item.EnvironmentID, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (r *PlatformRepo) CreateAccount(ctx context.Context, name, role, environmentID string) (platform.Account, error) {
	if role != "admin" && role != "moderator" && role != "viewer" {
		return platform.Account{}, fmt.Errorf("role must be admin, moderator, or viewer")
	}
	token, hash := platform.NewToken()
	item := platform.Account{ID: uuid.NewString(), Name: name, Role: role, EnvironmentID: environmentID, CreatedAt: time.Now().UTC(), Token: token}
	_, err := r.pg.pool.Exec(ctx, `INSERT INTO platform_service_accounts (id, organization_id, name, role, token_hash, environment_id, created_at) VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7)`, item.ID, r.orgID, name, role, hash, environmentID, item.CreatedAt)
	return item, err
}

func (r *PlatformRepo) DeleteAccount(ctx context.Context, id string) error {
	tag, err := r.pg.pool.Exec(ctx, `DELETE FROM platform_service_accounts WHERE organization_id = $1 AND id = $2`, r.orgID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("service account not found")
	}
	return nil
}

func (r *PlatformRepo) FindAccount(ctx context.Context, token string) (platform.Account, bool, error) {
	var item platform.Account
	err := r.pg.pool.QueryRow(ctx, `SELECT id, name, role, COALESCE(environment_id, '') FROM platform_service_accounts WHERE token_hash = $1`, platform.HashToken(token)).Scan(&item.ID, &item.Name, &item.Role, &item.EnvironmentID)
	if err != nil {
		return platform.Account{}, false, nil
	}
	return item, true, nil
}

func (r *PlatformRepo) ListRunbooks(ctx context.Context, environmentID string) ([]platform.Runbook, error) {
	query := `SELECT id, COALESCE(environment_id, ''), title, body, created_at, updated_at FROM platform_runbooks WHERE organization_id = $1`
	args := []any{r.orgID}
	if environmentID != "" {
		query += ` AND environment_id = $2`
		args = append(args, environmentID)
	}
	query += ` ORDER BY title`
	rows, err := r.pg.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []platform.Runbook{}
	for rows.Next() {
		var item platform.Runbook
		if err := rows.Scan(&item.ID, &item.EnvironmentID, &item.Title, &item.Body, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (r *PlatformRepo) CreateRunbook(ctx context.Context, title, body, environmentID string) (platform.Runbook, error) {
	now := time.Now().UTC()
	item := platform.Runbook{ID: uuid.NewString(), EnvironmentID: environmentID, Title: title, Body: body, CreatedAt: now, UpdatedAt: now}
	_, err := r.pg.pool.Exec(ctx, `INSERT INTO platform_runbooks (id, organization_id, environment_id, title, body, created_at, updated_at) VALUES ($1, $2, NULLIF($3, ''), $4, $5, $6, $7)`, item.ID, r.orgID, environmentID, title, body, now, now)
	return item, err
}

func (r *PlatformRepo) ListRules(ctx context.Context) ([]platform.Rule, error) {
	if err := r.Seed(ctx); err != nil {
		return nil, err
	}
	rows, err := r.pg.pool.Query(ctx, `SELECT id, name, kind, threshold, enabled, COALESCE(environment_id, '') FROM platform_alert_rules WHERE organization_id = $1 ORDER BY name`, r.orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []platform.Rule{}
	for rows.Next() {
		var item platform.Rule
		if err := rows.Scan(&item.ID, &item.Name, &item.Kind, &item.Threshold, &item.Enabled, &item.EnvironmentID); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (r *PlatformRepo) CreateRule(ctx context.Context, name, kind string, threshold int) (platform.Rule, error) {
	if !contains(platform.AlertKinds, kind) {
		return platform.Rule{}, fmt.Errorf("kind must be %s", strings.Join(platform.AlertKinds, ", "))
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return platform.Rule{}, fmt.Errorf("name is required")
	}
	item := platform.Rule{ID: uuid.NewString(), Name: name, Kind: kind, Threshold: threshold, Enabled: true}
	_, err := r.pg.pool.Exec(ctx, `INSERT INTO platform_alert_rules (id, organization_id, name, kind, threshold, enabled) VALUES ($1, $2, $3, $4, $5, TRUE)`, item.ID, r.orgID, item.Name, item.Kind, item.Threshold)
	return item, err
}

func (r *PlatformRepo) SetRuleEnabled(ctx context.Context, id string, enabled bool) error {
	tag, err := r.pg.pool.Exec(ctx, `UPDATE platform_alert_rules SET enabled = $1 WHERE organization_id = $2 AND id = $3`, enabled, r.orgID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("alert rule not found")
	}
	return nil
}

func (r *PlatformRepo) ListPolicies(ctx context.Context) ([]platform.Policy, error) {
	if err := r.Seed(ctx); err != nil {
		return nil, err
	}
	rows, err := r.pg.pool.Query(ctx, `SELECT id, name, kind, threshold, enabled, COALESCE(environment_id, '') FROM platform_policies WHERE organization_id = $1 ORDER BY name`, r.orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []platform.Policy{}
	for rows.Next() {
		var item platform.Policy
		if err := rows.Scan(&item.ID, &item.Name, &item.Kind, &item.Threshold, &item.Enabled, &item.EnvironmentID); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (r *PlatformRepo) CreatePolicy(ctx context.Context, name, kind string, threshold *int) (platform.Policy, error) {
	if !contains(platform.PolicyKinds, kind) {
		return platform.Policy{}, fmt.Errorf("kind must be %s", strings.Join(platform.PolicyKinds, ", "))
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return platform.Policy{}, fmt.Errorf("name is required")
	}
	item := platform.Policy{ID: uuid.NewString(), Name: name, Kind: kind, Threshold: threshold, Enabled: true}
	_, err := r.pg.pool.Exec(ctx, `INSERT INTO platform_policies (id, organization_id, name, kind, threshold, enabled) VALUES ($1, $2, $3, $4, $5, TRUE)`, item.ID, r.orgID, item.Name, item.Kind, item.Threshold)
	return item, err
}

func (r *PlatformRepo) SetPolicyEnabled(ctx context.Context, id string, enabled bool) error {
	tag, err := r.pg.pool.Exec(ctx, `UPDATE platform_policies SET enabled = $1 WHERE organization_id = $2 AND id = $3`, enabled, r.orgID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("policy not found")
	}
	return nil
}

func (r *PlatformRepo) Violations(ctx context.Context) ([]platform.Violation, error) {
	policies, err := r.ListPolicies(ctx)
	if err != nil {
		return nil, err
	}
	signals, err := r.signals(ctx)
	if err != nil {
		return nil, err
	}
	_ = r.addJob(ctx, "policy.evaluate", "operator", "succeeded", "")
	return platform.Evaluate(policies, signals, time.Now().UTC()), nil
}

func (r *PlatformRepo) ListJobs(ctx context.Context) ([]platform.Job, error) {
	rows, err := r.pg.pool.Query(ctx, `SELECT id, type, status, actor, COALESCE(error, ''), created_at, finished_at FROM platform_jobs WHERE organization_id = $1 ORDER BY created_at DESC LIMIT 200`, r.orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []platform.Job{}
	for rows.Next() {
		var item platform.Job
		if err := rows.Scan(&item.ID, &item.Type, &item.Status, &item.Actor, &item.Error, &item.CreatedAt, &item.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (r *PlatformRepo) Capture(ctx context.Context, actor string) (platform.Snapshot, error) {
	doc, err := r.Document(ctx)
	if err != nil {
		return platform.Snapshot{}, err
	}
	raw, _ := json.Marshal(doc)
	item := platform.Snapshot{ID: uuid.NewString(), Actor: actor, CreatedAt: time.Now().UTC()}
	_, err = r.pg.pool.Exec(ctx, `INSERT INTO platform_snapshots (id, organization_id, actor, body, created_at) VALUES ($1, $2, $3, $4::jsonb, $5)`, item.ID, r.orgID, actor, raw, item.CreatedAt)
	if err != nil {
		return platform.Snapshot{}, err
	}
	_ = r.addJob(ctx, "snapshot", actor, "succeeded", "")
	return item, nil
}

func (r *PlatformRepo) ListSnapshots(ctx context.Context) ([]platform.Snapshot, error) {
	rows, err := r.pg.pool.Query(ctx, `SELECT id, actor, created_at FROM platform_snapshots WHERE organization_id = $1 ORDER BY created_at DESC`, r.orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []platform.Snapshot{}
	for rows.Next() {
		var item platform.Snapshot
		if err := rows.Scan(&item.ID, &item.Actor, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (r *PlatformRepo) Apply(ctx context.Context, id string) error {
	var raw []byte
	if err := r.pg.pool.QueryRow(ctx, `SELECT body FROM platform_snapshots WHERE organization_id = $1 AND id = $2`, r.orgID, id).Scan(&raw); err != nil {
		return fmt.Errorf("snapshot not found")
	}
	var doc platform.Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	return r.ApplyDocument(ctx, doc)
}

func (r *PlatformRepo) ApplyDocument(ctx context.Context, doc platform.Document) error {
	for _, item := range doc.Environments {
		if _, err := r.pg.pool.Exec(ctx, `
			INSERT INTO platform_environments (id, organization_id, name, description, created_at) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description
		`, item.ID, r.orgID, item.Name, item.Description, item.CreatedAt); err != nil {
			return err
		}
	}
	if _, err := r.pg.pool.Exec(ctx, `DELETE FROM platform_runbooks WHERE organization_id = $1`, r.orgID); err != nil {
		return err
	}
	for _, item := range doc.Runbooks {
		if _, err := r.pg.pool.Exec(ctx, `INSERT INTO platform_runbooks (id, organization_id, environment_id, title, body, created_at, updated_at) VALUES ($1, $2, NULLIF($3, ''), $4, $5, $6, $7)`, item.ID, r.orgID, item.EnvironmentID, item.Title, item.Body, item.CreatedAt, item.UpdatedAt); err != nil {
			return err
		}
	}
	if _, err := r.pg.pool.Exec(ctx, `DELETE FROM platform_policies WHERE organization_id = $1`, r.orgID); err != nil {
		return err
	}
	for _, item := range doc.Policies {
		if _, err := r.pg.pool.Exec(ctx, `INSERT INTO platform_policies (id, organization_id, name, kind, threshold, enabled, environment_id) VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''))`, item.ID, r.orgID, item.Name, item.Kind, item.Threshold, item.Enabled, item.EnvironmentID); err != nil {
			return err
		}
	}
	if _, err := r.pg.pool.Exec(ctx, `DELETE FROM platform_alert_rules WHERE organization_id = $1`, r.orgID); err != nil {
		return err
	}
	for _, item := range doc.AlertRules {
		if _, err := r.pg.pool.Exec(ctx, `INSERT INTO platform_alert_rules (id, organization_id, name, kind, threshold, enabled, environment_id) VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''))`, item.ID, r.orgID, item.Name, item.Kind, item.Threshold, item.Enabled, item.EnvironmentID); err != nil {
			return err
		}
	}
	return nil
}

func (r *PlatformRepo) Document(ctx context.Context) (platform.Document, error) {
	environments, err := r.ListEnvironments(ctx)
	if err != nil {
		return platform.Document{}, err
	}
	runbooks, err := r.ListRunbooks(ctx, "")
	if err != nil {
		return platform.Document{}, err
	}
	rules, err := r.ListRules(ctx)
	if err != nil {
		return platform.Document{}, err
	}
	policies, err := r.ListPolicies(ctx)
	if err != nil {
		return platform.Document{}, err
	}
	return platform.Document{Environments: environments, Runbooks: runbooks, AlertRules: rules, Policies: policies}, nil
}

func (r *PlatformRepo) Metrics(ctx context.Context) (map[string]any, error) {
	jobs := map[string]int{}
	rows, err := r.pg.pool.Query(ctx, `SELECT status, COUNT(*) FROM platform_jobs WHERE organization_id = $1 GROUP BY status`, r.orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		jobs[status] = count
	}
	var nodes, rules int
	_ = r.pg.pool.QueryRow(ctx, `SELECT COUNT(*) FROM cluster_nodes WHERE organization_id = $1`, r.orgID).Scan(&nodes)
	_ = r.pg.pool.QueryRow(ctx, `SELECT COUNT(*) FROM platform_alert_rules WHERE organization_id = $1`, r.orgID).Scan(&rules)
	return map[string]any{"up": 1, "jobs": jobs, "nodes": nodes, "alertRules": rules}, rows.Err()
}

func (r *PlatformRepo) Prometheus(ctx context.Context) (string, error) {
	metrics, err := r.Metrics(ctx)
	if err != nil {
		return "", err
	}
	jobs, _ := metrics["jobs"].(map[string]int)
	nodes, _ := metrics["nodes"].(int)
	rules, _ := metrics["alertRules"].(int)
	return platform.Prometheus(jobs, nodes, rules), nil
}

func (r *PlatformRepo) Audit(ctx context.Context) ([]platform.AuditRow, error) {
	rows, err := r.pg.pool.Query(ctx, `
		SELECT COALESCE(u.username, ''), e.event_type, COALESCE(e.detail::text, ''), e.created_at
		  FROM audit_events e
		  LEFT JOIN users u ON u.id = e.actor_user_id
		 WHERE e.organization_id = $1
		 ORDER BY e.created_at DESC
		 LIMIT 500
	`, r.orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []platform.AuditRow{}
	for rows.Next() {
		var item platform.AuditRow
		if err := rows.Scan(&item.Actor, &item.Action, &item.Detail, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (r *PlatformRepo) ListUpgradeNodes(ctx context.Context) ([]UpgradeNode, error) {
	rows, err := r.pg.pool.Query(ctx, `SELECT name, advertised_addr, role, COALESCE(maintenance_token, '') FROM cluster_nodes WHERE organization_id = $1`, r.orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UpgradeNode{}
	for rows.Next() {
		var item UpgradeNode
		if err := rows.Scan(&item.Name, &item.Address, &item.Role, &item.Token); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

type UpgradeNode struct {
	Name, Address, Role, Token string
}

func (r *PlatformRepo) signals(ctx context.Context) (platform.Signals, error) {
	signals := platform.Signals{}
	rows, err := r.pg.pool.Query(ctx, `SELECT username FROM users WHERE organization_id = $1 AND role = 'admin' AND totp_enabled = FALSE`, r.orgID)
	if err == nil {
		for rows.Next() {
			var name string
			if scanErr := rows.Scan(&name); scanErr == nil {
				signals.AdminsWithoutMFA = append(signals.AdminsWithoutMFA, name)
			}
		}
		rows.Close()
	}
	var backup *time.Time
	_ = r.pg.pool.QueryRow(ctx, `SELECT MAX(created_at) FROM platform_snapshots WHERE organization_id = $1`, r.orgID).Scan(&backup)
	signals.NewestBackupAt = backup
	nodeRows, err := r.pg.pool.Query(ctx, `SELECT id::text, name, last_seen_at FROM cluster_nodes WHERE organization_id = $1`, r.orgID)
	if err == nil {
		for nodeRows.Next() {
			var node platform.NodeSignal
			if scanErr := nodeRows.Scan(&node.ID, &node.Name, &node.LastSeenAt); scanErr == nil {
				signals.Nodes = append(signals.Nodes, node)
			}
		}
		nodeRows.Close()
	}
	_ = r.pg.pool.QueryRow(ctx, `SELECT COUNT(*) FROM platform_jobs WHERE organization_id = $1 AND status = 'failed' AND created_at > NOW() - INTERVAL '24 hours'`, r.orgID).Scan(&signals.FailedJobs)
	return signals, nil
}

func (r *PlatformRepo) addJob(ctx context.Context, kind, actor, status, errText string) error {
	now := time.Now().UTC()
	_, err := r.pg.pool.Exec(ctx, `INSERT INTO platform_jobs (id, organization_id, type, status, actor, error, created_at, finished_at) VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7, $7)`, uuid.NewString(), r.orgID, kind, status, actor, errText, now)
	return err
}

func intPtr(value int) *int { return &value }
