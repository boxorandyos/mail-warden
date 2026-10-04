package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ProviderType string

const (
	ProviderTypeLocal ProviderType = "local"
	ProviderTypeLDAP  ProviderType = "ldap"
	ProviderTypeOIDC  ProviderType = "oidc"
)

type Provider struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Type      ProviderType   `json:"type"`
	Enabled   bool           `json:"enabled"`
	Priority  int            `json:"priority"`
	Config    map[string]any `json:"config"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

type ProvidersRepository struct {
	pool *pgxpool.Pool
	org  int64
}

func NewProvidersRepository(pool *pgxpool.Pool, organizationID int64) *ProvidersRepository {
	return &ProvidersRepository{pool: pool, org: organizationID}
}

func (r *ProvidersRepository) List(ctx context.Context) ([]Provider, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, name, type, enabled, priority, config, created_at, updated_at
		  FROM auth_providers
		 WHERE organization_id = $1
		 ORDER BY priority ASC, name ASC
	`, r.org)
	if err != nil {
		return nil, fmt.Errorf("query providers: %w", err)
	}
	defer rows.Close()
	out := make([]Provider, 0, 8)
	for rows.Next() {
		var (
			p         Provider
			configRaw []byte
		)
		if err := rows.Scan(&p.ID, &p.Name, &p.Type, &p.Enabled, &p.Priority, &configRaw, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan provider: %w", err)
		}
		_ = json.Unmarshal(configRaw, &p.Config)
		maskProviderSecrets(p.Config)
		out = append(out, p)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("iterate providers: %w", rows.Err())
	}
	return out, nil
}

func (r *ProvidersRepository) Upsert(ctx context.Context, provider Provider) (Provider, error) {
	if provider.ID == "" {
		provider.ID = uuid.NewString()
	}
	if provider.Priority == 0 {
		provider.Priority = 100
	}
	if provider.Type == "" {
		return Provider{}, fmt.Errorf("provider type is required")
	}
	if provider.Name == "" {
		provider.Name = string(provider.Type) + "-" + provider.ID[:8]
	}
	if provider.Config == nil {
		provider.Config = map[string]any{}
	}
	if existing, err := r.Get(ctx, provider.ID); err == nil {
		preserveProviderSecrets(provider.Config, existing.Config)
	}
	raw, err := json.Marshal(provider.Config)
	if err != nil {
		return Provider{}, fmt.Errorf("marshal provider config: %w", err)
	}
	var out Provider
	var configRaw []byte
	err = r.pool.QueryRow(ctx, `
		INSERT INTO auth_providers (id, organization_id, name, type, enabled, priority, config)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
		ON CONFLICT (id)
		DO UPDATE SET
		    name = EXCLUDED.name,
		    type = EXCLUDED.type,
		    enabled = EXCLUDED.enabled,
		    priority = EXCLUDED.priority,
		    config = EXCLUDED.config,
		    updated_at = NOW()
		RETURNING id, name, type, enabled, priority, config, created_at, updated_at
	`, provider.ID, r.org, provider.Name, string(provider.Type), provider.Enabled, provider.Priority, raw).
		Scan(&out.ID, &out.Name, &out.Type, &out.Enabled, &out.Priority, &configRaw, &out.CreatedAt, &out.UpdatedAt)
	if err != nil {
		return Provider{}, fmt.Errorf("upsert provider: %w", err)
	}
	_ = json.Unmarshal(configRaw, &out.Config)
	maskProviderSecrets(out.Config)
	return out, nil
}

func (r *ProvidersRepository) Get(ctx context.Context, id string) (Provider, error) {
	var (
		p         Provider
		configRaw []byte
	)
	err := r.pool.QueryRow(ctx, `
		SELECT id, name, type, enabled, priority, config, created_at, updated_at
		  FROM auth_providers
		 WHERE organization_id = $1 AND id = $2
	`, r.org, id).Scan(&p.ID, &p.Name, &p.Type, &p.Enabled, &p.Priority, &configRaw, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return Provider{}, fmt.Errorf("get provider: %w", err)
	}
	_ = json.Unmarshal(configRaw, &p.Config)
	return p, nil
}

func (r *ProvidersRepository) Delete(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM auth_providers WHERE organization_id = $1 AND id = $2`, r.org, id)
	if err != nil {
		return fmt.Errorf("delete provider: %w", err)
	}
	return nil
}

func preserveProviderSecrets(next, prev map[string]any) {
	if next == nil || prev == nil {
		return
	}
	for _, key := range []string{"bindPassword", "clientSecret", "bind_password", "client_secret"} {
		val := strings.TrimSpace(fmt.Sprint(next[key]))
		if val == "" || val == "********" || val == "<nil>" {
			if prevVal, ok := prev[key]; ok && strings.TrimSpace(fmt.Sprint(prevVal)) != "" && fmt.Sprint(prevVal) != "********" {
				next[key] = prevVal
			} else {
				delete(next, key)
			}
		}
	}
}

func maskProviderSecrets(config map[string]any) {
	if config == nil {
		return
	}
	secretKeys := []string{"bindPassword", "clientSecret", "bind_password", "client_secret"}
	for _, key := range secretKeys {
		if val, ok := config[key]; ok && strings.TrimSpace(fmt.Sprint(val)) != "" {
			config[key] = "********"
			config[key+"Set"] = true
		}
	}
	keys := make([]string, 0, len(config))
	for k := range config {
		keys = append(keys, k)
	}
	slices.Sort(keys)
}
