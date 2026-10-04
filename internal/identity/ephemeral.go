package identity

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type EphemeralStore struct {
	pool *pgxpool.Pool
	mu   sync.Mutex
	mem  map[string]ephemeralItem
}

type ephemeralItem struct {
	payload   string
	expiresAt time.Time
}

func NewEphemeralStore(pool *pgxpool.Pool) *EphemeralStore {
	return &EphemeralStore{pool: pool, mem: map[string]ephemeralItem{}}
}

func (s *EphemeralStore) PutOIDC(ctx context.Context, state, providerID, returnTo string) error {
	if s.pool != nil {
		_, err := s.pool.Exec(ctx, `
			INSERT INTO oidc_login_states (state, provider_id, return_to)
			VALUES ($1, $2, $3)
			ON CONFLICT (state) DO UPDATE SET provider_id = EXCLUDED.provider_id, return_to = EXCLUDED.return_to, created_at = NOW()
		`, state, providerID, returnTo)
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mem["oidc:"+state] = ephemeralItem{payload: providerID + "\n" + returnTo, expiresAt: time.Now().Add(10 * time.Minute)}
	return nil
}

func (s *EphemeralStore) TakeOIDC(ctx context.Context, state string) (string, string, bool) {
	if s.pool != nil {
		var providerID, returnTo string
		err := s.pool.QueryRow(ctx, `
			DELETE FROM oidc_login_states
			 WHERE state = $1 AND created_at > NOW() - INTERVAL '10 minutes'
			RETURNING provider_id, return_to
		`, state).Scan(&providerID, &returnTo)
		if err != nil {
			return "", "", false
		}
		return providerID, returnTo, true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.mem["oidc:"+state]
	delete(s.mem, "oidc:"+state)
	if !ok || time.Now().After(item.expiresAt) {
		return "", "", false
	}
	providerID, returnTo, _ := stringsCut(item.payload, "\n")
	return providerID, returnTo, true
}

func (s *EphemeralStore) PutExchange(ctx context.Context, code, payload string) error {
	if s.pool != nil {
		_, err := s.pool.Exec(ctx, `
			INSERT INTO auth_exchange_codes (code, payload, expires_at)
			VALUES ($1, $2::jsonb, NOW() + INTERVAL '5 minutes')
		`, code, payload)
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mem["ex:"+code] = ephemeralItem{payload: payload, expiresAt: time.Now().Add(5 * time.Minute)}
	return nil
}

func (s *EphemeralStore) TakeExchange(ctx context.Context, code string) (string, bool) {
	if s.pool != nil {
		var payload string
		err := s.pool.QueryRow(ctx, `
			DELETE FROM auth_exchange_codes
			 WHERE code = $1 AND expires_at > NOW()
			RETURNING payload::text
		`, code).Scan(&payload)
		if err != nil {
			return "", false
		}
		return payload, true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.mem["ex:"+code]
	delete(s.mem, "ex:"+code)
	if !ok || time.Now().After(item.expiresAt) {
		return "", false
	}
	return item.payload, true
}

func stringsCut(s, sep string) (string, string, bool) {
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			return s[:i], s[i+len(sep):], true
		}
	}
	return s, "", false
}
