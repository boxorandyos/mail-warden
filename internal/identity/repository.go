package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

type UserRecord struct {
	User
	PasswordHash string
}

type Session struct {
	ID              string    `json:"id"`
	UserID          string    `json:"user_id"`
	RefreshTokenJTI string    `json:"refresh_token_jti"`
	ExpiresAt       time.Time `json:"expires_at"`
	RevokedAt       time.Time `json:"revoked_at,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

type Repository struct {
	pool           *pgxpool.Pool
	organizationID int64
}

func NewRepository(pool *pgxpool.Pool, organizationID int64) *Repository {
	return &Repository{pool: pool, organizationID: organizationID}
}

func (r *Repository) FindByUsername(ctx context.Context, username string) (UserRecord, error) {
	var rec UserRecord
	var role string
	err := r.pool.QueryRow(ctx, `
		SELECT id, username, email, full_name, role, auth_provider, COALESCE(external_id,''), enabled, COALESCE(password_hash,'')
		  FROM users
		 WHERE organization_id = $1
		   AND username = $2
	`, r.organizationID, username).
		Scan(&rec.ID, &rec.Username, &rec.Email, &rec.FullName, &role, &rec.AuthProvider, &rec.ExternalID, &rec.Enabled, &rec.PasswordHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return UserRecord{}, ErrInvalidCredentials
		}
		return UserRecord{}, fmt.Errorf("query user: %w", err)
	}
	parsedRole, err := ParseRole(role)
	if err != nil {
		return UserRecord{}, err
	}
	rec.Role = parsedRole
	return rec, nil
}

func (r *Repository) FindByUserID(ctx context.Context, userID string) (UserRecord, error) {
	var rec UserRecord
	var role string
	err := r.pool.QueryRow(ctx, `
		SELECT id, username, email, full_name, role, auth_provider, COALESCE(external_id,''), enabled, COALESCE(password_hash,'')
		  FROM users
		 WHERE organization_id = $1
		   AND id = $2
	`, r.organizationID, userID).
		Scan(&rec.ID, &rec.Username, &rec.Email, &rec.FullName, &role, &rec.AuthProvider, &rec.ExternalID, &rec.Enabled, &rec.PasswordHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return UserRecord{}, ErrInvalidCredentials
		}
		return UserRecord{}, fmt.Errorf("query user by id: %w", err)
	}
	parsedRole, err := ParseRole(role)
	if err != nil {
		return UserRecord{}, err
	}
	rec.Role = parsedRole
	return rec, nil
}

func (r *Repository) UpsertExternalUser(ctx context.Context, id LDAPIdentity) (UserRecord, error) {
	return r.upsertExternalUser(ctx, id.Username, id.Email, id.FullName, string(id.Role), "ldap", id.ExternalID)
}

func (r *Repository) UpsertOIDCUser(ctx context.Context, email, fullName, externalID string, role Role) (UserRecord, error) {
	username := email
	if username == "" {
		username = externalID
	}
	return r.upsertExternalUser(ctx, username, email, fullName, string(role), "oidc", externalID)
}

func (r *Repository) upsertExternalUser(ctx context.Context, username, email, fullName, role, provider, externalID string) (UserRecord, error) {
	if role == "" {
		role = string(RoleViewer)
	}
	var out UserRecord
	var roleRaw string
	err := r.pool.QueryRow(ctx, `
		INSERT INTO users (id, organization_id, username, email, full_name, role, auth_provider, external_id, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true)
		ON CONFLICT (organization_id, username)
		DO UPDATE SET
		    email = EXCLUDED.email,
		    full_name = EXCLUDED.full_name,
		    role = EXCLUDED.role,
		    external_id = EXCLUDED.external_id,
		    updated_at = NOW()
		RETURNING id, username, email, full_name, role, auth_provider, COALESCE(external_id,''), enabled
	`, uuid.NewString(), r.organizationID, username, email, fullName, role, provider, externalID).
		Scan(&out.ID, &out.Username, &out.Email, &out.FullName, &roleRaw, &out.AuthProvider, &out.ExternalID, &out.Enabled)
	if err != nil {
		return UserRecord{}, fmt.Errorf("upsert ldap user: %w", err)
	}
	parsedRole, err := ParseRole(roleRaw)
	if err != nil {
		return UserRecord{}, err
	}
	out.Role = parsedRole
	return out, nil
}

func (r *Repository) EnsureBootstrapAdmin(ctx context.Context, username, email, fullName, passwordHash string) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO users (id, organization_id, username, email, full_name, role, auth_provider, password_hash, enabled)
		VALUES ($1, $2, $3, $4, $5, 'admin', 'local', $6, true)
		ON CONFLICT (organization_id, username) DO NOTHING
	`, uuid.NewString(), r.organizationID, username, email, fullName, passwordHash)
	if err != nil {
		return fmt.Errorf("ensure bootstrap admin: %w", err)
	}
	return nil
}

func (r *Repository) CreateSession(ctx context.Context, userID, refreshJTI string, expiresAt time.Time) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO user_sessions (id, user_id, refresh_token_jti, expires_at)
		VALUES ($1, $2, $3, $4)
	`, uuid.NewString(), userID, refreshJTI, expiresAt)
	if err != nil {
		return fmt.Errorf("insert user session: %w", err)
	}
	return nil
}

func (r *Repository) RotateSessionRefreshJTI(ctx context.Context, userID, oldJTI, newJTI string, newExpiry time.Time) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE user_sessions
		   SET refresh_token_jti = $1,
		       expires_at = $2
		 WHERE user_id = $3
		   AND refresh_token_jti = $4
		   AND revoked_at IS NULL
	`, newJTI, newExpiry, userID, oldJTI)
	if err != nil {
		return fmt.Errorf("rotate session token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrInvalidCredentials
	}
	return nil
}

func (r *Repository) RevokeSessionByJTI(ctx context.Context, userID, jti string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE user_sessions
		   SET revoked_at = NOW()
		 WHERE user_id = $1
		   AND refresh_token_jti = $2
		   AND revoked_at IS NULL
	`, userID, jti)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

func (r *Repository) RevokeAllSessions(ctx context.Context, userID string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE user_sessions
		   SET revoked_at = NOW()
		 WHERE user_id = $1
		   AND revoked_at IS NULL
	`, userID)
	if err != nil {
		return fmt.Errorf("revoke all sessions: %w", err)
	}
	return nil
}

func (r *Repository) ListSessions(ctx context.Context, userID string, limit int) ([]Session, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id, user_id, refresh_token_jti, expires_at, COALESCE(revoked_at, '0001-01-01'::timestamptz), created_at
		  FROM user_sessions
		 WHERE user_id = $1
		 ORDER BY created_at DESC
		 LIMIT $2
	`, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("list sessions query: %w", err)
	}
	defer rows.Close()
	out := make([]Session, 0, limit)
	for rows.Next() {
		var s Session
		if err := rows.Scan(&s.ID, &s.UserID, &s.RefreshTokenJTI, &s.ExpiresAt, &s.RevokedAt, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		out = append(out, s)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("iterate sessions: %w", rows.Err())
	}
	return out, nil
}
