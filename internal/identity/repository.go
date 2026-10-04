package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

type UserRecord struct {
	User
	PasswordHash       string
	TOTPSecret         string
	MustChangePassword bool
}

const userSelect = `id, username, email, full_name, role, auth_provider, COALESCE(external_id,''), enabled, COALESCE(password_hash,''), COALESCE(totp_secret,''), totp_enabled, must_change_password, COALESCE(language,'en'), COALESCE(timezone,'UTC')`

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
	row := r.pool.QueryRow(ctx, `
		SELECT `+userSelect+`
		  FROM users
		 WHERE organization_id = $1
		   AND username = $2
	`, r.organizationID, username)
	rec, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return UserRecord{}, ErrInvalidCredentials
		}
		return UserRecord{}, fmt.Errorf("query user: %w", err)
	}
	return rec, nil
}

func (r *Repository) FindByUserID(ctx context.Context, userID string) (UserRecord, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT `+userSelect+`
		  FROM users
		 WHERE organization_id = $1
		   AND id = $2
	`, r.organizationID, userID)
	rec, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return UserRecord{}, ErrInvalidCredentials
		}
		return UserRecord{}, fmt.Errorf("query user by id: %w", err)
	}
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
	row := r.pool.QueryRow(ctx, `
		INSERT INTO users (id, organization_id, username, email, full_name, role, auth_provider, external_id, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true)
		ON CONFLICT (organization_id, username)
		DO UPDATE SET
		    email = EXCLUDED.email,
		    full_name = EXCLUDED.full_name,
		    role = EXCLUDED.role,
		    external_id = EXCLUDED.external_id,
		    updated_at = NOW()
		RETURNING `+userSelect+`
	`, uuid.NewString(), r.organizationID, username, email, fullName, role, provider, externalID)
	out, err := scanUser(row)
	if err != nil {
		return UserRecord{}, fmt.Errorf("upsert ldap user: %w", err)
	}
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

var ErrNotFound = errors.New("not found")

type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(row rowScanner) (UserRecord, error) {
	var rec UserRecord
	var role string
	err := row.Scan(
		&rec.ID, &rec.Username, &rec.Email, &rec.FullName, &role, &rec.AuthProvider, &rec.ExternalID, &rec.Enabled,
		&rec.PasswordHash, &rec.TOTPSecret, &rec.TOTPEnabled, &rec.MustChangePassword, &rec.Language, &rec.Timezone,
	)
	if err != nil {
		return UserRecord{}, err
	}
	parsed, err := ParseRole(role)
	if err != nil {
		return UserRecord{}, err
	}
	rec.Role = parsed
	if rec.Language == "" {
		rec.Language = "en"
	}
	if rec.Timezone == "" {
		rec.Timezone = "UTC"
	}
	return rec, nil
}

func (r *Repository) UpdatePassword(ctx context.Context, userID, passwordHash string, clearMustChange bool) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE users
		   SET password_hash = $3,
		       must_change_password = CASE WHEN $4 THEN false ELSE must_change_password END,
		       updated_at = NOW()
		 WHERE organization_id = $1 AND id = $2
	`, r.organizationID, userID, passwordHash, clearMustChange)
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *Repository) SetTOTP(ctx context.Context, userID, secret string, enabled bool) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE users
		   SET totp_secret = NULLIF($3, ''),
		       totp_enabled = $4,
		       updated_at = NOW()
		 WHERE organization_id = $1 AND id = $2
	`, r.organizationID, userID, secret, enabled)
	if err != nil {
		return fmt.Errorf("set totp: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *Repository) RevokeSessionByID(ctx context.Context, userID, sessionID string) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE user_sessions
		   SET revoked_at = NOW()
		 WHERE user_id = $1 AND id = $2 AND revoked_at IS NULL
	`, userID, sessionID)
	if err != nil {
		return fmt.Errorf("revoke session by id: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

type ProfileUpdate struct {
	Email    string
	FullName string
	Language string
	Timezone string
}

func (r *Repository) UpdateProfile(ctx context.Context, userID string, in ProfileUpdate) (UserRecord, error) {
	row := r.pool.QueryRow(ctx, `
		UPDATE users
		   SET email = $3,
		       full_name = $4,
		       language = $5,
		       timezone = $6,
		       updated_at = NOW()
		 WHERE organization_id = $1 AND id = $2
		RETURNING `+userSelect+`
	`, r.organizationID, userID, strings.TrimSpace(in.Email), strings.TrimSpace(in.FullName), strings.TrimSpace(in.Language), strings.TrimSpace(in.Timezone))
	rec, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return UserRecord{}, ErrNotFound
		}
		return UserRecord{}, fmt.Errorf("update profile: %w", err)
	}
	return rec, nil
}

type UserWrite struct {
	Username           string `json:"username"`
	Email              string `json:"email"`
	FullName           string `json:"full_name"`
	Role               Role   `json:"role"`
	Password           string `json:"password"`
	Enabled            *bool  `json:"enabled"`
	MustChangePassword *bool  `json:"must_change_password"`
}

func (r *Repository) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT `+userSelect+`
		  FROM users
		 WHERE organization_id = $1
		 ORDER BY username
	`, r.organizationID)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	out := make([]User, 0, 16)
	for rows.Next() {
		rec, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec.User)
	}
	return out, rows.Err()
}

func (r *Repository) CreateUser(ctx context.Context, in UserWrite) (User, error) {
	role, err := ParseRole(string(in.Role))
	if err != nil {
		return User{}, err
	}
	hash, err := HashPassword(in.Password)
	if err != nil {
		return User{}, err
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	mustChange := false
	if in.MustChangePassword != nil {
		mustChange = *in.MustChangePassword
	}
	row := r.pool.QueryRow(ctx, `
		INSERT INTO users (id, organization_id, username, email, full_name, role, auth_provider, password_hash, enabled, must_change_password, language, timezone)
		VALUES ($1, $2, $3, $4, $5, $6, 'local', $7, $8, $9, 'en', 'UTC')
		RETURNING `+userSelect+`
	`, uuid.NewString(), r.organizationID, strings.TrimSpace(in.Username), strings.TrimSpace(in.Email), strings.TrimSpace(in.FullName), string(role), hash, enabled, mustChange)
	rec, err := scanUser(row)
	if err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return rec.User, nil
}

func (r *Repository) UpdateUser(ctx context.Context, userID string, in UserWrite) (User, error) {
	current, err := r.FindByUserID(ctx, userID)
	if err != nil {
		return User{}, err
	}
	role := current.Role
	if strings.TrimSpace(string(in.Role)) != "" {
		role, err = ParseRole(string(in.Role))
		if err != nil {
			return User{}, err
		}
	}
	email := current.Email
	if strings.TrimSpace(in.Email) != "" {
		email = strings.TrimSpace(in.Email)
	}
	fullName := current.FullName
	if strings.TrimSpace(in.FullName) != "" {
		fullName = strings.TrimSpace(in.FullName)
	}
	enabled := current.Enabled
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	mustChange := current.MustChangePassword
	if in.MustChangePassword != nil {
		mustChange = *in.MustChangePassword
	}
	row := r.pool.QueryRow(ctx, `
		UPDATE users
		   SET email = $3,
		       full_name = $4,
		       role = $5,
		       enabled = $6,
		       must_change_password = $7,
		       updated_at = NOW()
		 WHERE organization_id = $1 AND id = $2
		RETURNING `+userSelect+`
	`, r.organizationID, userID, email, fullName, string(role), enabled, mustChange)
	rec, err := scanUser(row)
	if err != nil {
		return User{}, fmt.Errorf("update user: %w", err)
	}
	if strings.TrimSpace(in.Password) != "" {
		hash, err := HashPassword(in.Password)
		if err != nil {
			return User{}, err
		}
		if err := r.UpdatePassword(ctx, userID, hash, false); err != nil {
			return User{}, err
		}
	}
	return rec.User, nil
}

func (r *Repository) DeleteUser(ctx context.Context, userID string) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM users WHERE organization_id = $1 AND id = $2`, r.organizationID, userID)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
