package identity

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLoginChallengesAndProvider(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := HashPassword("correct-horse")
	if err != nil {
		t.Fatal(err)
	}
	store := newMemoryUsers()
	store.put(UserRecord{
		User:         User{ID: "user-1", Username: "ada", Email: "ada@company.test", Role: RoleViewer, AuthProvider: "local", Enabled: true, TOTPEnabled: true},
		PasswordHash: hash,
		TOTPSecret:   secret,
	})
	tokens, err := NewTokenIssuer("access-secret-value", "refresh-secret-value", time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewAuthService(store, tokens, nil, false)

	result, err := svc.Login(ctx, LoginInput{Username: "ada", Password: "correct-horse", ProviderID: "local"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if result.Issued || !result.Requires2FA || result.UserID != "user-1" {
		t.Fatalf("expected totp challenge, got %+v", result)
	}

	svc.SetProviderResolver(func(context.Context, string) (ProviderType, *LDAPProvider, error) {
		return "", nil, errors.New("missing")
	})
	if _, err := svc.Login(ctx, LoginInput{Username: "ada", Password: "correct-horse", ProviderID: "missing"}, 1); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown provider should be rejected, got %v", err)
	}

	store.put(UserRecord{
		User:               User{ID: "user-2", Username: "new", Email: "new@company.test", Role: RoleViewer, AuthProvider: "local", Enabled: true},
		PasswordHash:       hash,
		MustChangePassword: true,
	})
	forced, err := svc.Login(ctx, LoginInput{Username: "new", Password: "correct-horse"}, 1)
	if err != nil || !forced.RequirePasswordChange || forced.TempToken == "" || forced.Issued {
		t.Fatalf("expected password change challenge, got %+v err=%v", forced, err)
	}
	changed, err := svc.ChangePasswordWithTempToken(ctx, forced.TempToken, "new-password-2", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !changed.Issued || !changed.Require2FASetup {
		t.Fatalf("expected tokens plus totp setup, got %+v", changed)
	}
}

type memoryUsers struct {
	byID   map[string]UserRecord
	byName map[string]string
}

func newMemoryUsers() *memoryUsers {
	return &memoryUsers{byID: map[string]UserRecord{}, byName: map[string]string{}}
}

func (m *memoryUsers) put(user UserRecord) {
	m.byID[user.ID] = user
	m.byName[user.Username] = user.ID
}

func (m *memoryUsers) FindByUsername(_ context.Context, username string) (UserRecord, error) {
	id, ok := m.byName[username]
	if !ok {
		return UserRecord{}, ErrInvalidCredentials
	}
	return m.byID[id], nil
}

func (m *memoryUsers) FindByUserID(_ context.Context, userID string) (UserRecord, error) {
	user, ok := m.byID[userID]
	if !ok {
		return UserRecord{}, ErrInvalidCredentials
	}
	return user, nil
}

func (m *memoryUsers) UpsertExternalUser(context.Context, LDAPIdentity) (UserRecord, error) {
	return UserRecord{}, errors.New("unused")
}

func (m *memoryUsers) UpsertOIDCUser(context.Context, string, string, string, Role) (UserRecord, error) {
	return UserRecord{}, errors.New("unused")
}

func (m *memoryUsers) CreateSession(context.Context, string, string, time.Time) error { return nil }
func (m *memoryUsers) RotateSessionRefreshJTI(context.Context, string, string, string, time.Time) error {
	return nil
}
func (m *memoryUsers) RevokeSessionByJTI(context.Context, string, string) error { return nil }
func (m *memoryUsers) RevokeSessionByID(context.Context, string, string) error  { return nil }
func (m *memoryUsers) RevokeAllSessions(context.Context, string) error          { return nil }
func (m *memoryUsers) ListSessions(context.Context, string, int) ([]Session, error) {
	return nil, nil
}
func (m *memoryUsers) UpdatePassword(_ context.Context, userID, passwordHash string, clearMustChange bool) error {
	user, ok := m.byID[userID]
	if !ok {
		return ErrNotFound
	}
	user.PasswordHash = passwordHash
	if clearMustChange {
		user.MustChangePassword = false
	}
	m.byID[userID] = user
	return nil
}
func (m *memoryUsers) SetTOTP(_ context.Context, userID, secret string, enabled bool) error {
	user, ok := m.byID[userID]
	if !ok {
		return ErrNotFound
	}
	user.TOTPSecret = secret
	user.TOTPEnabled = enabled
	m.byID[userID] = user
	return nil
}
