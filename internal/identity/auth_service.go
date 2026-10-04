package identity

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type userStore interface {
	FindByUsername(ctx context.Context, username string) (UserRecord, error)
	FindByUserID(ctx context.Context, userID string) (UserRecord, error)
	UpsertExternalUser(ctx context.Context, id LDAPIdentity) (UserRecord, error)
	UpsertOIDCUser(ctx context.Context, email, fullName, externalID string, role Role) (UserRecord, error)
	CreateSession(ctx context.Context, userID, refreshJTI string, expiresAt time.Time) error
	RotateSessionRefreshJTI(ctx context.Context, userID, oldJTI, newJTI string, newExpiry time.Time) error
	RevokeSessionByJTI(ctx context.Context, userID, jti string) error
	RevokeSessionByID(ctx context.Context, userID, sessionID string) error
	RevokeAllSessions(ctx context.Context, userID string) error
	ListSessions(ctx context.Context, userID string, limit int) ([]Session, error)
	UpdatePassword(ctx context.Context, userID, passwordHash string, clearMustChange bool) error
	SetTOTP(ctx context.Context, userID, secret string, enabled bool) error
}

type ProviderResolver func(ctx context.Context, providerID string) (ProviderType, *LDAPProvider, error)

type AuthService struct {
	repo       userStore
	tokens     *TokenIssuer
	ldap       *LDAPProvider
	allowLDAP  bool
	resolve    ProviderResolver
	mu         sync.RWMutex
	refreshTTL time.Duration
}

func NewAuthService(repo userStore, tokens *TokenIssuer, ldap *LDAPProvider, allowLDAP bool) *AuthService {
	ttl := 24 * time.Hour
	if tokens != nil {
		_, refresh := tokens.ttls()
		if refresh > 0 {
			ttl = refresh
		}
	}
	return &AuthService{
		repo:       repo,
		tokens:     tokens,
		ldap:       ldap,
		allowLDAP:  allowLDAP,
		refreshTTL: ttl,
	}
}

func (s *AuthService) SetProviderResolver(resolve ProviderResolver) {
	s.mu.Lock()
	s.resolve = resolve
	s.mu.Unlock()
}

func (s *AuthService) SetProcessLDAP(ldap *LDAPProvider, allow bool) {
	s.mu.Lock()
	s.ldap = ldap
	s.allowLDAP = allow
	s.mu.Unlock()
}

func (s *AuthService) SetRefreshTTL(ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	s.mu.Lock()
	s.refreshTTL = ttl
	s.mu.Unlock()
}

type LoginInput struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	ProviderID string `json:"provider_id"`
}

type LoginResult struct {
	User                  User
	Tokens                TokenPair
	Issued                bool
	RequirePasswordChange bool
	Requires2FA           bool
	Require2FASetup       bool
	UserID                string
	TempToken             string
}

func (s *AuthService) Login(ctx context.Context, in LoginInput, orgID int64) (LoginResult, error) {
	username := strings.TrimSpace(in.Username)
	password := in.Password
	if username == "" || password == "" {
		return LoginResult{}, ErrInvalidCredentials
	}
	providerID := strings.TrimSpace(in.ProviderID)
	if providerID != "" && !strings.EqualFold(providerID, "local") {
		s.mu.RLock()
		resolve := s.resolve
		s.mu.RUnlock()
		if resolve == nil {
			return LoginResult{}, ErrInvalidCredentials
		}
		kind, ldap, err := resolve(ctx, providerID)
		if err != nil {
			return LoginResult{}, ErrInvalidCredentials
		}
		switch kind {
		case ProviderTypeLocal:
			return s.loginLocal(ctx, username, password, orgID)
		case ProviderTypeLDAP:
			return s.loginLDAP(ctx, ldap, username, password, orgID)
		default:
			return LoginResult{}, ErrInvalidCredentials
		}
	}
	if strings.EqualFold(providerID, "local") {
		return s.loginLocal(ctx, username, password, orgID)
	}
	localUser, err := s.repo.FindByUsername(ctx, username)
	if err == nil && localUser.AuthProvider == "local" {
		if !localUser.Enabled || localUser.PasswordHash == "" || bcrypt.CompareHashAndPassword([]byte(localUser.PasswordHash), []byte(password)) != nil {
			return LoginResult{}, ErrInvalidCredentials
		}
		return s.issueForUser(ctx, localUser, orgID)
	}
	s.mu.RLock()
	allow := s.allowLDAP
	ldap := s.ldap
	s.mu.RUnlock()
	if allow && ldap != nil {
		return s.loginLDAP(ctx, ldap, username, password, orgID)
	}
	return LoginResult{}, ErrInvalidCredentials
}

func (s *AuthService) loginLocal(ctx context.Context, username, password string, orgID int64) (LoginResult, error) {
	localUser, err := s.repo.FindByUsername(ctx, username)
	if err != nil || localUser.AuthProvider != "local" || !localUser.Enabled || localUser.PasswordHash == "" {
		return LoginResult{}, ErrInvalidCredentials
	}
	if bcrypt.CompareHashAndPassword([]byte(localUser.PasswordHash), []byte(password)) != nil {
		return LoginResult{}, ErrInvalidCredentials
	}
	return s.issueForUser(ctx, localUser, orgID)
}

func (s *AuthService) loginLDAP(ctx context.Context, ldap *LDAPProvider, username, password string, orgID int64) (LoginResult, error) {
	if ldap == nil {
		return LoginResult{}, ErrInvalidCredentials
	}
	id, err := ldap.Authenticate(username, password)
	if err != nil {
		return LoginResult{}, ErrInvalidCredentials
	}
	user, err := s.repo.UpsertExternalUser(ctx, id)
	if err != nil {
		return LoginResult{}, err
	}
	return s.issueForUser(ctx, user, orgID)
}

func (s *AuthService) LoginOIDC(ctx context.Context, in OIDCIdentity, orgID int64) (LoginResult, error) {
	user, err := s.repo.UpsertOIDCUser(ctx, in.Email, in.FullName, in.Subject, in.Role)
	if err != nil {
		return LoginResult{}, err
	}
	return s.issueForUser(ctx, user, orgID)
}

func (s *AuthService) VerifyTOTP(ctx context.Context, userID, code string, orgID int64) (LoginResult, error) {
	user, err := s.repo.FindByUserID(ctx, strings.TrimSpace(userID))
	if err != nil || !user.Enabled || !user.TOTPEnabled {
		return LoginResult{}, ErrInvalidCredentials
	}
	if !ValidateTOTP(user.TOTPSecret, code, time.Now()) {
		return LoginResult{}, ErrInvalidCredentials
	}
	return s.issueTokens(ctx, user, orgID)
}

func (s *AuthService) ChangePasswordWithTempToken(ctx context.Context, tempToken, newPassword string, orgID int64) (LoginResult, error) {
	userID, err := s.tokens.VerifyPurpose(tempToken, "password_change")
	if err != nil {
		return LoginResult{}, ErrInvalidCredentials
	}
	if err := validatePassword(newPassword); err != nil {
		return LoginResult{}, err
	}
	hash, err := HashPassword(newPassword)
	if err != nil {
		return LoginResult{}, err
	}
	if err := s.repo.UpdatePassword(ctx, userID, hash, true); err != nil {
		return LoginResult{}, err
	}
	user, err := s.repo.FindByUserID(ctx, userID)
	if err != nil {
		return LoginResult{}, err
	}
	user.MustChangePassword = false
	if user.TOTPEnabled {
		return LoginResult{Requires2FA: true, UserID: user.ID}, nil
	}
	result, err := s.issueTokens(ctx, user, orgID)
	if err != nil {
		return LoginResult{}, err
	}
	result.Require2FASetup = true
	return result, nil
}

func (s *AuthService) ChangeOwnPassword(ctx context.Context, userID, current, next string) error {
	if err := validatePassword(next); err != nil {
		return err
	}
	user, err := s.repo.FindByUserID(ctx, userID)
	if err != nil || user.PasswordHash == "" || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(current)) != nil {
		return ErrInvalidCredentials
	}
	hash, err := HashPassword(next)
	if err != nil {
		return err
	}
	return s.repo.UpdatePassword(ctx, userID, hash, true)
}

func (s *AuthService) BeginTOTP(ctx context.Context, userID, account string) (string, string, error) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		return "", "", err
	}
	if err := s.repo.SetTOTP(ctx, userID, secret, false); err != nil {
		return "", "", err
	}
	return secret, TOTPAuthURL("Mail Warden", account, secret), nil
}

func (s *AuthService) EnableTOTP(ctx context.Context, userID, code string) error {
	user, err := s.repo.FindByUserID(ctx, userID)
	if err != nil || user.TOTPSecret == "" {
		return ErrInvalidCredentials
	}
	if !ValidateTOTP(user.TOTPSecret, code, time.Now()) {
		return ErrInvalidCredentials
	}
	return s.repo.SetTOTP(ctx, userID, user.TOTPSecret, true)
}

func (s *AuthService) DisableTOTP(ctx context.Context, userID, code string) error {
	user, err := s.repo.FindByUserID(ctx, userID)
	if err != nil || !user.TOTPEnabled {
		return ErrInvalidCredentials
	}
	if !ValidateTOTP(user.TOTPSecret, code, time.Now()) {
		return ErrInvalidCredentials
	}
	return s.repo.SetTOTP(ctx, userID, "", false)
}

func (s *AuthService) issueForUser(ctx context.Context, user UserRecord, orgID int64) (LoginResult, error) {
	if !user.Enabled {
		return LoginResult{}, ErrInvalidCredentials
	}
	if user.MustChangePassword && user.AuthProvider == "local" {
		token, err := s.tokens.IssuePurpose(user.ID, "password_change", 15*time.Minute)
		if err != nil {
			return LoginResult{}, err
		}
		return LoginResult{
			RequirePasswordChange: true,
			UserID:                user.ID,
			TempToken:             token,
		}, nil
	}
	if user.TOTPEnabled {
		return LoginResult{Requires2FA: true, UserID: user.ID}, nil
	}
	return s.issueTokens(ctx, user, orgID)
}

func (s *AuthService) issueTokens(ctx context.Context, user UserRecord, orgID int64) (LoginResult, error) {
	pair, err := s.tokens.Issue(Claims{
		UserID: user.ID,
		OrgID:  orgID,
		Role:   user.Role,
		Email:  user.Email,
	})
	if err != nil {
		return LoginResult{}, err
	}
	if err := s.repo.CreateSession(ctx, user.ID, pair.RefreshJTI, s.refreshExpiry()); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{
		User:   user.User,
		Tokens: pair,
		Issued: true,
	}, nil
}

func (s *AuthService) refreshExpiry() time.Time {
	s.mu.RLock()
	ttl := s.refreshTTL
	s.mu.RUnlock()
	return time.Now().UTC().Add(ttl)
}

func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (TokenPair, error) {
	rc, err := s.tokens.VerifyRefresh(refreshToken)
	if err != nil {
		return TokenPair{}, ErrInvalidCredentials
	}
	rec, err := s.repo.FindByUserID(ctx, rc.UserID)
	if err != nil || !rec.Enabled {
		return TokenPair{}, ErrInvalidCredentials
	}
	pair, err := s.tokens.Issue(Claims{
		UserID: rec.ID,
		OrgID:  rc.OrgID,
		Role:   rec.Role,
		Email:  rec.Email,
	})
	if err != nil {
		return TokenPair{}, err
	}
	if err := s.repo.RotateSessionRefreshJTI(ctx, rec.ID, rc.JTI, pair.RefreshJTI, s.refreshExpiry()); err != nil {
		return TokenPair{}, err
	}
	return pair, nil
}

func (s *AuthService) Logout(ctx context.Context, userID, jti string) error {
	if jti == "" {
		return nil
	}
	return s.repo.RevokeSessionByJTI(ctx, userID, jti)
}

func (s *AuthService) LogoutWithRefreshToken(ctx context.Context, userID, refreshToken string) error {
	rc, err := s.tokens.VerifyRefresh(refreshToken)
	if err != nil {
		return ErrInvalidCredentials
	}
	if rc.UserID != userID {
		return ErrInvalidCredentials
	}
	return s.Logout(ctx, userID, rc.JTI)
}

func (s *AuthService) LogoutAll(ctx context.Context, userID string) error {
	return s.repo.RevokeAllSessions(ctx, userID)
}

func (s *AuthService) RevokeSession(ctx context.Context, userID, sessionID string) error {
	return s.repo.RevokeSessionByID(ctx, userID, sessionID)
}

func (s *AuthService) ListSessions(ctx context.Context, userID string, limit int) ([]Session, error) {
	return s.repo.ListSessions(ctx, userID, limit)
}

func HashPassword(raw string) (string, error) {
	if err := validatePassword(raw); err != nil {
		return "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func validatePassword(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return errors.New("password cannot be empty")
	}
	if len(raw) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	return nil
}
