package identity

import (
	"context"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	repo       *Repository
	tokens     *TokenIssuer
	ldap       *LDAPProvider
	allowLDAP  bool
	refreshTTL time.Duration
}

func NewAuthService(repo *Repository, tokens *TokenIssuer, ldap *LDAPProvider, allowLDAP bool) *AuthService {
	return &AuthService{
		repo:       repo,
		tokens:     tokens,
		ldap:       ldap,
		allowLDAP:  allowLDAP,
		refreshTTL: 24 * time.Hour,
	}
}

type LoginInput struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResult struct {
	User   User      `json:"user"`
	Tokens TokenPair `json:"tokens"`
}

func (s *AuthService) Login(ctx context.Context, in LoginInput, orgID int64) (LoginResult, error) {
	username := strings.TrimSpace(in.Username)
	password := in.Password
	if username == "" || password == "" {
		return LoginResult{}, ErrInvalidCredentials
	}

	localUser, err := s.repo.FindByUsername(ctx, username)
	if err == nil && localUser.AuthProvider == "local" {
		if localUser.PasswordHash == "" || bcrypt.CompareHashAndPassword([]byte(localUser.PasswordHash), []byte(password)) != nil {
			return LoginResult{}, ErrInvalidCredentials
		}
		return s.issueForUser(ctx, localUser, orgID)
	}

	if s.allowLDAP && s.ldap != nil {
		id, err := s.ldap.Authenticate(username, password)
		if err != nil {
			return LoginResult{}, ErrInvalidCredentials
		}
		user, err := s.repo.UpsertExternalUser(ctx, id)
		if err != nil {
			return LoginResult{}, err
		}
		return s.issueForUser(ctx, user, orgID)
	}

	return LoginResult{}, ErrInvalidCredentials
}

func (s *AuthService) LoginOIDC(ctx context.Context, in OIDCIdentity, orgID int64) (LoginResult, error) {
	user, err := s.repo.UpsertOIDCUser(ctx, in.Email, in.FullName, in.Subject, in.Role)
	if err != nil {
		return LoginResult{}, err
	}
	return s.issueForUser(ctx, user, orgID)
}

func (s *AuthService) issueForUser(ctx context.Context, user UserRecord, orgID int64) (LoginResult, error) {
	pair, err := s.tokens.Issue(Claims{
		UserID: user.ID,
		OrgID:  orgID,
		Role:   user.Role,
		Email:  user.Email,
	})
	if err != nil {
		return LoginResult{}, err
	}
	if err := s.repo.CreateSession(ctx, user.ID, pair.RefreshJTI, time.Now().UTC().Add(s.refreshTTL)); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{
		User: user.User,
		Tokens: TokenPair{
			AccessToken:  pair.AccessToken,
			RefreshToken: pair.RefreshToken,
			SessionID:    pair.SessionID,
		},
	}, nil
}

func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (TokenPair, error) {
	rc, err := s.tokens.VerifyRefresh(refreshToken)
	if err != nil {
		return TokenPair{}, ErrInvalidCredentials
	}
	rec, err := s.repo.FindByUserID(ctx, rc.UserID)
	if err != nil {
		return TokenPair{}, err
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
	if err := s.repo.RotateSessionRefreshJTI(ctx, rec.ID, rc.JTI, pair.RefreshJTI, time.Now().UTC().Add(s.refreshTTL)); err != nil {
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

func (s *AuthService) ListSessions(ctx context.Context, userID string, limit int) ([]Session, error) {
	return s.repo.ListSessions(ctx, userID, limit)
}

func HashPassword(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", errors.New("password cannot be empty")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
