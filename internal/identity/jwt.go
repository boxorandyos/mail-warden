package identity

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type TokenIssuer struct {
	mu            sync.RWMutex
	accessSecret  []byte
	refreshSecret []byte
	accessTTL     time.Duration
	refreshTTL    time.Duration
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	SessionID    string `json:"session_id"`
	RefreshJTI   string `json:"refresh_jti"`
}

func NewTokenIssuer(accessSecret, refreshSecret string, accessTTL, refreshTTL time.Duration) (*TokenIssuer, error) {
	if accessSecret == "" || refreshSecret == "" {
		return nil, errors.New("token secrets are required")
	}
	if accessTTL <= 0 {
		accessTTL = 15 * time.Minute
	}
	if refreshTTL <= 0 {
		refreshTTL = 24 * time.Hour
	}
	return &TokenIssuer{
		accessSecret:  []byte(accessSecret),
		refreshSecret: []byte(refreshSecret),
		accessTTL:     accessTTL,
		refreshTTL:    refreshTTL,
	}, nil
}

func (t *TokenIssuer) SetTTL(access, refresh time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if access > 0 {
		t.accessTTL = access
	}
	if refresh > 0 {
		t.refreshTTL = refresh
	}
}

func (t *TokenIssuer) ttls() (time.Duration, time.Duration) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.accessTTL, t.refreshTTL
}

func (t *TokenIssuer) Issue(claims Claims) (TokenPair, error) {
	now := time.Now().UTC()
	sessionID := uuid.NewString()
	accessTTL, refreshTTL := t.ttls()

	accessClaims := jwt.MapClaims{
		"user_id": claims.UserID,
		"org_id":  claims.OrgID,
		"role":    string(claims.Role),
		"email":   claims.Email,
		"sid":     sessionID,
		"exp":     now.Add(accessTTL).Unix(),
		"iat":     now.Unix(),
	}
	access := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessToken, err := access.SignedString(t.accessSecret)
	if err != nil {
		return TokenPair{}, fmt.Errorf("sign access token: %w", err)
	}

	refreshClaims := jwt.MapClaims{
		"user_id": claims.UserID,
		"org_id":  claims.OrgID,
		"role":    string(claims.Role),
		"email":   claims.Email,
		"sid":     sessionID,
		"jti":     uuid.NewString(),
		"exp":     now.Add(refreshTTL).Unix(),
		"iat":     now.Unix(),
	}
	refresh := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshToken, err := refresh.SignedString(t.refreshSecret)
	if err != nil {
		return TokenPair{}, fmt.Errorf("sign refresh token: %w", err)
	}

	return TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		SessionID:    sessionID,
		RefreshJTI:   refreshClaims["jti"].(string),
	}, nil
}

func (t *TokenIssuer) VerifyAccess(token string) (Claims, error) {
	parsed, err := jwt.Parse(token, func(kk *jwt.Token) (any, error) {
		if kk.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("unexpected signing method")
		}
		return t.accessSecret, nil
	})
	if err != nil || !parsed.Valid {
		return Claims{}, errors.New("invalid token")
	}
	mc, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return Claims{}, errors.New("invalid token claims")
	}
	orgFloat, ok := mc["org_id"].(float64)
	if !ok {
		return Claims{}, errors.New("invalid org_id")
	}
	role, err := ParseRole(toString(mc["role"]))
	if err != nil {
		return Claims{}, err
	}
	return Claims{
		UserID: toString(mc["user_id"]),
		OrgID:  int64(orgFloat),
		Role:   role,
		Email:  toString(mc["email"]),
	}, nil
}

type RefreshClaims struct {
	Claims
	SessionID string
	JTI       string
	ExpiresAt time.Time
}

func (t *TokenIssuer) VerifyRefresh(token string) (RefreshClaims, error) {
	parsed, err := jwt.Parse(token, func(kk *jwt.Token) (any, error) {
		if kk.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("unexpected signing method")
		}
		return t.refreshSecret, nil
	})
	if err != nil || !parsed.Valid {
		return RefreshClaims{}, errors.New("invalid refresh token")
	}
	mc, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return RefreshClaims{}, errors.New("invalid refresh claims")
	}
	orgFloat, ok := mc["org_id"].(float64)
	if !ok {
		return RefreshClaims{}, errors.New("invalid org_id")
	}
	role, err := ParseRole(toString(mc["role"]))
	if err != nil {
		return RefreshClaims{}, err
	}
	expFloat, ok := mc["exp"].(float64)
	if !ok {
		return RefreshClaims{}, errors.New("invalid exp")
	}
	return RefreshClaims{
		Claims: Claims{
			UserID: toString(mc["user_id"]),
			OrgID:  int64(orgFloat),
			Role:   role,
			Email:  toString(mc["email"]),
		},
		SessionID: toString(mc["sid"]),
		JTI:       toString(mc["jti"]),
		ExpiresAt: time.Unix(int64(expFloat), 0).UTC(),
	}, nil
}

func (t *TokenIssuer) IssuePurpose(userID, purpose string, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"user_id": userID,
		"purpose": purpose,
		"jti":     uuid.NewString(),
		"exp":     now.Add(ttl).Unix(),
		"iat":     now.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(t.accessSecret)
	if err != nil {
		return "", fmt.Errorf("sign purpose token: %w", err)
	}
	return signed, nil
}

func (t *TokenIssuer) VerifyPurpose(token, purpose string) (string, error) {
	parsed, err := jwt.Parse(token, func(kk *jwt.Token) (any, error) {
		if kk.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("unexpected signing method")
		}
		return t.accessSecret, nil
	})
	if err != nil || !parsed.Valid {
		return "", errors.New("invalid token")
	}
	mc, ok := parsed.Claims.(jwt.MapClaims)
	if !ok || toString(mc["purpose"]) != purpose {
		return "", errors.New("invalid token")
	}
	userID := toString(mc["user_id"])
	if userID == "" {
		return "", errors.New("invalid token")
	}
	return userID, nil
}

func toString(v any) string {
	switch vv := v.(type) {
	case string:
		return vv
	default:
		return fmt.Sprint(v)
	}
}
