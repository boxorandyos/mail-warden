package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type OIDCConfig struct {
	Enabled      bool
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	EmailClaim   string
	NameClaim    string
	GroupsClaim  string
	DefaultRole  Role
	RoleMap      map[string]Role
}

type OIDCProvider struct {
	cfg      OIDCConfig
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth2   oauth2.Config
}

func NewOIDCProvider(ctx context.Context, cfg OIDCConfig) (*OIDCProvider, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.RedirectURL == "" {
		return nil, errors.New("oidc requires issuer, client_id, client_secret, redirect_url")
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("create oidc provider: %w", err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	oauthCfg := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.RedirectURL,
		Scopes:       cfg.Scopes,
	}
	return &OIDCProvider{
		cfg:      cfg,
		provider: provider,
		verifier: verifier,
		oauth2:   oauthCfg,
	}, nil
}

func (p *OIDCProvider) AuthCodeURL(state string) string {
	if state == "" {
		state = randomState()
	}
	return p.oauth2.AuthCodeURL(state)
}

type OIDCIdentity struct {
	Subject  string
	Email    string
	FullName string
	Groups   []string
	Role     Role
}

func (p *OIDCProvider) ExchangeCode(ctx context.Context, code string) (OIDCIdentity, error) {
	token, err := p.oauth2.Exchange(ctx, code)
	if err != nil {
		return OIDCIdentity{}, fmt.Errorf("oidc exchange code: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return OIDCIdentity{}, errors.New("missing id_token")
	}
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return OIDCIdentity{}, fmt.Errorf("verify id token: %w", err)
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return OIDCIdentity{}, fmt.Errorf("decode id token claims: %w", err)
	}
	email := strings.TrimSpace(toString(claims[p.cfg.EmailClaim]))
	if email == "" {
		email = strings.TrimSpace(toString(claims["email"]))
	}
	name := strings.TrimSpace(toString(claims[p.cfg.NameClaim]))
	if name == "" {
		name = email
	}
	subject := strings.TrimSpace(toString(claims["sub"]))
	groups := extractGroups(claims[p.cfg.GroupsClaim])
	role := MapGroupsToRole(groups, p.cfg.RoleMap, p.cfg.DefaultRole)

	return OIDCIdentity{
		Subject:  subject,
		Email:    email,
		FullName: name,
		Groups:   groups,
		Role:     role,
	}, nil
}

func randomState() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func extractGroups(v any) []string {
	switch vv := v.(type) {
	case []any:
		out := make([]string, 0, len(vv))
		for _, item := range vv {
			s := strings.TrimSpace(toString(item))
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return vv
	default:
		return nil
	}
}
