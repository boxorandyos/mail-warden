package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/boxorandyos/mail-warden/internal/config"
	"github.com/boxorandyos/mail-warden/internal/database"
	"github.com/boxorandyos/mail-warden/internal/events"
	"github.com/boxorandyos/mail-warden/internal/identity"
	"github.com/boxorandyos/mail-warden/internal/policy"
	"github.com/boxorandyos/mail-warden/internal/quarantine"
	"github.com/boxorandyos/mail-warden/internal/rspamd"
	"github.com/boxorandyos/mail-warden/internal/scoring"
	"github.com/boxorandyos/mail-warden/internal/security"
	"github.com/boxorandyos/mail-warden/internal/siem"
	"github.com/boxorandyos/mail-warden/internal/smtp"
)

type finishAPI struct {
	orgID       int64
	configPath  string
	auth        *identity.AuthService
	users       *identity.Repository
	providers   *identity.ProvidersRepository
	quarantine  quarantine.Repository
	db          *database.Postgres
	events      *events.Repository
	siem        *siem.Forwarder
	ephemeral   *identity.EphemeralStore
	hold        smtp.HoldReleaser
	serviceMu   *sync.RWMutex
	service     *config.ServiceConfig
	policyMu    *sync.RWMutex
	policyCfg   *config.PolicyConfig
	engine      **policy.Engine
	oidc        **identity.OIDCProvider
	rspamd      **rspamd.Client
	sandbox     **security.SandboxClient
	forwarder   **siem.Forwarder
	processLDAP func(config.ServiceConfig) *identity.LDAPProvider
	rebuildOIDC func(context.Context, config.ServiceConfig) *identity.OIDCProvider
}

func (a *finishAPI) readService() config.ServiceConfig {
	a.serviceMu.RLock()
	defer a.serviceMu.RUnlock()
	return *a.service
}

func (a *finishAPI) currentEngine() *policy.Engine {
	a.policyMu.RLock()
	defer a.policyMu.RUnlock()
	return *a.engine
}

func writeAuthResult(w http.ResponseWriter, result identity.LoginResult) {
	if result.RequirePasswordChange {
		_ = policy.WriteHTTPJSON(w, http.StatusOK, map[string]any{
			"require_password_change": true,
			"user_id":                 result.UserID,
			"temp_token":              result.TempToken,
		})
		return
	}
	if result.Requires2FA && !result.Issued {
		_ = policy.WriteHTTPJSON(w, http.StatusOK, map[string]any{
			"requires_2fa": true,
			"user_id":      result.UserID,
		})
		return
	}
	body := map[string]any{
		"user":   result.User,
		"tokens": result.Tokens,
	}
	if result.Require2FASetup {
		body["require_2fa_setup"] = true
	}
	_ = policy.WriteHTTPJSON(w, http.StatusOK, body)
}

func safeReturnPath(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.Contains(value, "://") {
		return "/dashboard"
	}
	return value
}

func randomToken() string {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func originAllowed(origin string, allowed []string) bool {
	origin = strings.TrimRight(strings.TrimSpace(origin), "/")
	if origin == "" {
		return false
	}
	for _, item := range allowed {
		if strings.TrimRight(strings.TrimSpace(item), "/") == origin {
			return true
		}
	}
	return false
}

func (a *finishAPI) portalOrigins() []string {
	cfg := a.readService()
	if len(cfg.Portal.Origins) == 0 {
		return []string{"http://localhost:5173", "http://127.0.0.1:5173"}
	}
	return cfg.Portal.Origins
}

func (a *finishAPI) loginProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	type item struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Type    string `json:"type"`
		Enabled bool   `json:"enabled"`
	}
	out := make([]item, 0, 4)
	hasLocal := false
	hasLDAP := false
	if a.providers != nil {
		list, err := a.providers.List(r.Context())
		if err != nil {
			writeInternalServerError(w, "list login providers", err)
			return
		}
		for _, provider := range list {
			if !provider.Enabled {
				continue
			}
			out = append(out, item{ID: provider.ID, Name: provider.Name, Type: string(provider.Type), Enabled: true})
			if provider.Type == identity.ProviderTypeLocal {
				hasLocal = true
			}
			if provider.Type == identity.ProviderTypeLDAP {
				hasLDAP = true
			}
		}
	}
	if !hasLocal {
		out = append([]item{{ID: "local", Name: "Local", Type: "local", Enabled: true}}, out...)
	}
	cfg := a.readService()
	if cfg.LDAP.Enabled && !hasLDAP {
		out = append(out, item{ID: "ldap", Name: "LDAP", Type: "ldap", Enabled: true})
	}
	_ = policy.WriteHTTPJSON(w, http.StatusOK, out)
}

func (a *finishAPI) resolveProvider(ctx context.Context, providerID string) (identity.ProviderType, *identity.LDAPProvider, error) {
	if providerID == "ldap" {
		cfg := a.readService()
		if !cfg.LDAP.Enabled || a.processLDAP == nil {
			return "", nil, identity.ErrInvalidCredentials
		}
		provider := a.processLDAP(cfg)
		if provider == nil {
			return "", nil, identity.ErrInvalidCredentials
		}
		return identity.ProviderTypeLDAP, provider, nil
	}
	if a.providers == nil {
		return "", nil, identity.ErrInvalidCredentials
	}
	item, err := a.providers.Get(ctx, providerID)
	if err != nil || !item.Enabled {
		return "", nil, identity.ErrInvalidCredentials
	}
	switch item.Type {
	case identity.ProviderTypeLocal:
		return identity.ProviderTypeLocal, nil, nil
	case identity.ProviderTypeLDAP:
		provider, err := identity.LDAPProviderFromMap(item.Config)
		if err != nil {
			return "", nil, err
		}
		return identity.ProviderTypeLDAP, provider, nil
	default:
		return "", nil, identity.ErrInvalidCredentials
	}
}

func (a *finishAPI) verify2FA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || a.auth == nil {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		UserID string `json:"user_id"`
		Code   string `json:"code"`
	}
	if !decodeJSONBody(w, r, maxJSONBodyBytes, &req) {
		return
	}
	result, err := a.auth.VerifyTOTP(r.Context(), req.UserID, req.Code, a.orgID)
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	writeAuthResult(w, result)
}

func (a *finishAPI) changeFirstPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || a.auth == nil {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		TempToken   string `json:"temp_token"`
		NewPassword string `json:"new_password"`
	}
	if !decodeJSONBody(w, r, maxJSONBodyBytes, &req) {
		return
	}
	result, err := a.auth.ChangePasswordWithTempToken(r.Context(), req.TempToken, req.NewPassword, a.orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeAuthResult(w, result)
}

func (a *finishAPI) oidcExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || a.ephemeral == nil {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if !decodeJSONBody(w, r, maxJSONBodyBytes, &req) || strings.TrimSpace(req.Code) == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}
	payload, ok := a.ephemeral.TakeExchange(r.Context(), strings.TrimSpace(req.Code))
	if !ok {
		http.Error(w, "invalid code", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(payload))
}

func (a *finishAPI) startOIDC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	providerID := strings.TrimSpace(r.URL.Query().Get("provider_id"))
	returnTo := safeReturnPath(r.URL.Query().Get("return_to"))
	oidcProvider, err := a.oidcFor(r.Context(), providerID)
	if err != nil || oidcProvider == nil {
		http.Error(w, "oidc provider unavailable", http.StatusBadRequest)
		return
	}
	state := randomToken()
	if err := a.ephemeral.PutOIDC(r.Context(), state, providerID, returnTo); err != nil {
		writeInternalServerError(w, "store oidc state", err)
		return
	}
	http.Redirect(w, r, oidcProvider.AuthCodeURL(state), http.StatusFound)
}

func (a *finishAPI) oidcFor(ctx context.Context, providerID string) (*identity.OIDCProvider, error) {
	if providerID == "" && a.oidc != nil && *a.oidc != nil {
		return *a.oidc, nil
	}
	if a.providers == nil || providerID == "" {
		if a.oidc != nil {
			return *a.oidc, nil
		}
		return nil, errors.New("oidc unavailable")
	}
	item, err := a.providers.Get(ctx, providerID)
	if err != nil || !item.Enabled || item.Type != identity.ProviderTypeOIDC {
		return nil, identity.ErrInvalidCredentials
	}
	cfg := a.readService()
	oidcCfg, err := identity.OIDCConfigFromMap(item.Config, cfg.Auth.OIDC.RedirectURL)
	if err != nil {
		return nil, err
	}
	return identity.NewOIDCProvider(ctx, oidcCfg)
}

func (a *finishAPI) finishOIDC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || a.auth == nil || a.ephemeral == nil {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	providerID, returnTo, ok := a.ephemeral.TakeOIDC(r.Context(), state)
	if !ok || code == "" {
		a.redirectLoginError(w, r, "invalid oidc state")
		return
	}
	oidcProvider, err := a.oidcFor(r.Context(), providerID)
	if err != nil || oidcProvider == nil {
		a.redirectLoginError(w, r, "oidc provider unavailable")
		return
	}
	idn, err := oidcProvider.ExchangeCode(r.Context(), code)
	if err != nil {
		a.redirectLoginError(w, r, "oidc exchange failed")
		return
	}
	result, err := a.auth.LoginOIDC(r.Context(), idn, a.orgID)
	if err != nil {
		a.redirectLoginError(w, r, "oidc login failed")
		return
	}
	payload := authResultJSON(result)
	exchange := randomToken()
	if err := a.ephemeral.PutExchange(r.Context(), exchange, string(payload)); err != nil {
		a.redirectLoginError(w, r, "unable to finish login")
		return
	}
	cfg := a.readService()
	target := strings.TrimRight(cfg.Portal.PublicURL, "/") + "/login?code=" + url.QueryEscape(exchange) + "&redirect=" + url.QueryEscape(safeReturnPath(returnTo))
	http.Redirect(w, r, target, http.StatusFound)
}

func (a *finishAPI) redirectLoginError(w http.ResponseWriter, r *http.Request, msg string) {
	cfg := a.readService()
	target := strings.TrimRight(cfg.Portal.PublicURL, "/") + "/login?error=" + url.QueryEscape(msg)
	http.Redirect(w, r, target, http.StatusFound)
}

func authResultJSON(result identity.LoginResult) []byte {
	var body any
	switch {
	case result.RequirePasswordChange:
		body = map[string]any{"require_password_change": true, "user_id": result.UserID, "temp_token": result.TempToken}
	case result.Requires2FA && !result.Issued:
		body = map[string]any{"requires_2fa": true, "user_id": result.UserID}
	default:
		payload := map[string]any{"user": result.User, "tokens": result.Tokens}
		if result.Require2FASetup {
			payload["require_2fa_setup"] = true
		}
		body = payload
	}
	raw, _ := json.Marshal(body)
	return raw
}

func (a *finishAPI) revokeSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete || a.auth == nil {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	claims, _ := identity.ClaimsFromContext(r.Context())
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/auth/sessions/"), "/")
	if id == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	if err := a.auth.RevokeSession(r.Context(), claims.UserID, id); err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			http.Error(w, "session not found", http.StatusNotFound)
			return
		}
		writeInternalServerError(w, "revoke session", err)
		return
	}
	_ = policy.WriteHTTPJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *finishAPI) profile(w http.ResponseWriter, r *http.Request) {
	if a.users == nil {
		http.Error(w, "account unavailable", http.StatusServiceUnavailable)
		return
	}
	claims, _ := identity.ClaimsFromContext(r.Context())
	switch r.Method {
	case http.MethodGet:
		user, err := a.users.FindByUserID(r.Context(), claims.UserID)
		if err != nil {
			http.Error(w, "account not found", http.StatusNotFound)
			return
		}
		_ = policy.WriteHTTPJSON(w, http.StatusOK, user.User)
	case http.MethodPut:
		var req struct {
			Email    string `json:"email"`
			FullName string `json:"full_name"`
			Language string `json:"language"`
			Timezone string `json:"timezone"`
		}
		if !decodeJSONBody(w, r, maxJSONBodyBytes, &req) {
			return
		}
		if !validLanguage(req.Language) {
			http.Error(w, "invalid language", http.StatusBadRequest)
			return
		}
		user, err := a.users.UpdateProfile(r.Context(), claims.UserID, identity.ProfileUpdate{
			Email: req.Email, FullName: req.FullName, Language: req.Language, Timezone: req.Timezone,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = policy.WriteHTTPJSON(w, http.StatusOK, user.User)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func validLanguage(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 16 {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && r != '-' {
			return false
		}
	}
	return true
}

func (a *finishAPI) accountPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || a.auth == nil {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	claims, _ := identity.ClaimsFromContext(r.Context())
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decodeJSONBody(w, r, maxJSONBodyBytes, &req) {
		return
	}
	if err := a.auth.ChangeOwnPassword(r.Context(), claims.UserID, req.CurrentPassword, req.NewPassword); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_ = policy.WriteHTTPJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *finishAPI) account2FA(w http.ResponseWriter, r *http.Request) {
	if a.auth == nil || a.users == nil {
		http.Error(w, "account unavailable", http.StatusServiceUnavailable)
		return
	}
	claims, _ := identity.ClaimsFromContext(r.Context())
	switch {
	case r.URL.Path == "/api/v1/account/2fa" && r.Method == http.MethodGet:
		user, err := a.users.FindByUserID(r.Context(), claims.UserID)
		if err != nil {
			http.Error(w, "account not found", http.StatusNotFound)
			return
		}
		_ = policy.WriteHTTPJSON(w, http.StatusOK, map[string]bool{"enabled": user.TOTPEnabled})
	case r.URL.Path == "/api/v1/account/2fa/setup" && r.Method == http.MethodPost:
		user, err := a.users.FindByUserID(r.Context(), claims.UserID)
		if err != nil {
			http.Error(w, "account not found", http.StatusNotFound)
			return
		}
		secret, otpauth, err := a.auth.BeginTOTP(r.Context(), claims.UserID, user.Email)
		if err != nil {
			writeInternalServerError(w, "totp setup", err)
			return
		}
		_ = policy.WriteHTTPJSON(w, http.StatusOK, map[string]string{"secret": secret, "otpauth_url": otpauth})
	case r.URL.Path == "/api/v1/account/2fa/enable" && r.Method == http.MethodPost:
		var req struct {
			Code string `json:"code"`
		}
		if !decodeJSONBody(w, r, maxJSONBodyBytes, &req) {
			return
		}
		if err := a.auth.EnableTOTP(r.Context(), claims.UserID, req.Code); err != nil {
			http.Error(w, "invalid code", http.StatusBadRequest)
			return
		}
		_ = policy.WriteHTTPJSON(w, http.StatusOK, map[string]bool{"enabled": true})
	case r.URL.Path == "/api/v1/account/2fa/disable" && r.Method == http.MethodPost:
		var req struct {
			Code string `json:"code"`
		}
		if !decodeJSONBody(w, r, maxJSONBodyBytes, &req) {
			return
		}
		if err := a.auth.DisableTOTP(r.Context(), claims.UserID, req.Code); err != nil {
			http.Error(w, "invalid code", http.StatusBadRequest)
			return
		}
		_ = policy.WriteHTTPJSON(w, http.StatusOK, map[string]bool{"enabled": false})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *finishAPI) handleUsers(w http.ResponseWriter, r *http.Request) {
	if a.users == nil {
		http.Error(w, "user repository unavailable", http.StatusServiceUnavailable)
		return
	}
	claims, _ := identity.ClaimsFromContext(r.Context())
	if r.URL.Path == "/api/v1/users" {
		switch r.Method {
		case http.MethodGet:
			items, err := a.users.ListUsers(r.Context())
			if err != nil {
				writeInternalServerError(w, "list users", err)
				return
			}
			_ = policy.WriteHTTPJSON(w, http.StatusOK, items)
		case http.MethodPost:
			var req identity.UserWrite
			if !decodeJSONBody(w, r, maxJSONBodyBytes, &req) {
				return
			}
			item, err := a.users.CreateUser(r.Context(), req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if a.events != nil {
				_ = a.events.AddAuditEvent(r.Context(), a.orgID, claims.UserID, "user_created", "user", item.ID, map[string]any{"role": item.Role})
			}
			_ = policy.WriteHTTPJSON(w, http.StatusCreated, item)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/users/"), "/")
	if id == "" {
		http.Error(w, "missing user id", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var req identity.UserWrite
		if !decodeJSONBody(w, r, maxJSONBodyBytes, &req) {
			return
		}
		item, err := a.users.UpdateUser(r.Context(), id, req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = policy.WriteHTTPJSON(w, http.StatusOK, item)
	case http.MethodDelete:
		if id == claims.UserID {
			http.Error(w, "you cannot delete your own account", http.StatusBadRequest)
			return
		}
		if err := a.users.DeleteUser(r.Context(), id); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if a.events != nil {
			_ = a.events.AddAuditEvent(r.Context(), a.orgID, claims.UserID, "user_deleted", "user", id, nil)
		}
		_ = policy.WriteHTTPJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *finishAPI) audit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || a.events == nil {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	items, err := a.events.ListAuditEvents(r.Context(), a.orgID, 200)
	if err != nil {
		writeInternalServerError(w, "list audit", err)
		return
	}
	_ = policy.WriteHTTPJSON(w, http.StatusOK, items)
}

func (a *finishAPI) serviceConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		_ = policy.WriteHTTPJSON(w, http.StatusOK, a.readService().PublicView())
	case http.MethodPut:
		var put config.ServicePut
		if !decodeJSONBody(w, r, maxJSONBodyBytes, &put) {
			return
		}
		a.serviceMu.Lock()
		next, restart := config.MergeServicePut(*a.service, put)
		if err := next.ValidateRuntimeSafety(); err != nil {
			a.serviceMu.Unlock()
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		*a.service = next
		a.serviceMu.Unlock()
		a.applyLive(r.Context(), next)
		if a.configPath != "" {
			if err := config.SaveServiceConfig(a.configPath, next); err != nil {
				log.Printf("persist service config: %v", err)
			}
		}
		if a.db != nil {
			claims, _ := identity.ClaimsFromContext(r.Context())
			_, _ = a.db.SaveConfigSnapshot(r.Context(), a.orgID, "service", next.PublicView(), claims.UserID)
		}
		_ = policy.WriteHTTPJSON(w, http.StatusOK, map[string]any{
			"config":           next.PublicView(),
			"restart_required": len(restart) > 0,
			"restart_fields":   restart,
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *finishAPI) applyLive(ctx context.Context, cfg config.ServiceConfig) {
	if a.rspamd != nil {
		var client *rspamd.Client
		if cfg.Rspamd.Endpoint != "" {
			client = rspamd.NewClient(cfg.Rspamd.Endpoint, cfg.Rspamd.TimeoutSeconds)
		}
		*a.rspamd = client
	}
	if a.sandbox != nil {
		*a.sandbox = security.NewSandboxClient(cfg.Sandbox.Enabled, cfg.Sandbox.Endpoint, cfg.Sandbox.APIKey, cfg.Sandbox.TimeoutSeconds)
	}
	if a.forwarder != nil {
		*a.forwarder = siem.NewForwarder(cfg.SIEM.Enabled, cfg.SIEM.WebhookURL, cfg.SIEM.BearerToken, cfg.SIEM.TimeoutSeconds)
	}
	if a.auth != nil {
		var ldap *identity.LDAPProvider
		if a.processLDAP != nil {
			ldap = a.processLDAP(cfg)
		}
		a.auth.SetProcessLDAP(ldap, ldap != nil)
		a.auth.SetRefreshTTL(time.Duration(cfg.Auth.RefreshTTLHours) * time.Hour)
	}
	if a.oidc != nil && a.rebuildOIDC != nil {
		*a.oidc = a.rebuildOIDC(ctx, cfg)
	}
}

func (a *finishAPI) putPolicy(w http.ResponseWriter, r *http.Request) {
	if a.db == nil {
		http.Error(w, "policy repository unavailable", http.StatusServiceUnavailable)
		return
	}
	var next config.PolicyConfig
	if !decodeJSONBody(w, r, maxJSONBodyBytes, &next) {
		return
	}
	if next.HardBlocks == nil {
		next.HardBlocks = []string{}
	}
	if next.Caps == nil {
		next.Caps = map[string]config.SignalCap{}
	}
	if err := config.ValidatePolicy(next); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	claims, _ := identity.ClaimsFromContext(r.Context())
	version, err := a.db.SavePolicyVersion(r.Context(), a.orgID, "edit-"+time.Now().UTC().Format("20060102T150405Z"), next, claims.UserID)
	if err != nil {
		writeInternalServerError(w, "save policy version", err)
		return
	}
	a.policyMu.Lock()
	*a.policyCfg = next
	*a.engine = policy.NewEngine(policy.EngineConfigFrom(next))
	a.policyMu.Unlock()
	if a.events != nil {
		_ = a.events.AddAuditEvent(r.Context(), a.orgID, claims.UserID, "policy_updated", "policy", strconv.FormatInt(version.ID, 10), nil)
	}
	_ = policy.WriteHTTPJSON(w, http.StatusOK, map[string]any{
		"policy":  next,
		"version": version,
	})
}

func (a *finishAPI) applySnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || a.db == nil {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid snapshot id", http.StatusBadRequest)
		return
	}
	snap, err := a.db.GetConfigSnapshot(r.Context(), a.orgID, id)
	if err != nil {
		http.Error(w, "snapshot not found", http.StatusNotFound)
		return
	}
	switch {
	case strings.Contains(snap.SnapshotType, "policy"):
		var next config.PolicyConfig
		if err := json.Unmarshal(snap.ConfigJSON, &next); err != nil {
			http.Error(w, "snapshot is not a policy document", http.StatusBadRequest)
			return
		}
		if err := config.ValidatePolicy(next); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		a.policyMu.Lock()
		*a.policyCfg = next
		*a.engine = policy.NewEngine(policy.EngineConfigFrom(next))
		a.policyMu.Unlock()
		_ = policy.WriteHTTPJSON(w, http.StatusOK, map[string]any{
			"applied":        snap.SnapshotType,
			"disk_unchanged": true,
			"note":           "The live policy engine was updated. The on-disk policy YAML file was not rewritten.",
		})
	default:
		var put config.ServicePut
		if err := json.Unmarshal(snap.ConfigJSON, &put); err != nil {
			http.Error(w, "snapshot is not a service configuration", http.StatusBadRequest)
			return
		}
		r.Body = http.NoBody
		a.serviceMu.Lock()
		next, restart := config.MergeServicePut(*a.service, put)
		*a.service = next
		a.serviceMu.Unlock()
		a.applyLive(r.Context(), next)
		if a.configPath != "" {
			_ = config.SaveServiceConfig(a.configPath, next)
		}
		_ = policy.WriteHTTPJSON(w, http.StatusOK, map[string]any{
			"applied":          "service",
			"restart_required": len(restart) > 0,
			"restart_fields":   restart,
			"config":           next.PublicView(),
		})
	}
}

func (a *finishAPI) messageDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || a.db == nil {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	idText := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/messages/"), "/")
	id, err := strconv.ParseInt(idText, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid message id", http.StatusBadRequest)
		return
	}
	msg, err := a.db.GetMessage(r.Context(), a.orgID, id)
	if err != nil {
		http.Error(w, "message not found", http.StatusNotFound)
		return
	}
	claims, _ := identity.ClaimsFromContext(r.Context())
	if !identity.CanScopeAll(claims.Role) && !identity.OwnsMail(claims.Email, msg.Sender, msg.Recipients) {
		http.Error(w, "message not found", http.StatusNotFound)
		return
	}
	authResult, _ := a.db.GetAuthenticationResult(r.Context(), id)
	urls, _ := a.db.ListURLObservations(r.Context(), id)
	attachments, _ := a.db.ListAttachmentObservations(r.Context(), id)
	_ = policy.WriteHTTPJSON(w, http.StatusOK, map[string]any{
		"message":        msg,
		"decision":       json.RawMessage(msg.Decision),
		"decision_input": json.RawMessage(msg.DecisionInput),
		"authentication": authResult,
		"urls":           urls,
		"attachments":    attachments,
	})
}

func (a *finishAPI) releaseQuarantine(w http.ResponseWriter, r *http.Request, id string) {
	claims, _ := identity.ClaimsFromContext(r.Context())
	mode := quarantine.ModeRescan
	if r.ContentLength != 0 || strings.Contains(r.Header.Get("Content-Type"), "json") {
		var req struct {
			Mode string `json:"mode"`
		}
		if !decodeJSONBody(w, r, maxJSONBodyBytes, &req) {
			return
		}
		if strings.TrimSpace(req.Mode) != "" {
			mode = strings.TrimSpace(req.Mode)
		}
	}
	msg, err := a.quarantine.Get(r.Context(), id)
	if err != nil {
		http.Error(w, "quarantine message not found", http.StatusNotFound)
		return
	}
	if !identity.CanScopeAll(claims.Role) && !identity.OwnsMail(claims.Email, msg.From, msg.To) {
		http.Error(w, "quarantine message not found", http.StatusNotFound)
		return
	}
	direction := msg.Direction
	if direction == "" {
		direction = msg.Decision.Direction
	}
	deliver, decision, err := quarantine.DecideRelease(mode, direction, msg.DecisionInput, func(dir string, input scoring.NormalizedDecisionObject) scoring.Decision {
		return a.currentEngine().EvaluateByDirection(dir, input)
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if !deliver {
		updated, err := a.quarantine.UpdateAfterRescan(r.Context(), id, decision, decision.Reason, false)
		if err != nil {
			writeInternalServerError(w, "update quarantine decision", err)
			return
		}
		_ = policy.WriteHTTPJSON(w, http.StatusOK, map[string]any{
			"released": false,
			"decision": decision,
			"message":  updated,
		})
		return
	}
	if strings.TrimSpace(msg.QueueID) == "" {
		http.Error(w, "queue id was not stored for this message", http.StatusConflict)
		return
	}
	if a.hold == nil {
		http.Error(w, "hold release is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := a.hold.ReleaseHold(r.Context(), msg.QueueID); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	updated, err := a.quarantine.UpdateAfterRescan(r.Context(), id, decision, decision.Reason, true)
	if err != nil {
		writeInternalServerError(w, "mark quarantine released", err)
		return
	}
	eventType := "quarantine_release"
	if strings.EqualFold(mode, quarantine.ModeBypass) {
		eventType = "quarantine_release_bypass"
	}
	if a.events != nil {
		_ = a.events.AddAuditEvent(r.Context(), a.orgID, claims.UserID, eventType, "quarantine_message", updated.ID, map[string]any{
			"mode":     mode,
			"queue_id": msg.QueueID,
		})
	}
	forwarder := a.siem
	if a.forwarder != nil && *a.forwarder != nil {
		forwarder = *a.forwarder
	}
	if forwarder != nil {
		_ = forwarder.Send(r.Context(), map[string]any{
			"type":        "audit",
			"event":       eventType,
			"actorUserId": claims.UserID,
			"messageId":   updated.ID,
			"ts":          time.Now().UTC().Format(time.RFC3339),
		})
	}
	_ = policy.WriteHTTPJSON(w, http.StatusOK, map[string]any{
		"released": true,
		"decision": decision,
		"message":  updated,
	})
}

func registerFinishRoutes(mux *http.ServeMux, a *finishAPI, authMW, viewerOnly, adminOnly func(http.Handler) http.Handler) {
	mux.HandleFunc("/api/v1/identity/login-providers", a.loginProviders)
	mux.HandleFunc("/api/v1/auth/verify-2fa", a.verify2FA)
	mux.HandleFunc("/api/v1/auth/first-login/change-password", a.changeFirstPassword)
	mux.HandleFunc("/api/v1/auth/oidc/exchange", a.oidcExchange)
	mux.Handle("/api/v1/auth/sessions/", withMiddleware(http.HandlerFunc(a.revokeSession), authMW, viewerOnly))
	mux.Handle("/api/v1/account/profile", withMiddleware(http.HandlerFunc(a.profile), authMW, viewerOnly))
	mux.Handle("/api/v1/account/password", withMiddleware(http.HandlerFunc(a.accountPassword), authMW, viewerOnly))
	mux.Handle("/api/v1/account/2fa", withMiddleware(http.HandlerFunc(a.account2FA), authMW, viewerOnly))
	mux.Handle("/api/v1/account/2fa/", withMiddleware(http.HandlerFunc(a.account2FA), authMW, viewerOnly))
	mux.Handle("/api/v1/users", withMiddleware(http.HandlerFunc(a.handleUsers), authMW, adminOnly))
	mux.Handle("/api/v1/users/", withMiddleware(http.HandlerFunc(a.handleUsers), authMW, adminOnly))
	mux.Handle("/api/v1/audit", withMiddleware(http.HandlerFunc(a.audit), authMW, adminOnly))
	mux.Handle("/api/v1/config/service", withMiddleware(http.HandlerFunc(a.serviceConfig), authMW, adminOnly))
	mux.Handle("/api/v1/config/snapshots/apply", withMiddleware(http.HandlerFunc(a.applySnapshot), authMW, adminOnly))
	mux.Handle("/api/v1/messages/", withMiddleware(http.HandlerFunc(a.messageDetail), authMW, viewerOnly))
}
