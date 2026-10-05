package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/boxorandyos/mail-warden/internal/config"
	"github.com/boxorandyos/mail-warden/internal/database"
	"github.com/boxorandyos/mail-warden/internal/dlp"
	"github.com/boxorandyos/mail-warden/internal/events"
	"github.com/boxorandyos/mail-warden/internal/exchange"
	"github.com/boxorandyos/mail-warden/internal/identity"
	"github.com/boxorandyos/mail-warden/internal/maintenance"
	"github.com/boxorandyos/mail-warden/internal/platform"
	"github.com/boxorandyos/mail-warden/internal/policy"
	"github.com/boxorandyos/mail-warden/internal/quarantine"
	"github.com/boxorandyos/mail-warden/internal/reputation"
	"github.com/boxorandyos/mail-warden/internal/rspamd"
	"github.com/boxorandyos/mail-warden/internal/scoring"
	"github.com/boxorandyos/mail-warden/internal/security"
	"github.com/boxorandyos/mail-warden/internal/siem"
	"github.com/boxorandyos/mail-warden/internal/smtp"
	"github.com/boxorandyos/mail-warden/internal/telemetry"
)

const (
	maxJSONBodyBytes       = 1 << 20  // 1 MiB
	maxPolicyEvalBodyBytes = 10 << 20 // 10 MiB (includes optional raw message payload)
)

var platformMetrics func() string

func main() {
	configPath := flag.String("config", "./configs/mailwarden.example.yaml", "path to service config")
	policyPath := flag.String("policy-config", "./configs/policy.example.yaml", "path to policy config")
	flag.Parse()

	serviceCfg, err := config.LoadServiceConfig(*configPath)
	if err != nil {
		log.Fatal(fmt.Errorf("load service config: %w", err))
	}
	currentPolicyCfg, err := config.LoadPolicyConfig(*policyPath)
	if err != nil {
		log.Fatal(fmt.Errorf("load policy config: %w", err))
	}

	ctx := context.Background()
	var policyMu sync.RWMutex
	var serviceMu sync.RWMutex
	var finish *finishAPI
	currentEngine := policy.NewEngine(policy.EngineConfigFrom(currentPolicyCfg))
	metrics := telemetry.NewTracker()
	authRateLimiter := newInMemoryLimiter(time.Minute, 30)

	var pg *database.Postgres
	if serviceCfg.Stores.PostgresDSN != "" {
		pg, err = database.NewPostgres(ctx, serviceCfg.Stores.PostgresDSN)
		if err != nil {
			log.Printf("postgres unavailable, continuing degraded: %v", err)
		}
	}
	defer func() {
		if pg != nil {
			pg.Close()
		}
	}()

	if pg != nil {
		if applied, err := pg.ApplyMigrations(ctx, "./migrations"); err != nil {
			log.Printf("postgres migrations failed: %v", err)
		} else {
			log.Printf("applied %d migration(s)", len(applied))
			_ = pg.EnsureBootstrapOrg(ctx, serviceCfg.Defaults.OrganizationID, serviceCfg.Defaults.Organization)
		}
	}

	var qRepo quarantine.Repository = quarantine.NewStore()
	var messageStore *database.Postgres
	var eventRepo *events.Repository
	var recipientValidator *exchange.RecipientValidator
	var idRepo *identity.Repository
	var providersRepo *identity.ProvidersRepository
	if pg != nil {
		qRepo = quarantine.NewPostgresStore(pg.Pool(), serviceCfg.Defaults.OrganizationID)
		messageStore = pg
		eventRepo = events.NewRepository(pg.Pool())
		recipientValidator = exchange.NewRecipientValidator(pg.Pool(), serviceCfg.Defaults.OrganizationID)
		idRepo = identity.NewRepository(pg.Pool(), serviceCfg.Defaults.OrganizationID)
		providersRepo = identity.NewProvidersRepository(pg.Pool(), serviceCfg.Defaults.OrganizationID)
	}

	var outboundCounters *reputation.OutboundCounters
	var recipientBehavior *reputation.RecipientBehaviorDetector
	if serviceCfg.Stores.RedisAddr != "" {
		outboundCounters = reputation.NewOutboundCounters(serviceCfg.Stores.RedisAddr)
		if err := outboundCounters.Ping(ctx); err != nil {
			log.Printf("redis unavailable: %v", err)
			_ = outboundCounters.Close()
			outboundCounters = nil
		} else {
			recipientBehavior = reputation.NewRecipientBehaviorDetector(serviceCfg.Stores.RedisAddr)
		}
	}
	defer func() {
		if outboundCounters != nil {
			_ = outboundCounters.Close()
		}
		if recipientBehavior != nil {
			_ = recipientBehavior.Close()
		}
	}()

	var rspamdClient *rspamd.Client
	if serviceCfg.Rspamd.Endpoint != "" {
		rspamdClient = rspamd.NewClient(serviceCfg.Rspamd.Endpoint, serviceCfg.Rspamd.TimeoutSeconds)
	}
	sandboxClient := security.NewSandboxClient(
		serviceCfg.Sandbox.Enabled,
		serviceCfg.Sandbox.Endpoint,
		serviceCfg.Sandbox.APIKey,
		serviceCfg.Sandbox.TimeoutSeconds,
	)
	siemForwarder := siem.NewForwarder(
		serviceCfg.SIEM.Enabled,
		serviceCfg.SIEM.WebhookURL,
		serviceCfg.SIEM.BearerToken,
		serviceCfg.SIEM.TimeoutSeconds,
	)

	accessSecret := serviceCfg.Auth.AccessSecret
	refreshSecret := serviceCfg.Auth.RefreshSecret
	if accessSecret == "" {
		if !serviceCfg.IsBootstrapMode() {
			log.Fatal("auth.access_secret is required outside bootstrap mode")
		}
		accessSecret = generateEphemeralSecret()
		log.Printf("auth.access_secret not set; generated ephemeral startup secret (bootstrap mode)")
	}
	if refreshSecret == "" {
		if !serviceCfg.IsBootstrapMode() {
			log.Fatal("auth.refresh_secret is required outside bootstrap mode")
		}
		refreshSecret = generateEphemeralSecret()
		log.Printf("auth.refresh_secret not set; generated ephemeral startup secret (bootstrap mode)")
	}
	tokenIssuer, err := identity.NewTokenIssuer(
		accessSecret,
		refreshSecret,
		time.Duration(serviceCfg.Auth.AccessTTLMinutes)*time.Minute,
		time.Duration(serviceCfg.Auth.RefreshTTLHours)*time.Hour,
	)
	if err != nil {
		log.Fatal(fmt.Errorf("build token issuer: %w", err))
	}

	var authService *identity.AuthService
	var oidcProvider *identity.OIDCProvider
	if idRepo != nil {
		if serviceCfg.Auth.BootstrapAdminPassword != "" {
			hash, err := identity.HashPassword(serviceCfg.Auth.BootstrapAdminPassword)
			if err != nil {
				log.Fatalf("hash bootstrap admin password: %v", err)
			}
			_ = idRepo.EnsureBootstrapAdmin(ctx, serviceCfg.Auth.BootstrapAdminUser, serviceCfg.Auth.BootstrapAdminEmail, serviceCfg.Auth.BootstrapAdminFullName, hash)
		}
		ldapProvider := buildLDAPProvider(serviceCfg)
		authService = identity.NewAuthService(idRepo, tokenIssuer, ldapProvider, ldapProvider != nil)

		if serviceCfg.Auth.OIDC.Enabled {
			scopes := strings.Fields(serviceCfg.Auth.OIDC.Scopes)
			if len(scopes) == 0 {
				scopes = []string{"openid", "profile", "email"}
			}
			oidcProvider, err = identity.NewOIDCProvider(ctx, identity.OIDCConfig{
				Enabled:      serviceCfg.Auth.OIDC.Enabled,
				Issuer:       serviceCfg.Auth.OIDC.Issuer,
				ClientID:     serviceCfg.Auth.OIDC.ClientID,
				ClientSecret: serviceCfg.Auth.OIDC.ClientSecret,
				RedirectURL:  serviceCfg.Auth.OIDC.RedirectURL,
				Scopes:       scopes,
				EmailClaim:   serviceCfg.Auth.OIDC.EmailClaim,
				NameClaim:    serviceCfg.Auth.OIDC.NameClaim,
				GroupsClaim:  serviceCfg.Auth.OIDC.GroupsClaim,
				DefaultRole:  identity.RoleViewer,
			})
			if err != nil {
				log.Printf("oidc disabled due to config error: %v", err)
				oidcProvider = nil
			}
		}
	}

	mux := http.NewServeMux()
	authMW := identity.AuthMiddleware(tokenIssuer)
	viewerOnly := identity.RequireRoles(identity.RoleViewer, identity.RoleModerator, identity.RoleAdmin)
	moderatorOnly := identity.RequireRoles(identity.RoleModerator, identity.RoleAdmin)
	adminOnly := identity.RequireRoles(identity.RoleAdmin)

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		ready := pg != nil && messageStore != nil && authService != nil
		status := http.StatusOK
		if !ready {
			status = http.StatusServiceUnavailable
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ready":             ready,
			"postgres":          pg != nil,
			"message_store":     messageStore != nil,
			"auth_service":      authService != nil,
			"rspamd_configured": rspamdClient != nil,
			"redis_configured":  outboundCounters != nil,
		})
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		body := metrics.PrometheusText()
		if platformMetrics != nil {
			body += platformMetrics()
		}
		_, _ = w.Write([]byte(body))
	})

	mux.HandleFunc("/api/v1/info", func(w http.ResponseWriter, _ *http.Request) {
		_ = policy.WriteHTTPJSON(w, http.StatusOK, map[string]any{
			"service_mode": serviceCfg.Service.Mode,
			"listen":       serviceCfg.Service.Listen,
			"smtp_policy":  serviceCfg.SMTP.PolicyListen,
		})
	})

	mux.HandleFunc("/api/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !enforceRateLimit(w, r, authRateLimiter, "auth_login") {
			return
		}
		if authService == nil {
			http.Error(w, "auth service unavailable", http.StatusServiceUnavailable)
			return
		}
		var in identity.LoginInput
		if !decodeJSONBody(w, r, maxJSONBodyBytes, &in) {
			return
		}
		result, err := authService.Login(r.Context(), in, serviceCfg.Defaults.OrganizationID)
		if err != nil {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		writeAuthResult(w, result)
	})

	mux.HandleFunc("/api/v1/auth/oidc/start", func(w http.ResponseWriter, r *http.Request) {
		if finish == nil {
			http.Error(w, "oidc unavailable", http.StatusServiceUnavailable)
			return
		}
		finish.startOIDC(w, r)
	})

	mux.HandleFunc("/api/v1/auth/oidc/callback", func(w http.ResponseWriter, r *http.Request) {
		if finish == nil {
			http.Error(w, "oidc unavailable", http.StatusServiceUnavailable)
			return
		}
		finish.finishOIDC(w, r)
	})

	mux.HandleFunc("/api/v1/auth/refresh", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !enforceRateLimit(w, r, authRateLimiter, "auth_refresh") {
			return
		}
		if authService == nil {
			http.Error(w, "auth service unavailable", http.StatusServiceUnavailable)
			return
		}
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}
		if !decodeJSONBody(w, r, maxJSONBodyBytes, &req) || req.RefreshToken == "" {
			http.Error(w, "invalid refresh payload", http.StatusBadRequest)
			return
		}
		pair, err := authService.Refresh(r.Context(), req.RefreshToken)
		if err != nil {
			http.Error(w, "invalid refresh token", http.StatusUnauthorized)
			return
		}
		_ = policy.WriteHTTPJSON(w, http.StatusOK, pair)
	})

	mux.Handle("/api/v1/auth/logout", withMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if authService == nil {
			http.Error(w, "auth service unavailable", http.StatusServiceUnavailable)
			return
		}
		claims, _ := identity.ClaimsFromContext(r.Context())
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}
		if r.ContentLength != 0 && !decodeJSONBody(w, r, maxJSONBodyBytes, &req) {
			return
		}
		if err := authService.LogoutWithRefreshToken(r.Context(), claims.UserID, req.RefreshToken); err != nil {
			http.Error(w, "invalid logout token", http.StatusUnauthorized)
			return
		}
		_ = policy.WriteHTTPJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}), authMW, viewerOnly))

	mux.Handle("/api/v1/auth/logout-all", withMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if authService == nil {
			http.Error(w, "auth service unavailable", http.StatusServiceUnavailable)
			return
		}
		claims, _ := identity.ClaimsFromContext(r.Context())
		if err := authService.LogoutAll(r.Context(), claims.UserID); err != nil {
			writeInternalServerError(w, "logout all", err)
			return
		}
		_ = policy.WriteHTTPJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}), authMW, viewerOnly))

	mux.Handle("/api/v1/auth/sessions", withMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if authService == nil {
			http.Error(w, "auth service unavailable", http.StatusServiceUnavailable)
			return
		}
		claims, _ := identity.ClaimsFromContext(r.Context())
		sessions, err := authService.ListSessions(r.Context(), claims.UserID, 50)
		if err != nil {
			writeInternalServerError(w, "list sessions", err)
			return
		}
		_ = policy.WriteHTTPJSON(w, http.StatusOK, sessions)
	}), authMW, viewerOnly))

	mux.Handle("/api/v1/policy/evaluate", withMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		metrics.IncMessagesReceived()
		bodyReader := http.MaxBytesReader(w, r.Body, maxPolicyEvalBodyBytes)
		body, err := io.ReadAll(bodyReader)
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "unable to read request body", http.StatusBadRequest)
			return
		}
		req, err := policy.DecodeRequest(bytes.NewReader(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req.Normalize()

		highValueRecipient := false
		if recipientValidator != nil && recipientBehavior != nil && len(req.Message.Envelope.Recipients) > 0 {
			profiles, err := recipientValidator.LookupRecipientProfiles(r.Context(), req.Message.Envelope.Recipients)
			if err == nil {
				validSet := make(map[string]bool, len(profiles))
				for _, profile := range profiles {
					validSet[profile.Address] = profile.Valid
					if profile.PolicyClass == "EXECUTIVE" || profile.PolicyClass == "FINANCE" || profile.PolicyClass == "HR" {
						highValueRecipient = true
					}
				}
				beh, err := recipientBehavior.Observe(r.Context(), req.Message.Envelope.From, req.Message.Envelope.Recipients, validSet)
				if err == nil {
					req.Message.Envelope.InvalidRatio = beh.InvalidRatio
					req.Message.Behavior.EnumerationLikely = beh.EnumerationLikely
					metrics.AddInvalidRecipients(int64(float64(len(req.Message.Envelope.Recipients)) * beh.InvalidRatio))
					if beh.EnumerationLikely {
						metrics.IncEnumerationDetections()
					}
				}
			}
		}

		var (
			urlObservations        []database.URLObservation
			attachmentObservations []database.AttachmentObservation
		)
		if req.RawMessage != "" {
			urlObservations = rspamd.ExtractURLObservations([]byte(req.RawMessage), false, "unknown")
			attachmentObservations = rspamd.ExtractAttachmentObservations([]byte(req.RawMessage))
		}

		attachmentNames := make([]string, 0, len(attachmentObservations))
		suspiciousAttachments := make([]map[string]any, 0, len(attachmentObservations))
		for _, a := range attachmentObservations {
			attachmentNames = append(attachmentNames, a.Filename)
			if a.Suspicious {
				suspiciousAttachments = append(suspiciousAttachments, map[string]any{
					"filename":     a.Filename,
					"content_type": a.ContentType,
					"size_bytes":   a.SizeBytes,
				})
			}
		}

		if req.RawMessage != "" && rspamdClient != nil {
			firstRecipient := ""
			if len(req.Message.Envelope.Recipients) > 0 {
				firstRecipient = req.Message.Envelope.Recipients[0]
			}
			contentResult, err := rspamdClient.Check(r.Context(), rspamd.CheckRequest{
				RawMessage: []byte(req.RawMessage),
				FromIP:     req.SourceIP,
				Helo:       req.HELO,
				From:       req.Message.Envelope.From,
				Recipient:  firstRecipient,
			})
			if err == nil {
				req.Message.Content.RspamdScore = contentResult.Score
				req.Message.Content.MaliciousURL = contentResult.MaliciousURL
				req.Message.Content.MalwareConfirmed = contentResult.MalwareDetected
				if contentResult.MaliciousURL {
					for i := range urlObservations {
						urlObservations[i].Malicious = true
						urlObservations[i].Confidence = "high"
					}
				}
			}
		}

		if req.Direction == "outbound" && req.RawMessage != "" {
			dlpResult := dlp.Analyze(req.RawMessage, attachmentNames)
			if dlpResult.Matched {
				req.Message.Behavior.SendingVelocityLevel = firstNonEmpty(req.Message.Behavior.SendingVelocityLevel, "elevated")
				req.Message.Content.RspamdScore += float64(dlpResult.RiskScore) / 10
			}
		}

		if len(suspiciousAttachments) >= serviceCfg.Sandbox.MinSuspicionHit {
			sandboxResult, err := sandboxClient.AnalyzeAttachments(r.Context(), suspiciousAttachments)
			if err == nil && sandboxResult.Malicious {
				req.Message.Content.MalwareConfirmed = true
				req.Message.Content.PhishingConfidenceLevel = "critical"
			}
		}
		if req.Direction == "outbound" && outboundCounters != nil {
			if obs, err := outboundCounters.ObserveOutbound(r.Context(), req.Message.Envelope.From, req.Message.Envelope.Recipients, reputation.OutboundLimits{
				RecipientsPerHour:    currentPolicyCfg.Policy.Outbound.Throttle.RecipientsPerHour,
				UniqueDomainsPerHour: currentPolicyCfg.Policy.Outbound.Throttle.UniqueDomainsPerHour,
			}); err == nil {
				req.Message.Behavior.SendingVelocityLevel = obs.VelocityLevel
				req.Message.Behavior.RecipientDiversity = obs.RecipientDiversity
			}
		}

		policyMu.RLock()
		engine := currentEngine
		policyMu.RUnlock()
		decision := policy.DecisionResponse{
			Direction: req.Direction,
			Decision:  engine.EvaluateByDirection(req.Direction, req.Message),
		}

		knownCorrespondentRisk := req.Message.Relationship.KnownCorrespondent &&
			(req.Message.Authentication.SPF == "fail" || req.Message.Authentication.DKIM == "fail" || req.Message.Authentication.DMARC == "fail") &&
			(req.Message.Content.MaliciousURL || req.Message.Content.PhishingConfidenceLevel == "high" || req.Message.Content.PhishingConfidenceLevel == "critical")
		if knownCorrespondentRisk && decision.Decision.Action == scoring.ActionAccept {
			decision.Decision.Action = scoring.ActionQuarantine
			decision.Decision.Reason = decision.Decision.Reason + "; possible BEC anomaly"
		}
		if highValueRecipient {
			decision.Decision.Score -= 3
			if decision.Decision.Action == scoring.ActionAccept && decision.Decision.Score <= -7 {
				decision.Decision.Action = scoring.ActionQuarantine
				decision.Decision.Reason = decision.Decision.Reason + "; elevated mailbox policy class"
			}
		}

		switch decision.Decision.Action {
		case scoring.ActionAccept:
			metrics.IncMessagesAccepted()
		case scoring.ActionReject:
			metrics.IncMessagesRejected()
		case scoring.ActionQuarantine:
			metrics.IncMessagesQuarantined()
		}

		if messageStore != nil {
			decisionRaw, _ := json.Marshal(decision.Decision)
			inputRaw, _ := json.Marshal(req.Message)
			messageID, err := messageStore.InsertMessage(r.Context(), serviceCfg.Defaults.OrganizationID, database.MessageRecord{
				Direction:     req.Direction,
				Sender:        req.Message.Envelope.From,
				Recipients:    req.Message.Envelope.Recipients,
				SourceIP:      req.SourceIP,
				PolicyAction:  string(decision.Decision.Action),
				PolicyScore:   decision.Decision.Score,
				ObservedAt:    time.Now().UTC(),
				Quarantined:   decision.Decision.Action == scoring.ActionQuarantine,
				Subject:       req.Subject,
				QueueID:       req.QueueID,
				Decision:      decisionRaw,
				DecisionInput: inputRaw,
			})
			if err == nil && eventRepo != nil {
				_ = messageStore.InsertAuthenticationResult(r.Context(), messageID, database.AuthResult{
					SPF:   req.Message.Authentication.SPF,
					DKIM:  req.Message.Authentication.DKIM,
					DMARC: req.Message.Authentication.DMARC,
					ARC:   req.Message.Authentication.ARC,
				})
				_ = messageStore.InsertURLObservations(r.Context(), messageID, urlObservations)
				_ = messageStore.InsertAttachmentObservations(r.Context(), messageID, attachmentObservations)

				_ = eventRepo.AddMessageEvent(r.Context(), messageID, events.PolicyDecision, map[string]string{
					"direction": req.Direction,
					"action":    string(decision.Decision.Action),
				})
				_ = siemForwarder.Send(r.Context(), map[string]any{
					"type":      "policy_decision",
					"messageId": messageID,
					"direction": req.Direction,
					"action":    string(decision.Decision.Action),
					"score":     decision.Decision.Score,
					"ts":        time.Now().UTC().Format(time.RFC3339),
				})
			} else if err != nil {
				log.Printf("persist message failed: %v", err)
			}
		}
		if decision.Decision.Action == scoring.ActionQuarantine {
			subject := req.Subject
			if strings.TrimSpace(subject) == "" {
				subject = "(unknown)"
			}
			_, _ = qRepo.Add(r.Context(), quarantine.Message{
				From:          req.Message.Envelope.From,
				To:            req.Message.Envelope.Recipients,
				Subject:       subject,
				Reason:        decision.Decision.Reason,
				Decision:      decision.Decision,
				DecisionInput: req.Message,
				QueueID:       req.QueueID,
				Direction:     req.Direction,
				ReceivedAt:    time.Now().UTC(),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = decision.WriteJSON(w)
	}), authMW, moderatorOnly))

	mux.Handle("/api/v1/policy/current", withMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			policyMu.RLock()
			defer policyMu.RUnlock()
			_ = policy.WriteHTTPJSON(w, http.StatusOK, currentPolicyCfg)
		case http.MethodPut:
			if claims, ok := identity.ClaimsFromContext(r.Context()); !ok || claims.Role != identity.RoleAdmin {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			if finish == nil {
				http.Error(w, "policy editor unavailable", http.StatusServiceUnavailable)
				return
			}
			finish.putPolicy(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}), authMW, viewerOnly))

	mux.Handle("/api/v1/policy/versions", withMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if messageStore == nil {
			http.Error(w, "policy repository unavailable", http.StatusServiceUnavailable)
			return
		}
		switch r.Method {
		case http.MethodGet:
			items, err := messageStore.ListPolicyVersions(r.Context(), serviceCfg.Defaults.OrganizationID, 20)
			if err != nil {
				writeInternalServerError(w, "list policy versions", err)
				return
			}
			_ = policy.WriteHTTPJSON(w, http.StatusOK, items)
		case http.MethodPost:
			claims, _ := identity.ClaimsFromContext(r.Context())
			label := "manual-" + time.Now().UTC().Format("20060102T150405Z")
			var req struct {
				Label string `json:"label"`
			}
			_ = decodeJSONBody(w, r, maxJSONBodyBytes, &req)
			if strings.TrimSpace(req.Label) != "" {
				label = strings.TrimSpace(req.Label)
			}
			policyMu.RLock()
			snap := currentPolicyCfg
			policyMu.RUnlock()
			v, err := messageStore.SavePolicyVersion(r.Context(), serviceCfg.Defaults.OrganizationID, label, snap, claims.UserID)
			if err != nil {
				writeInternalServerError(w, "save policy version", err)
				return
			}
			if eventRepo != nil {
				_ = eventRepo.AddAuditEvent(r.Context(), serviceCfg.Defaults.OrganizationID, claims.UserID, "policy_version_created", "policy_version", strconv.FormatInt(v.ID, 10), map[string]any{"label": v.VersionLabel})
			}
			_ = siemForwarder.Send(r.Context(), map[string]any{
				"type":        "audit",
				"event":       "policy_version_created",
				"actorUserId": claims.UserID,
				"policyId":    v.ID,
				"ts":          time.Now().UTC().Format(time.RFC3339),
			})
			_ = policy.WriteHTTPJSON(w, http.StatusCreated, v)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}), authMW, adminOnly))

	mux.Handle("/api/v1/policy/rollback", withMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || messageStore == nil {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		claims, _ := identity.ClaimsFromContext(r.Context())
		idValue := r.URL.Query().Get("id")
		id, err := strconv.ParseInt(idValue, 10, 64)
		if err != nil || id <= 0 {
			http.Error(w, "invalid policy version id", http.StatusBadRequest)
			return
		}
		version, err := messageStore.GetPolicyVersion(r.Context(), serviceCfg.Defaults.OrganizationID, id)
		if err != nil {
			http.Error(w, "policy version not found", http.StatusNotFound)
			return
		}
		var newPolicy config.PolicyConfig
		if err := json.Unmarshal(version.PolicyJSON, &newPolicy); err != nil {
			http.Error(w, "stored policy payload invalid", http.StatusInternalServerError)
			return
		}
		policyMu.Lock()
		currentPolicyCfg = newPolicy
		currentEngine = policy.NewEngine(policy.EngineConfigFrom(newPolicy))
		policyMu.Unlock()
		_, _ = messageStore.SaveConfigSnapshot(r.Context(), serviceCfg.Defaults.OrganizationID, "policy-rollback", newPolicy, claims.UserID)
		if eventRepo != nil {
			_ = eventRepo.AddAuditEvent(r.Context(), serviceCfg.Defaults.OrganizationID, claims.UserID, "policy_rollback", "policy_version", strconv.FormatInt(id, 10), nil)
		}
		_ = siemForwarder.Send(r.Context(), map[string]any{
			"type":        "audit",
			"event":       "policy_rollback",
			"actorUserId": claims.UserID,
			"policyId":    id,
			"ts":          time.Now().UTC().Format(time.RFC3339),
		})
		_ = policy.WriteHTTPJSON(w, http.StatusOK, map[string]any{
			"rolled_back_to": id,
			"disk_unchanged": true,
			"note":           "Rollback updated the live policy engine. The on-disk policy YAML file was not rewritten.",
		})
	}), authMW, adminOnly))

	mux.Handle("/api/v1/config/snapshots", withMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if messageStore == nil {
			http.Error(w, "snapshot repository unavailable", http.StatusServiceUnavailable)
			return
		}
		switch r.Method {
		case http.MethodGet:
			sType := strings.TrimSpace(r.URL.Query().Get("type"))
			items, err := messageStore.ListConfigSnapshots(r.Context(), serviceCfg.Defaults.OrganizationID, sType, 20)
			if err != nil {
				writeInternalServerError(w, "list config snapshots", err)
				return
			}
			_ = policy.WriteHTTPJSON(w, http.StatusOK, items)
		case http.MethodPost:
			claims, _ := identity.ClaimsFromContext(r.Context())
			var req struct {
				Type   string         `json:"type"`
				Config map[string]any `json:"config"`
			}
			if !decodeJSONBody(w, r, maxJSONBodyBytes, &req) {
				return
			}
			if req.Type == "" {
				req.Type = "manual"
			}
			s, err := messageStore.SaveConfigSnapshot(r.Context(), serviceCfg.Defaults.OrganizationID, req.Type, req.Config, claims.UserID)
			if err != nil {
				writeInternalServerError(w, "save config snapshot", err)
				return
			}
			_ = policy.WriteHTTPJSON(w, http.StatusCreated, s)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}), authMW, adminOnly))

	mux.Handle("/api/v1/identity/providers", withMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if providersRepo == nil {
			http.Error(w, "provider repository unavailable", http.StatusServiceUnavailable)
			return
		}
		switch r.Method {
		case http.MethodGet:
			items, err := providersRepo.List(r.Context())
			if err != nil {
				writeInternalServerError(w, "list identity providers", err)
				return
			}
			_ = policy.WriteHTTPJSON(w, http.StatusOK, items)
		case http.MethodPost:
			claims, _ := identity.ClaimsFromContext(r.Context())
			var req identity.Provider
			if !decodeJSONBody(w, r, maxJSONBodyBytes, &req) {
				return
			}
			req, err := identity.ValidateProviderInput(req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			item, err := providersRepo.Upsert(r.Context(), req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if eventRepo != nil {
				_ = eventRepo.AddAuditEvent(r.Context(), serviceCfg.Defaults.OrganizationID, claims.UserID, "identity_provider_upsert", "auth_provider", item.ID, map[string]any{"type": item.Type})
			}
			_ = siemForwarder.Send(r.Context(), map[string]any{
				"type":        "audit",
				"event":       "identity_provider_upsert",
				"actorUserId": claims.UserID,
				"providerId":  item.ID,
				"provider":    item.Type,
				"ts":          time.Now().UTC().Format(time.RFC3339),
			})
			_ = policy.WriteHTTPJSON(w, http.StatusOK, item)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}), authMW, adminOnly))

	mux.Handle("/api/v1/identity/providers/", withMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || providersRepo == nil {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		claims, _ := identity.ClaimsFromContext(r.Context())
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/identity/providers/")
		if id == "" {
			http.Error(w, "missing provider id", http.StatusBadRequest)
			return
		}
		if err := providersRepo.Delete(r.Context(), id); err != nil {
			writeInternalServerError(w, "delete provider", err)
			return
		}
		if eventRepo != nil {
			_ = eventRepo.AddAuditEvent(r.Context(), serviceCfg.Defaults.OrganizationID, claims.UserID, "identity_provider_deleted", "auth_provider", id, nil)
		}
		_ = siemForwarder.Send(r.Context(), map[string]any{
			"type":        "audit",
			"event":       "identity_provider_deleted",
			"actorUserId": claims.UserID,
			"providerId":  id,
			"ts":          time.Now().UTC().Format(time.RFC3339),
		})
		_ = policy.WriteHTTPJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}), authMW, adminOnly))

	mux.Handle("/api/v1/quarantine/messages", withMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := identity.ClaimsFromContext(r.Context())
		switch r.Method {
		case http.MethodGet:
			all, err := identity.ResolveScope(claims.Role, r.URL.Query().Get("scope"))
			if err != nil {
				status := http.StatusBadRequest
				if errors.Is(err, identity.ErrScopeForbidden) {
					status = http.StatusForbidden
				}
				http.Error(w, err.Error(), status)
				return
			}
			var messages []quarantine.Message
			if all {
				messages, err = qRepo.List(r.Context(), 200)
			} else {
				messages, err = qRepo.ListScoped(r.Context(), 200, claims.Email)
			}
			if err != nil {
				writeInternalServerError(w, "list quarantine", err)
				return
			}
			_ = policy.WriteHTTPJSON(w, http.StatusOK, messages)
		case http.MethodPost:
			if claims.Role == identity.RoleViewer {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			var req quarantine.Message
			if !decodeJSONBody(w, r, maxJSONBodyBytes, &req) {
				return
			}
			msg, err := qRepo.Add(r.Context(), req)
			if err != nil {
				writeInternalServerError(w, "add quarantine message", err)
				return
			}
			_ = policy.WriteHTTPJSON(w, http.StatusCreated, msg)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}), authMW, viewerOnly))

	mux.Handle("/api/v1/quarantine/messages/", withMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/quarantine/messages/")
		if id == "" {
			http.Error(w, "missing message id", http.StatusBadRequest)
			return
		}
		if strings.HasSuffix(id, "/release") {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if finish == nil {
				http.Error(w, "release unavailable", http.StatusServiceUnavailable)
				return
			}
			msgID := strings.TrimSuffix(strings.TrimSuffix(id, "/release"), "/")
			finish.releaseQuarantine(w, r, msgID)
			return
		}
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		msg, err := qRepo.Get(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		_ = policy.WriteHTTPJSON(w, http.StatusOK, msg)
	}), authMW, moderatorOnly))

	mux.Handle("/api/v1/messages", withMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || messageStore == nil {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		claims, _ := identity.ClaimsFromContext(r.Context())
		all, scopeErr := identity.ResolveScope(claims.Role, r.URL.Query().Get("scope"))
		if scopeErr != nil {
			status := http.StatusBadRequest
			if errors.Is(scopeErr, identity.ErrScopeForbidden) {
				status = http.StatusForbidden
			}
			http.Error(w, scopeErr.Error(), status)
			return
		}
		direction := strings.TrimSpace(r.URL.Query().Get("direction"))
		records, err := messageStore.ListMessagesVisible(r.Context(), serviceCfg.Defaults.OrganizationID, direction, claims.Email, all, 300)
		if err != nil {
			writeInternalServerError(w, "list messages", err)
			return
		}
		_ = policy.WriteHTTPJSON(w, http.StatusOK, records)
	}), authMW, viewerOnly))

	mux.Handle("/api/v1/events", withMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || eventRepo == nil {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		records, err := eventRepo.ListMessageEvents(r.Context(), 300)
		if err != nil {
			writeInternalServerError(w, "list events", err)
			return
		}
		_ = policy.WriteHTTPJSON(w, http.StatusOK, records)
	}), authMW, viewerOnly))

	mux.Handle("/api/v1/metrics", withMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = policy.WriteHTTPJSON(w, http.StatusOK, metrics.Snapshot())
	}), authMW, viewerOnly))

	mux.Handle("/api/v1/cluster/heartbeat", withMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || messageStore == nil {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Name     string         `json:"name"`
			Address  string         `json:"address"`
			Role     string         `json:"role"`
			Metadata map[string]any `json:"metadata"`
		}
		if !decodeJSONBody(w, r, maxJSONBodyBytes, &req) {
			return
		}
		if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Address) == "" || strings.TrimSpace(req.Role) == "" {
			http.Error(w, "name, address, and role are required", http.StatusBadRequest)
			return
		}
		if !isValidClusterNodeAddress(req.Address) {
			http.Error(w, "invalid cluster node address", http.StatusBadRequest)
			return
		}
		node, err := messageStore.UpsertClusterNodeHeartbeat(r.Context(), serviceCfg.Defaults.OrganizationID, req.Name, req.Address, req.Role, req.Metadata)
		if err != nil {
			writeInternalServerError(w, "upsert cluster heartbeat", err)
			return
		}
		_ = policy.WriteHTTPJSON(w, http.StatusOK, node)
	}), authMW, adminOnly))

	mux.Handle("/api/v1/cluster/nodes", withMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || messageStore == nil {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		nodes, err := messageStore.ListClusterNodes(r.Context(), serviceCfg.Defaults.OrganizationID)
		if err != nil {
			writeInternalServerError(w, "list cluster nodes", err)
			return
		}
		_ = policy.WriteHTTPJSON(w, http.StatusOK, nodes)
	}), authMW, adminOnly))

	finish = &finishAPI{
		orgID:       serviceCfg.Defaults.OrganizationID,
		configPath:  *configPath,
		auth:        authService,
		users:       idRepo,
		providers:   providersRepo,
		quarantine:  qRepo,
		db:          messageStore,
		events:      eventRepo,
		siem:        siemForwarder,
		ephemeral:   identity.NewEphemeralStore(nil),
		hold:        smtp.PostsuperHoldReleaser{},
		serviceMu:   &serviceMu,
		service:     &serviceCfg,
		policyMu:    &policyMu,
		policyCfg:   &currentPolicyCfg,
		engine:      &currentEngine,
		oidc:        &oidcProvider,
		rspamd:      &rspamdClient,
		sandbox:     &sandboxClient,
		forwarder:   &siemForwarder,
		processLDAP: buildLDAPProvider,
		rebuildOIDC: buildOIDCProvider,
	}
	if pg != nil {
		finish.ephemeral = identity.NewEphemeralStore(pg.Pool())
	}
	if authService != nil {
		authService.SetProviderResolver(finish.resolveProvider)
		authService.SetRefreshTTL(time.Duration(serviceCfg.Auth.RefreshTTLHours) * time.Hour)
	}
	registerFinishRoutes(mux, finish, authMW, viewerOnly, adminOnly)
	registerMaintenance(mux, messageStore, serviceCfg.Defaults.OrganizationID, authMW, adminOnly)

	handler := hardenHTTPServer(mux, func() []string { return finish.portalOrigins() })
	s := &http.Server{
		Addr:              serviceCfg.Service.Listen,
		Handler:           handler,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		server := &smtp.PostfixPolicyServer{
			Address: serviceCfg.SMTP.PolicyListen,
			CurrentEngine: func() *policy.Engine {
				policyMu.RLock()
				defer policyMu.RUnlock()
				return currentEngine
			},
			OnQuarantine: func(msg quarantine.Message) {
				if _, err := qRepo.Add(context.Background(), msg); err != nil {
					log.Printf("persist postfix quarantine: %v", err)
				}
			},
		}
		if err := server.Serve(ctx); err != nil {
			log.Printf("postfix policy server stopped: %v", err)
		}
	}()

	log.Printf("mailwarden starting on %s (config=%s policy=%s)", serviceCfg.Service.Listen, *configPath, *policyPath)
	if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(fmt.Errorf("mailwarden exited: %w", err))
	}
}

func buildLDAPProvider(serviceCfg config.ServiceConfig) *identity.LDAPProvider {
	if !serviceCfg.LDAP.Enabled {
		return nil
	}
	roleMap := map[string]identity.Role{}
	for group, roleRaw := range serviceCfg.LDAP.RoleMap {
		role, err := identity.ParseRole(roleRaw)
		if err != nil {
			continue
		}
		roleMap[group] = role
	}
	defaultRole, err := identity.ParseRole(serviceCfg.LDAP.DefaultRole)
	if err != nil {
		defaultRole = identity.RoleViewer
	}
	provider, err := identity.NewLDAPProvider(identity.LDAPConfig{
		URL:                   serviceCfg.LDAP.URL,
		BindDN:                serviceCfg.LDAP.BindDN,
		BindPassword:          serviceCfg.LDAP.BindPassword,
		SearchBase:            serviceCfg.LDAP.SearchBase,
		SearchFilter:          serviceCfg.LDAP.SearchFilter,
		EmailAttr:             serviceCfg.LDAP.EmailAttr,
		NameAttr:              serviceCfg.LDAP.NameAttr,
		GroupBase:             serviceCfg.LDAP.GroupBase,
		GroupFilter:           serviceCfg.LDAP.GroupFilter,
		GroupNameAttr:         serviceCfg.LDAP.GroupNameAttr,
		StartTLS:              serviceCfg.LDAP.StartTLS,
		TLSRejectUnauthorized: serviceCfg.LDAP.TLSRejectUnauthorized,
		RoleMap:               roleMap,
		DefaultRole:           defaultRole,
	})
	if err != nil {
		log.Printf("ldap disabled due to config error: %v", err)
		return nil
	}
	return provider
}

func withMiddleware(h http.Handler, m ...func(http.Handler) http.Handler) http.Handler {
	out := h
	for i := len(m) - 1; i >= 0; i-- {
		out = m[i](out)
	}
	return out
}

func buildOIDCProvider(ctx context.Context, serviceCfg config.ServiceConfig) *identity.OIDCProvider {
	if !serviceCfg.Auth.OIDC.Enabled {
		return nil
	}
	scopes := strings.Fields(serviceCfg.Auth.OIDC.Scopes)
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	provider, err := identity.NewOIDCProvider(ctx, identity.OIDCConfig{
		Enabled:      serviceCfg.Auth.OIDC.Enabled,
		Issuer:       serviceCfg.Auth.OIDC.Issuer,
		ClientID:     serviceCfg.Auth.OIDC.ClientID,
		ClientSecret: serviceCfg.Auth.OIDC.ClientSecret,
		RedirectURL:  serviceCfg.Auth.OIDC.RedirectURL,
		Scopes:       scopes,
		EmailClaim:   serviceCfg.Auth.OIDC.EmailClaim,
		NameClaim:    serviceCfg.Auth.OIDC.NameClaim,
		GroupsClaim:  serviceCfg.Auth.OIDC.GroupsClaim,
		DefaultRole:  identity.RoleViewer,
	})
	if err != nil {
		log.Printf("oidc disabled due to config error: %v", err)
		return nil
	}
	return provider
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func generateEphemeralSecret() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("mailwarden-ephemeral-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return false
		}
		http.Error(w, "invalid request payload", http.StatusBadRequest)
		return false
	}
	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		http.Error(w, "invalid request payload", http.StatusBadRequest)
		return false
	}
	return true
}

func writeInternalServerError(w http.ResponseWriter, op string, err error) {
	log.Printf("%s failed: %v", op, err)
	http.Error(w, "internal server error", http.StatusInternalServerError)
}

func hardenHTTPServer(next http.Handler, origins func() []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if origins != nil {
			origin := strings.TrimSpace(r.Header.Get("Origin"))
			if originAllowed(origin, origins()) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			}
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type rateLimiter struct {
	window time.Duration
	limit  int
	mu     sync.Mutex
	hits   map[string][]time.Time
}

func newInMemoryLimiter(window time.Duration, limit int) *rateLimiter {
	if window <= 0 {
		window = time.Minute
	}
	if limit <= 0 {
		limit = 1
	}
	return &rateLimiter{
		window: window,
		limit:  limit,
		hits:   make(map[string][]time.Time),
	}
}

func (r *rateLimiter) Allow(key string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := now.Add(-r.window)
	current := r.hits[key]
	idx := 0
	for idx < len(current) && current[idx].Before(cutoff) {
		idx++
	}
	current = current[idx:]
	if len(current) >= r.limit {
		r.hits[key] = current
		return false
	}
	current = append(current, now)
	r.hits[key] = current
	return true
}

func enforceRateLimit(w http.ResponseWriter, r *http.Request, limiter *rateLimiter, scope string) bool {
	if limiter == nil {
		return true
	}
	key := scope + ":" + callerIPKey(r)
	if limiter.Allow(key, time.Now().UTC()) {
		return true
	}
	w.Header().Set("Retry-After", "60")
	http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
	return false
}

func callerIPKey(r *http.Request) string {
	ff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if ff != "" {
		first := strings.TrimSpace(strings.Split(ff, ",")[0])
		if first != "" {
			return first
		}
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	if strings.TrimSpace(r.RemoteAddr) != "" {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return "unknown"
}

func registerMaintenance(mux *http.ServeMux, store *database.Postgres, orgID int64, authMW, adminOnly func(http.Handler) http.Handler) {
	root := os.Getenv("MAIL_WARDEN_ROOT")
	if root == "" {
		root = "."
	}
	deps := maintenance.Deps{
		Allow: maintenance.HostUpdateAllowed(os.Getenv("MAIL_ALLOW_HOST_UPDATE") == "1"),
		Root:  root,
		Key:   os.Getenv("MAIL_MAINTENANCE_KEY"),
		Role:  os.Getenv("MAIL_NODE_ROLE"),
	}
	if store != nil {
		repo := database.NewPlatformRepo(store, orgID)
		deps.ListNodes = func(ctx context.Context) ([]maintenance.Node, error) {
			rows, err := repo.ListUpgradeNodes(ctx)
			if err != nil {
				return nil, err
			}
			nodes := make([]maintenance.Node, 0, len(rows))
			for _, row := range rows {
				nodes = append(nodes, maintenance.Node{Name: row.Name, Address: row.Address, Role: row.Role, Key: row.Token})
			}
			return nodes, nil
		}
		identity.ServiceAccountLookup = func(ctx context.Context, token string) (identity.Claims, string, bool) {
			account, ok, err := repo.FindAccount(ctx, token)
			if err != nil || !ok {
				return identity.Claims{}, "", false
			}
			return identity.Claims{UserID: account.ID, Role: identity.Role(account.Role), Email: account.Name}, account.EnvironmentID, true
		}
		platformMetrics = func() string {
			text, err := repo.Prometheus(context.Background())
			if err != nil {
				return ""
			}
			return text
		}
		logPath := os.Getenv("MAIL_WARDEN_UPDATE_LOG")
		if logPath == "" {
			logPath = "/var/log/mail-warden-update.log"
		}
		platform.Register(mux, repo, authMW, adminOnly, logPath, os.Getenv("MAIL_MAINTENANCE_KEY"), func(ctx context.Context) ([]platform.SyncNode, error) {
			rows, err := repo.ListUpgradeNodes(ctx)
			if err != nil {
				return nil, err
			}
			out := make([]platform.SyncNode, 0, len(rows))
			for _, row := range rows {
				if !maintenance.IsSecondary(row.Role) {
					continue
				}
				key := row.Token
				if key == "" {
					key = os.Getenv("MAIL_MAINTENANCE_KEY")
				}
				out = append(out, platform.SyncNode{Name: row.Name, URL: "http://" + row.Address + "/api/v1/platform/sync/apply", Key: key})
			}
			return out, nil
		}, func(ctx context.Context, url, key string, body []byte) (int, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
			if err != nil {
				return 0, err
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Maintenance-Key", key)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				return 0, err
			}
			defer res.Body.Close()
			return res.StatusCode, nil
		})
	}
	mux.HandleFunc("/api/v1/maintenance/apply", deps.Apply)
	mux.Handle("/api/v1/maintenance/product", withMiddleware(http.HandlerFunc(deps.Local(maintenance.Product)), authMW, adminOnly))
	mux.Handle("/api/v1/maintenance/packages", withMiddleware(http.HandlerFunc(deps.Local(maintenance.Packages)), authMW, adminOnly))
	mux.Handle("/api/v1/maintenance/slaves", withMiddleware(http.HandlerFunc(deps.Slaves), authMW, adminOnly))
}

func isValidClusterNodeAddress(v string) bool {
	addr := strings.TrimSpace(v)
	if addr == "" {
		return false
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.TrimSpace(host) == "" {
		return false
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum <= 0 || portNum > 65535 {
		return false
	}
	return true
}
