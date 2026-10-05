package platform

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/boxorandyos/mail-warden/internal/identity"
)

type Repo interface {
	ListEnvironments(ctx context.Context) ([]Environment, error)
	CreateEnvironment(ctx context.Context, name, description string) (Environment, error)
	ListAccounts(ctx context.Context) ([]Account, error)
	CreateAccount(ctx context.Context, name, role, environmentID string) (Account, error)
	DeleteAccount(ctx context.Context, id string) error
	ListJobs(ctx context.Context) ([]Job, error)
	ListRunbooks(ctx context.Context, environmentID string) ([]Runbook, error)
	CreateRunbook(ctx context.Context, title, body, environmentID string) (Runbook, error)
	ListRules(ctx context.Context) ([]Rule, error)
	CreateRule(ctx context.Context, name, kind string, threshold int) (Rule, error)
	SetRuleEnabled(ctx context.Context, id string, enabled bool) error
	ListPolicies(ctx context.Context) ([]Policy, error)
	CreatePolicy(ctx context.Context, name, kind string, threshold *int) (Policy, error)
	SetPolicyEnabled(ctx context.Context, id string, enabled bool) error
	Violations(ctx context.Context) ([]Violation, error)
	ListSnapshots(ctx context.Context) ([]Snapshot, error)
	Capture(ctx context.Context, actor string) (Snapshot, error)
	Apply(ctx context.Context, id string) error
	ApplyDocument(ctx context.Context, doc Document) error
	Document(ctx context.Context) (Document, error)
	Metrics(ctx context.Context) (map[string]any, error)
	Audit(ctx context.Context) ([]AuditRow, error)
}

type SyncNode struct {
	Name string
	URL  string
	Key  string
}

func Register(mux *http.ServeMux, repo Repo, authMW, adminOnly func(http.Handler) http.Handler, logPath, maintenanceKey string, nodes func(ctx context.Context) ([]SyncNode, error), post func(ctx context.Context, url, key string, body []byte) (int, error)) {
	handle := func(pattern string, admin bool, handler http.HandlerFunc) {
		wrapped := authMW(handler)
		if admin {
			wrapped = authMW(adminOnly(handler))
		}
		mux.Handle(pattern, wrapped)
	}
	handle("/api/v1/platform/environments", false, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			items, err := repo.ListEnvironments(r.Context())
			respond(w, items, err)
		case http.MethodPost:
			var body struct{ Name, Description string }
			if !decode(w, r, &body) {
				return
			}
			item, err := repo.CreateEnvironment(r.Context(), body.Name, body.Description)
			respond(w, item, err)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	handle("/api/v1/platform/service-accounts", true, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			items, err := repo.ListAccounts(r.Context())
			respond(w, items, err)
		case http.MethodPost:
			var body struct {
				Name          string `json:"name"`
				Role          string `json:"role"`
				EnvironmentID string `json:"environmentId"`
			}
			if !decode(w, r, &body) {
				return
			}
			if pin := identity.EnvironmentFromContext(r.Context()); pin != "" && body.EnvironmentID != "" && body.EnvironmentID != pin {
				http.Error(w, "service account is pinned to another environment", http.StatusForbidden)
				return
			}
			item, err := repo.CreateAccount(r.Context(), body.Name, body.Role, body.EnvironmentID)
			respond(w, item, err)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	handle("/api/v1/platform/service-accounts/", true, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/platform/service-accounts/")
		respond(w, map[string]bool{"ok": true}, repo.DeleteAccount(r.Context(), id))
	})
	handle("/api/v1/platform/jobs", false, func(w http.ResponseWriter, r *http.Request) {
		items, err := repo.ListJobs(r.Context())
		respond(w, items, err)
	})
	handle("/api/v1/platform/runbooks", false, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			env := r.URL.Query().Get("environmentId")
			if pin := identity.EnvironmentFromContext(r.Context()); pin != "" {
				env = pin
			}
			items, err := repo.ListRunbooks(r.Context(), env)
			respond(w, items, err)
		case http.MethodPost:
			var body struct {
				Title         string `json:"title"`
				Body          string `json:"body"`
				EnvironmentID string `json:"environmentId"`
			}
			if !decode(w, r, &body) {
				return
			}
			item, err := repo.CreateRunbook(r.Context(), body.Title, body.Body, body.EnvironmentID)
			respond(w, item, err)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	handle("/api/v1/platform/alert-rules", false, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			items, err := repo.ListRules(r.Context())
			respond(w, items, err)
		case http.MethodPost:
			var body struct {
				Name      string `json:"name"`
				Kind      string `json:"kind"`
				Threshold int    `json:"threshold"`
			}
			if !decode(w, r, &body) {
				return
			}
			item, err := repo.CreateRule(r.Context(), body.Name, body.Kind, body.Threshold)
			respond(w, item, err)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	handle("/api/v1/platform/alert-rules/", true, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch && r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var body struct{ Enabled bool }
		if !decode(w, r, &body) {
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/platform/alert-rules/")
		respond(w, map[string]bool{"ok": true}, repo.SetRuleEnabled(r.Context(), id, body.Enabled))
	})
	handle("/api/v1/platform/policies", false, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			items, err := repo.ListPolicies(r.Context())
			respond(w, items, err)
		case http.MethodPost:
			var body struct {
				Name      string `json:"name"`
				Kind      string `json:"kind"`
				Threshold *int   `json:"threshold"`
			}
			if !decode(w, r, &body) {
				return
			}
			item, err := repo.CreatePolicy(r.Context(), body.Name, body.Kind, body.Threshold)
			respond(w, item, err)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	handle("/api/v1/platform/policies/", true, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/violations") {
			items, err := repo.Violations(r.Context())
			respond(w, items, err)
			return
		}
		var body struct{ Enabled bool }
		if !decode(w, r, &body) {
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/platform/policies/")
		respond(w, map[string]bool{"ok": true}, repo.SetPolicyEnabled(r.Context(), id, body.Enabled))
	})
	handle("/api/v1/platform/policies/violations", false, func(w http.ResponseWriter, r *http.Request) {
		items, err := repo.Violations(r.Context())
		respond(w, items, err)
	})
	handle("/api/v1/platform/snapshots", true, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			items, err := repo.ListSnapshots(r.Context())
			respond(w, items, err)
		case http.MethodPost:
			claims, _ := identity.ClaimsFromContext(r.Context())
			item, err := repo.Capture(r.Context(), claims.Email)
			respond(w, item, err)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	handle("/api/v1/platform/snapshots/", true, func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/platform/snapshots/"), "/apply")
		respond(w, map[string]bool{"ok": true}, repo.Apply(r.Context(), id))
	})
	handle("/api/v1/platform/metrics", false, func(w http.ResponseWriter, r *http.Request) {
		item, err := repo.Metrics(r.Context())
		respond(w, item, err)
	})
	handle("/api/v1/platform/audit/export", true, func(w http.ResponseWriter, r *http.Request) {
		rows, err := repo.Audit(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("format") == "csv" {
			w.Header().Set("Content-Type", "text/csv")
			_, _ = w.Write([]byte(ExportCSV(rows)))
			return
		}
		writeJSON(w, http.StatusOK, rows)
	})
	handle("/api/v1/platform/logs", true, func(w http.ResponseWriter, _ *http.Request) {
		content, exists := TailLog(logPath, 200)
		writeJSON(w, http.StatusOK, map[string]any{"content": content, "exists": exists, "path": logPath})
	})
	mux.HandleFunc("/api/v1/platform/sync/apply", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		presented := r.Header.Get("X-Maintenance-Key")
		if maintenanceKey == "" || len(maintenanceKey) != len(presented) || subtle.ConstantTimeCompare([]byte(maintenanceKey), []byte(presented)) != 1 {
			http.Error(w, "invalid maintenance key", http.StatusUnauthorized)
			return
		}
		var doc Document
		if !decode(w, r, &doc) {
			return
		}
		respond(w, map[string]bool{"ok": true}, repo.ApplyDocument(r.Context(), doc))
	})
	handle("/api/v1/platform/sync", true, func(w http.ResponseWriter, r *http.Request) {
		if nodes == nil || post == nil {
			writeJSON(w, http.StatusOK, []any{})
			return
		}
		doc, err := repo.Document(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		raw, _ := json.Marshal(doc)
		list, err := nodes(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		results := make([]map[string]any, 0, len(list))
		for _, node := range list {
			status, postErr := post(r.Context(), node.URL, node.Key, raw)
			message := ""
			if postErr != nil {
				message = postErr.Error()
			}
			results = append(results, map[string]any{"name": node.Name, "status": status, "message": message})
		}
		writeJSON(w, http.StatusOK, results)
	})
}

func respond(w http.ResponseWriter, payload any, err error) {
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, payload)
}

func decode(w http.ResponseWriter, r *http.Request, dest any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(dest); err != nil && err != io.EOF {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
