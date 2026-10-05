package maintenance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Deps struct {
	Allow     bool
	Root      string
	Key       string
	Role      string
	ListNodes func(ctx context.Context) ([]Node, error)
	Schedule  func(ctx context.Context, kind Kind) (executed bool, detail string, err error)
	Post      func(ctx context.Context, call Call, key string) (status int, message string, err error)
}

func (d Deps) schedule(ctx context.Context, kind Kind) (bool, string, error) {
	if d.Schedule != nil {
		return d.Schedule(ctx, kind)
	}
	return ScheduleScript(ctx, d.Root, kind, d.Allow)
}

func (d Deps) post(ctx context.Context, call Call, key string) (int, string, error) {
	if d.Post != nil {
		return d.Post(ctx, call, key)
	}
	return postMaintenance(ctx, call, key)
}

func (d Deps) Apply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !KeyMatches(d.Key, r.Header.Get("X-Maintenance-Key")) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "invalid maintenance key"})
		return
	}
	var body struct {
		Kind string `json:"kind"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "invalid body"})
		return
	}
	kind, err := ParseKind(body.Kind)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": err.Error()})
		return
	}
	executed, detail, err := d.schedule(r.Context(), kind)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"success": true, "executed": executed, "detail": detail})
}

func (d Deps) Local(kind Kind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		executed, detail, err := d.schedule(r.Context(), kind)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": err.Error()})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"success": true, "executed": executed, "detail": detail})
	}
}

func (d Deps) Slaves(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Kind string `json:"kind"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil && err != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "invalid body"})
		return
	}
	kind, err := ParseKind(body.Kind)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": err.Error()})
		return
	}
	if d.ListNodes == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "cluster store is unavailable"})
		return
	}
	nodes, err := d.ListNodes(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": err.Error()})
		return
	}
	calls, err := PlanSlaveUpgrades(d.Role, nodes, kind)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": err.Error()})
		return
	}
	results := make([]map[string]any, 0, len(calls))
	for _, call := range calls {
		key := call.Key
		if key == "" {
			key = d.Key
		}
		status, message, postErr := d.post(r.Context(), call, key)
		if postErr != nil {
			status = 0
			message = postErr.Error()
		}
		results = append(results, map[string]any{"name": call.Name, "status": status, "message": message})
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "kind": kind, "results": results})
}

func (d Deps) Backups(w http.ResponseWriter, r *http.Request) {
	dir := filepath.Join(d.Root, "backups")
	switch r.Method {
	case http.MethodGet:
		entries, _ := os.ReadDir(dir)
		names := []string{}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			names = append(names, entry.Name())
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": names})
	case http.MethodPost:
		detail := "bash scripts/backup.sh ./backups"
		if !d.Allow {
			writeJSON(w, http.StatusAccepted, map[string]any{"success": true, "executed": false, "detail": "planned: " + detail + " (set WARDEN_ALLOW_HOST_UPDATE=1 to run it)"})
			return
		}
		script := filepath.Join(d.Root, "scripts", "backup.sh")
		cmd := exec.Command("bash", script, dir)
		cmd.Dir = d.Root
		cmd.Env = os.Environ()
		if err := cmd.Start(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": err.Error()})
			return
		}
		go func() { _ = cmd.Wait() }()
		writeJSON(w, http.StatusAccepted, map[string]any{"success": true, "executed": true, "detail": "scheduled: " + detail})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (d Deps) Runtimes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": RuntimeCatalog()})
}

func (d Deps) Runtime(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Component string `json:"component"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "invalid body"})
		return
	}
	executed, detail, err := ScheduleRuntime(d.Root, body.Component, d.Allow)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"success": true, "executed": executed, "detail": detail})
}

func ScheduleRuntime(root, component string, allow bool) (bool, string, error) {
	executed, detail, err := PlanRuntime(component, allow)
	if err != nil || !executed {
		return executed, detail, err
	}
	spec, err := RuntimeSpecFor(component)
	if err != nil {
		return false, detail, err
	}
	script := filepath.Join(root, "scripts", spec.Script)
	if st, statErr := os.Stat(script); statErr != nil || st.IsDir() {
		return false, detail, fmt.Errorf("maintenance script not found")
	}
	cmd := exec.Command("bash", append([]string{script}, spec.Args...)...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), spec.Confirm+"=1")
	if err := cmd.Start(); err != nil {
		return false, detail, err
	}
	go func() { _ = cmd.Wait() }()
	return true, detail, nil
}

func ScheduleScript(ctx context.Context, root string, kind Kind, allow bool) (bool, string, error) {
	script := filepath.Join(root, "scripts", scriptName(kind))
	detail := "bash " + script
	if !allow {
		return false, "planned: " + detail + " (set WARDEN_ALLOW_HOST_UPDATE=1 to run it)", nil
	}
	if st, err := os.Stat(script); err != nil || st.IsDir() {
		return false, detail, fmt.Errorf("maintenance script not found")
	}
	cmd := exec.CommandContext(ctx, "bash", script)
	cmd.Dir = root
	if err := cmd.Start(); err != nil {
		return false, detail, err
	}
	go func() { _ = cmd.Wait() }()
	return true, "scheduled: " + detail, nil
}

func scriptName(kind Kind) string {
	if kind == Packages {
		return "update-packages.sh"
	}
	return "update.sh"
}

func postMaintenance(ctx context.Context, call Call, key string) (int, string, error) {
	payload, _ := json.Marshal(map[string]string{"kind": string(call.Kind)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, call.URL, bytes.NewReader(payload))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Maintenance-Key", key)
	client := &http.Client{Timeout: 20 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	message := strings.TrimSpace(string(raw))
	return res.StatusCode, message, nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
