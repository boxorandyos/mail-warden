package platform

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	TokenPrefix = "mw_"
)

var AlertKinds = []string{"availability", "backup_age", "node_stale", "job_failed"}
var PolicyKinds = []string{"require_mfa", "backup_max_age", "node_heartbeat_max_age"}

type Environment struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"createdAt"`
}

type Account struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Role          string    `json:"role"`
	EnvironmentID string    `json:"environmentId"`
	CreatedAt     time.Time `json:"createdAt"`
	Token         string    `json:"token,omitempty"`
	TokenHash     string    `json:"-"`
}

type Job struct {
	ID         string     `json:"id"`
	Type       string     `json:"type"`
	Status     string     `json:"status"`
	Actor      string     `json:"actor"`
	Error      string     `json:"error,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
}

type Runbook struct {
	ID            string    `json:"id"`
	EnvironmentID string    `json:"environmentId"`
	Title         string    `json:"title"`
	Body          string    `json:"body"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

type Rule struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	Threshold     int    `json:"threshold"`
	Enabled       bool   `json:"enabled"`
	EnvironmentID string `json:"environmentId"`
}

type Policy struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	Threshold     *int   `json:"threshold"`
	Enabled       bool   `json:"enabled"`
	EnvironmentID string `json:"environmentId"`
}

type Snapshot struct {
	ID        string    `json:"id"`
	Actor     string    `json:"actor"`
	CreatedAt time.Time `json:"createdAt"`
	Body      Document  `json:"-"`
}

type Document struct {
	Environments []Environment `json:"environments"`
	Runbooks     []Runbook     `json:"runbooks"`
	AlertRules   []Rule        `json:"alertRules"`
	Policies     []Policy      `json:"policies"`
}

type Signals struct {
	AdminsWithoutMFA []string
	NewestBackupAt   *time.Time
	Nodes            []NodeSignal
	FailedJobs       int
}

type NodeSignal struct {
	ID         string
	Name       string
	LastSeenAt *time.Time
}

type Violation struct {
	PolicyID   string `json:"policyId"`
	PolicyName string `json:"policyName"`
	ResourceID string `json:"resourceId"`
	Detail     string `json:"detail"`
}

type AuditRow struct {
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Detail    string    `json:"detail"`
	CreatedAt time.Time `json:"createdAt"`
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func NewToken() (string, string) {
	token := TokenPrefix + strings.ReplaceAll(uuid.NewString(), "-", "") + strings.ReplaceAll(uuid.NewString(), "-", "")
	return token[:3+48], HashToken(token[:3+48])
}

func Evaluate(policies []Policy, signals Signals, now time.Time) []Violation {
	out := make([]Violation, 0)
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}
		switch policy.Kind {
		case "require_mfa":
			for _, name := range signals.AdminsWithoutMFA {
				out = append(out, Violation{PolicyID: policy.ID, PolicyName: policy.Name, ResourceID: name, Detail: "admin " + name + " has MFA disabled"})
			}
		case "backup_max_age":
			limit := 24
			if policy.Threshold != nil {
				limit = *policy.Threshold
			}
			if signals.NewestBackupAt == nil || now.Sub(*signals.NewestBackupAt) > time.Duration(limit)*time.Hour {
				detail := "no successful backup"
				if signals.NewestBackupAt != nil {
					detail = fmt.Sprintf("newest backup is %.1fh old", now.Sub(*signals.NewestBackupAt).Hours())
				}
				out = append(out, Violation{PolicyID: policy.ID, PolicyName: policy.Name, ResourceID: "fleet", Detail: detail})
			}
		case "node_heartbeat_max_age":
			limit := 120
			if policy.Threshold != nil {
				limit = *policy.Threshold
			}
			for _, node := range signals.Nodes {
				stale := node.LastSeenAt == nil || now.Sub(*node.LastSeenAt) > time.Duration(limit)*time.Second
				if stale {
					out = append(out, Violation{PolicyID: policy.ID, PolicyName: policy.Name, ResourceID: node.ID, Detail: node.Name + " heartbeat is stale"})
				}
			}
		}
	}
	return out
}

func Prometheus(jobs map[string]int, nodes, rules int) string {
	var b strings.Builder
	b.WriteString("# HELP warden_up Mail Warden is serving.\n# TYPE warden_up gauge\nwarden_up 1\n")
	b.WriteString("# HELP warden_nodes Cluster nodes.\n# TYPE warden_nodes gauge\n")
	fmt.Fprintf(&b, "warden_nodes %d\n", nodes)
	b.WriteString("# HELP warden_alert_rules Platform alert rules.\n# TYPE warden_alert_rules gauge\n")
	fmt.Fprintf(&b, "warden_alert_rules %d\n", rules)
	b.WriteString("# HELP warden_jobs Platform jobs by status.\n# TYPE warden_jobs gauge\n")
	for _, status := range []string{"succeeded", "failed", "running"} {
		fmt.Fprintf(&b, "warden_jobs{status=%q} %d\n", status, jobs[status])
	}
	return b.String()
}

func TailLog(path string, maxLines int) (string, bool) {
	if path == "" {
		return "", false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	lines := strings.Split(string(raw), "\n")
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return strings.Join(lines, "\n"), true
}

func ExportCSV(rows []AuditRow) string {
	var b strings.Builder
	b.WriteString("actor,action,detail,createdAt\n")
	for _, row := range rows {
		fmt.Fprintf(&b, "%q,%q,%q,%q\n", row.Actor, row.Action, row.Detail, row.CreatedAt.Format(time.RFC3339))
	}
	return b.String()
}

func MustJSON(value any) []byte {
	raw, _ := json.Marshal(value)
	return raw
}
