package platform

import (
	"fmt"
	"strings"
	"time"
)

type Memory struct {
	Environments []Environment
	Accounts     []Account
	Jobs         []Job
	Runbooks     []Runbook
	Rules        []Rule
	Policies     []Policy
	Snapshots    []Snapshot
	Signals      Signals
	Audit        []AuditRow
}

func NewMemory() *Memory {
	store := &Memory{}
	store.Seed()
	return store
}

func (m *Memory) Seed() {
	if len(m.Environments) == 0 {
		m.Environments = append(m.Environments, Environment{ID: "env-default", Name: "default", Description: "Initial environment", CreatedAt: time.Now().UTC()})
	}
	m.ensureRule("Availability", "availability", 1)
	m.ensureRule("Backup age", "backup_age", 24)
	m.ensureRule("Node heartbeat", "node_stale", 120)
	m.ensureRule("Failed jobs", "job_failed", 0)
	day := 24
	heartbeat := 120
	m.ensurePolicy("Require MFA", "require_mfa", nil)
	m.ensurePolicy("Backup maximum age", "backup_max_age", &day)
	m.ensurePolicy("Node heartbeat age", "node_heartbeat_max_age", &heartbeat)
}

func (m *Memory) CreateEnvironment(name, description string) (Environment, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Environment{}, fmt.Errorf("name is required")
	}
	for _, item := range m.Environments {
		if item.Name == name {
			return Environment{}, fmt.Errorf("environment already exists")
		}
	}
	item := Environment{ID: "env-" + name, Name: name, Description: description, CreatedAt: time.Now().UTC()}
	m.Environments = append(m.Environments, item)
	return item, nil
}

func (m *Memory) CreateAccount(name, role, environmentID string) (Account, error) {
	if role != "admin" && role != "moderator" && role != "viewer" {
		return Account{}, fmt.Errorf("role must be admin, moderator, or viewer")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return Account{}, fmt.Errorf("name is required")
	}
	token, hash := NewToken()
	item := Account{ID: "acct-" + name, Name: name, Role: role, EnvironmentID: environmentID, CreatedAt: time.Now().UTC(), Token: token, TokenHash: hash}
	m.Accounts = append(m.Accounts, item)
	return item, nil
}

func (m *Memory) PublicAccounts() []Account {
	out := make([]Account, 0, len(m.Accounts))
	for _, item := range m.Accounts {
		item.Token = ""
		item.TokenHash = ""
		out = append(out, item)
	}
	return out
}

func (m *Memory) FindAccount(token string) (Account, bool) {
	hash := HashToken(token)
	for _, item := range m.Accounts {
		if item.TokenHash == hash {
			item.Token = ""
			return item, true
		}
	}
	return Account{}, false
}

func (m *Memory) DeleteAccount(id string) error {
	next := m.Accounts[:0]
	found := false
	for _, item := range m.Accounts {
		if item.ID == id {
			found = true
			continue
		}
		next = append(next, item)
	}
	if !found {
		return fmt.Errorf("service account not found")
	}
	m.Accounts = next
	return nil
}

func (m *Memory) AddRunbook(title, body, environmentID string) (Runbook, error) {
	title = strings.TrimSpace(title)
	if title == "" {
		return Runbook{}, fmt.Errorf("title is required")
	}
	now := time.Now().UTC()
	item := Runbook{ID: "rb-" + title, EnvironmentID: environmentID, Title: title, Body: body, CreatedAt: now, UpdatedAt: now}
	m.Runbooks = append(m.Runbooks, item)
	return item, nil
}

func (m *Memory) SetRuleEnabled(id string, enabled bool) (Rule, error) {
	for i := range m.Rules {
		if m.Rules[i].ID == id {
			m.Rules[i].Enabled = enabled
			return m.Rules[i], nil
		}
	}
	return Rule{}, fmt.Errorf("alert rule not found")
}

func (m *Memory) SetPolicyEnabled(id string, enabled bool) (Policy, error) {
	for i := range m.Policies {
		if m.Policies[i].ID == id {
			m.Policies[i].Enabled = enabled
			return m.Policies[i], nil
		}
	}
	return Policy{}, fmt.Errorf("policy not found")
}

func (m *Memory) Violations(now time.Time) []Violation {
	m.AddJob("policy.evaluate", "operator", "succeeded", "")
	return Evaluate(m.Policies, m.Signals, now)
}

func (m *Memory) AddJob(kind, actor, status, errText string) Job {
	now := time.Now().UTC()
	item := Job{ID: fmt.Sprintf("job-%d", len(m.Jobs)+1), Type: kind, Status: status, Actor: actor, Error: errText, CreatedAt: now, FinishedAt: &now}
	m.Jobs = append(m.Jobs, item)
	return item
}

func (m *Memory) Capture(actor string) Snapshot {
	item := Snapshot{ID: fmt.Sprintf("snap-%d", len(m.Snapshots)+1), Actor: actor, CreatedAt: time.Now().UTC(), Body: m.Document()}
	m.Snapshots = append(m.Snapshots, item)
	m.AddJob("snapshot", actor, "succeeded", "")
	return item
}

func (m *Memory) Apply(id string) error {
	for _, item := range m.Snapshots {
		if item.ID == id {
			m.ApplyDocument(item.Body)
			return nil
		}
	}
	return fmt.Errorf("snapshot not found")
}

func (m *Memory) ApplyDocument(doc Document) {
	if len(doc.Environments) > 0 {
		m.Environments = doc.Environments
	}
	m.Runbooks = doc.Runbooks
	m.Rules = doc.AlertRules
	m.Policies = doc.Policies
}

func (m *Memory) Document() Document {
	return Document{Environments: m.Environments, Runbooks: m.Runbooks, AlertRules: m.Rules, Policies: m.Policies}
}

func (m *Memory) Metrics() map[string]any {
	jobs := map[string]int{}
	for _, job := range m.Jobs {
		jobs[job.Status]++
	}
	return map[string]any{"up": 1, "jobs": jobs, "nodes": len(m.Signals.Nodes), "alertRules": len(m.Rules)}
}

func (m *Memory) ensureRule(name, kind string, threshold int) {
	for _, item := range m.Rules {
		if item.Kind == kind {
			return
		}
	}
	m.Rules = append(m.Rules, Rule{ID: "rule-" + kind, Name: name, Kind: kind, Threshold: threshold, Enabled: true})
}

func (m *Memory) ensurePolicy(name, kind string, threshold *int) {
	for _, item := range m.Policies {
		if item.Kind == kind {
			return
		}
	}
	m.Policies = append(m.Policies, Policy{ID: "policy-" + kind, Name: name, Kind: kind, Threshold: threshold, Enabled: true})
}
