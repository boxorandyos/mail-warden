package maintenance

import (
	"crypto/subtle"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

type Kind string

const (
	Product  Kind = "product"
	Packages Kind = "packages"
)

var PackageAllowlist = []string{
	"postfix",
	"postfix-pcre",
	"rspamd",
	"redis-server",
	"ca-certificates",
	"openssl",
}

type Node struct {
	Name    string
	Address string
	Role    string
	Key     string
}

type Call struct {
	Name string
	URL  string
	Kind Kind
	Key  string
}

func HostUpdateAllowed(productDefault bool) bool {
	switch os.Getenv("WARDEN_ALLOW_HOST_UPDATE") {
	case "1":
		return true
	case "0":
		return false
	default:
		return productDefault
	}
}

type RuntimeSpec struct {
	Script  string
	Args    []string
	Confirm string
}

func RuntimeSpecFor(component string) (RuntimeSpec, error) {
	switch strings.TrimSpace(component) {
	case "postgres":
		return RuntimeSpec{Script: "upgrade-postgres.sh", Args: []string{"18"}, Confirm: "UPGRADE_POSTGRES_CONFIRM"}, nil
	case "redis":
		return RuntimeSpec{Script: "upgrade-redis.sh", Args: []string{"8"}, Confirm: "UPGRADE_REDIS_CONFIRM"}, nil
	case "go":
		return RuntimeSpec{Script: "upgrade-go.sh", Args: []string{"1.27.0"}, Confirm: "UPGRADE_GO_CONFIRM"}, nil
	default:
		return RuntimeSpec{}, fmt.Errorf("component must be postgres, redis, or go")
	}
}

func PlanRuntime(component string, allow bool) (bool, string, error) {
	spec, err := RuntimeSpecFor(component)
	if err != nil {
		return false, "", err
	}
	detail := "bash scripts/" + spec.Script
	if len(spec.Args) > 0 {
		detail += " " + strings.Join(spec.Args, " ")
	}
	if !allow {
		return false, "planned: " + detail + " (set MAIL_ALLOW_HOST_UPDATE=1 to run it)", nil
	}
	return true, "scheduled: " + detail, nil
}

func RuntimeCatalog() []map[string]any {
	return []map[string]any{
		{"id": "postgres", "newInstall": "18", "latestLts": "18", "note": "Set POSTGRES_IMAGE=postgres:18 for a new volume. The console copies an existing database beside the live one.", "canRun": true},
		{"id": "redis", "newInstall": "8.2", "latestLts": "8.2", "note": "Redis 8.2 is the current line with support through 2030. A new volume uses it when REDIS_IMAGE=redis:8.2. An existing volume stays on Redis 7 until the console copies it.", "canRun": true},
		{"id": "go", "newInstall": "1.27", "latestLts": "1.27", "note": "New image builds use golang:1.27. The console installs that toolchain on a host that still has an older Go.", "canRun": true},
		{"id": "rspamd", "newInstall": "4.2", "latestLts": "4.2", "note": "A new stack sets RSPAMD_IMAGE=rspamd/rspamd:4.2. The shipped default stays 3.10 so an existing container is not replaced on compose up.", "canRun": false},
	}
}

func ParseKind(value string) (Kind, error) {
	switch Kind(strings.TrimSpace(value)) {
	case Product:
		return Product, nil
	case Packages:
		return Packages, nil
	default:
		return "", fmt.Errorf("kind must be product or packages")
	}
}

func KeyMatches(expected, presented string) bool {
	if expected == "" || presented == "" {
		return false
	}
	if len(expected) != len(presented) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(presented)) == 1
}

func IsSecondary(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "secondary", "slave", "standby", "backup", "replica":
		return true
	default:
		return false
	}
}

func IsPrimary(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "", "primary", "master", "active":
		return true
	default:
		return false
	}
}

func PlanSlaveUpgrades(role string, nodes []Node, kind Kind) ([]Call, error) {
	if !IsPrimary(role) {
		return nil, fmt.Errorf("only a primary node can trigger slave upgrades")
	}
	calls := make([]Call, 0)
	for _, node := range nodes {
		if !IsSecondary(node.Role) {
			continue
		}
		target, err := maintenanceURL(node.Address)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", node.Name, err)
		}
		calls = append(calls, Call{Name: node.Name, URL: target, Kind: kind, Key: node.Key})
	}
	return calls, nil
}

func maintenanceURL(address string) (string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return "", fmt.Errorf("address must be host:port")
	}
	if host == "" || strings.ContainsAny(host, "/\\@ ") {
		return "", fmt.Errorf("invalid host")
	}
	u := url.URL{Scheme: "http", Host: net.JoinHostPort(host, port), Path: "/api/v1/maintenance/apply"}
	return u.String(), nil
}
