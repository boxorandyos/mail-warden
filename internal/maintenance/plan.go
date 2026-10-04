package maintenance

import (
	"crypto/subtle"
	"fmt"
	"net"
	"net/url"
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
}

type Call struct {
	Name string
	URL  string
	Kind Kind
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
		calls = append(calls, Call{Name: node.Name, URL: target, Kind: kind})
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
