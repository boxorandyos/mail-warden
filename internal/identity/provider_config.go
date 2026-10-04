package identity

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
)

type LDAPConfig struct {
	URL                   string
	BindDN                string
	BindPassword          string
	SearchBase            string
	SearchFilter          string
	EmailAttr             string
	NameAttr              string
	GroupBase             string
	GroupFilter           string
	GroupNameAttr         string
	StartTLS              bool
	TLSRejectUnauthorized bool
	RoleMap               map[string]Role
	DefaultRole           Role
}

func ValidateLDAPConfig(raw LDAPConfig) (LDAPConfig, error) {
	if strings.TrimSpace(raw.URL) == "" {
		return LDAPConfig{}, errors.New("ldap url is required")
	}
	url := strings.ToLower(strings.TrimSpace(raw.URL))
	if !strings.HasPrefix(url, "ldap://") && !strings.HasPrefix(url, "ldaps://") {
		return LDAPConfig{}, errors.New("ldap url must start with ldap:// or ldaps://")
	}
	if strings.HasPrefix(url, "ldap://") && !raw.StartTLS {
		return LDAPConfig{}, errors.New("ldap:// requires starttls=true, or use ldaps://")
	}
	if strings.TrimSpace(raw.SearchBase) == "" {
		return LDAPConfig{}, errors.New("ldap search_base is required")
	}
	if strings.TrimSpace(raw.SearchFilter) == "" {
		raw.SearchFilter = "(uid={{username}})"
	}
	if !strings.Contains(raw.SearchFilter, "{{username}}") {
		return LDAPConfig{}, errors.New("ldap search_filter must include {{username}}")
	}
	if raw.EmailAttr == "" {
		raw.EmailAttr = "mail"
	}
	if raw.NameAttr == "" {
		raw.NameAttr = "cn"
	}
	if raw.GroupNameAttr == "" {
		raw.GroupNameAttr = "cn"
	}
	if raw.DefaultRole == "" {
		raw.DefaultRole = RoleViewer
	}
	raw.URL = strings.TrimSpace(raw.URL)
	raw.SearchBase = strings.TrimSpace(raw.SearchBase)
	raw.SearchFilter = strings.TrimSpace(raw.SearchFilter)
	return raw, nil
}

func EscapeLDAPFilterValue(value string) string {
	replacer := strings.NewReplacer(
		`\\`, `\5c`,
		`*`, `\2a`,
		`(`, `\28`,
		`)`, `\29`,
		string(rune(0)), `\00`,
	)
	return replacer.Replace(value)
}

func MapGroupsToRole(groups []string, roleMap map[string]Role, defaultRole Role) Role {
	if len(roleMap) == 0 {
		return defaultRole
	}
	lower := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		lower[strings.ToLower(strings.TrimSpace(g))] = struct{}{}
	}
	order := []Role{RoleAdmin, RoleModerator, RoleViewer}
	for _, candidate := range order {
		for groupName, mapped := range roleMap {
			if mapped != candidate {
				continue
			}
			if _, ok := lower[strings.ToLower(groupName)]; ok {
				return candidate
			}
		}
	}
	return defaultRole
}

func ParseRole(v string) (Role, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "admin":
		return RoleAdmin, nil
	case "moderator":
		return RoleModerator, nil
	case "viewer":
		return RoleViewer, nil
	default:
		return "", fmt.Errorf("invalid role: %q", v)
	}
}

func ParseProviderType(v string) (ProviderType, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case string(ProviderTypeLocal):
		return ProviderTypeLocal, nil
	case string(ProviderTypeLDAP):
		return ProviderTypeLDAP, nil
	case string(ProviderTypeOIDC):
		return ProviderTypeOIDC, nil
	default:
		return "", fmt.Errorf("invalid provider type: %q", v)
	}
}

func ValidateProviderInput(in Provider) (Provider, error) {
	out := in
	pType, err := ParseProviderType(string(out.Type))
	if err != nil {
		return Provider{}, err
	}
	out.Type = pType
	out.Name = strings.TrimSpace(out.Name)
	if out.Name == "" {
		out.Name = string(out.Type)
	}
	if out.Priority < 0 || out.Priority > 1000 {
		return Provider{}, errors.New("provider priority must be between 0 and 1000")
	}
	if out.Config == nil {
		out.Config = map[string]any{}
	}
	out.Config = normalizedConfigMap(out.Config)
	if err := validateProviderConfigByType(out.Type, out.Config); err != nil {
		return Provider{}, err
	}
	return out, nil
}

func validateProviderConfigByType(t ProviderType, cfg map[string]any) error {
	requireKeys := func(keys []string) error {
		for _, key := range keys {
			value, ok := cfg[key]
			if !ok || strings.TrimSpace(providerValueToString(value)) == "" || strings.EqualFold(strings.TrimSpace(providerValueToString(value)), "<nil>") {
				return fmt.Errorf("%s provider requires config.%s", t, key)
			}
		}
		return nil
	}
	switch t {
	case ProviderTypeLocal:
		return nil
	case ProviderTypeLDAP:
		return requireKeys([]string{"url", "search_base", "search_filter"})
	case ProviderTypeOIDC:
		return requireKeys([]string{"issuer", "client_id", "redirect_url"})
	default:
		return fmt.Errorf("unsupported provider type: %s", t)
	}
}

func normalizedConfigMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for _, key := range sortedKeys(in) {
		normalizedKey := strings.TrimSpace(key)
		if normalizedKey == "" {
			continue
		}
		out[normalizedKey] = in[key]
	}
	return out
}

func sortedKeys(m map[string]any) []string {
	keys := slices.Collect(maps.Keys(m))
	slices.Sort(keys)
	return keys
}

func providerValueToString(v any) string {
	switch vv := v.(type) {
	case string:
		return vv
	default:
		return fmt.Sprint(v)
	}
}
