package identity

import (
	"fmt"
	"strings"
)

func LDAPProviderFromMap(cfg map[string]any) (*LDAPProvider, error) {
	roleMap := map[string]Role{}
	if raw, ok := cfg["role_map"].(map[string]any); ok {
		for group, roleRaw := range raw {
			role, err := ParseRole(fmt.Sprint(roleRaw))
			if err != nil {
				return nil, err
			}
			roleMap[group] = role
		}
	}
	defaultRole := RoleViewer
	if v := strings.TrimSpace(providerValueToString(cfg["default_role"])); v != "" {
		parsed, err := ParseRole(v)
		if err != nil {
			return nil, err
		}
		defaultRole = parsed
	}
	return NewLDAPProvider(LDAPConfig{
		URL:                   providerValueToString(cfg["url"]),
		BindDN:                providerValueToString(cfg["bind_dn"]),
		BindPassword:          providerValueToString(cfg["bind_password"]),
		SearchBase:            providerValueToString(cfg["search_base"]),
		SearchFilter:          providerValueToString(cfg["search_filter"]),
		EmailAttr:             providerValueToString(cfg["email_attr"]),
		NameAttr:              providerValueToString(cfg["name_attr"]),
		GroupBase:             providerValueToString(cfg["group_base"]),
		GroupFilter:           providerValueToString(cfg["group_filter"]),
		GroupNameAttr:         providerValueToString(cfg["group_name_attr"]),
		StartTLS:              providerBool(cfg["start_tls"]),
		TLSRejectUnauthorized: providerBoolDefault(cfg["tls_reject_unauthorized"], true),
		RoleMap:               roleMap,
		DefaultRole:           defaultRole,
	})
}

func OIDCConfigFromMap(cfg map[string]any, fallbackRedirect string) (OIDCConfig, error) {
	scopes := strings.Fields(providerValueToString(cfg["scopes"]))
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	redirect := providerValueToString(cfg["redirect_url"])
	if redirect == "" {
		redirect = fallbackRedirect
	}
	roleMap := map[string]Role{}
	if raw, ok := cfg["role_map"].(map[string]any); ok {
		for group, roleRaw := range raw {
			role, err := ParseRole(fmt.Sprint(roleRaw))
			if err != nil {
				return OIDCConfig{}, err
			}
			roleMap[group] = role
		}
	}
	defaultRole := RoleViewer
	if v := strings.TrimSpace(providerValueToString(cfg["default_role"])); v != "" {
		parsed, err := ParseRole(v)
		if err != nil {
			return OIDCConfig{}, err
		}
		defaultRole = parsed
	}
	return OIDCConfig{
		Enabled:      true,
		Issuer:       providerValueToString(cfg["issuer"]),
		ClientID:     providerValueToString(cfg["client_id"]),
		ClientSecret: providerValueToString(cfg["client_secret"]),
		RedirectURL:  redirect,
		Scopes:       scopes,
		EmailClaim:   firstNonEmpty(providerValueToString(cfg["email_claim"]), "email"),
		NameClaim:    firstNonEmpty(providerValueToString(cfg["name_claim"]), "name"),
		GroupsClaim:  firstNonEmpty(providerValueToString(cfg["groups_claim"]), "groups"),
		DefaultRole:  defaultRole,
		RoleMap:      roleMap,
	}, nil
}

func providerBool(v any) bool {
	switch vv := v.(type) {
	case bool:
		return vv
	case string:
		return strings.EqualFold(vv, "true") || vv == "1"
	default:
		return false
	}
}

func providerBoolDefault(v any, fallback bool) bool {
	if v == nil {
		return fallback
	}
	if s, ok := v.(string); ok && strings.TrimSpace(s) == "" {
		return fallback
	}
	return providerBool(v)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
