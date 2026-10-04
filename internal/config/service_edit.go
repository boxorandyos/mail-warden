package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type ServiceSecrets struct {
	PostgresDSN            string `json:"postgres_dsn,omitempty"`
	AccessSecret           string `json:"access_secret,omitempty"`
	RefreshSecret          string `json:"refresh_secret,omitempty"`
	BootstrapAdminPassword string `json:"bootstrap_admin_password,omitempty"`
	OIDCClientSecret       string `json:"oidc_client_secret,omitempty"`
	LDAPBindPassword       string `json:"ldap_bind_password,omitempty"`
	SandboxAPIKey          string `json:"sandbox_api_key,omitempty"`
	SIEMBearerToken        string `json:"siem_bearer_token,omitempty"`
}

type ServiceView struct {
	Service struct {
		Listen string `json:"listen"`
		Mode   string `json:"mode"`
	} `json:"service"`
	Defaults struct {
		OrganizationID int64  `json:"organization_id"`
		Organization   string `json:"organization_name"`
	} `json:"defaults"`
	Exchange struct {
		SmartHost            string `json:"smart_host"`
		ReceiveConnectorName string `json:"receive_connector_name"`
	} `json:"exchange"`
	Stores struct {
		PostgresDSNSet bool   `json:"postgres_dsn_set"`
		RedisAddr      string `json:"redis_addr"`
	} `json:"stores"`
	Rspamd struct {
		Endpoint       string `json:"endpoint"`
		TimeoutSeconds int    `json:"timeout_seconds"`
	} `json:"rspamd"`
	Sandbox struct {
		Enabled         bool   `json:"enabled"`
		Endpoint        string `json:"endpoint"`
		APIKeySet       bool   `json:"api_key_set"`
		TimeoutSeconds  int    `json:"timeout_seconds"`
		MinSuspicionHit int    `json:"min_suspicion_hit"`
	} `json:"sandbox"`
	SIEM struct {
		Enabled        bool   `json:"enabled"`
		WebhookURL     string `json:"webhook_url"`
		BearerTokenSet bool   `json:"bearer_token_set"`
		TimeoutSeconds int    `json:"timeout_seconds"`
	} `json:"siem"`
	SMTP struct {
		PolicyListen string `json:"policy_listen"`
	} `json:"smtp"`
	Auth struct {
		AccessSecretSet        bool   `json:"access_secret_set"`
		RefreshSecretSet       bool   `json:"refresh_secret_set"`
		AccessTTLMinutes       int    `json:"access_ttl_minutes"`
		RefreshTTLHours        int    `json:"refresh_ttl_hours"`
		BootstrapAdminUser     string `json:"bootstrap_admin_user"`
		BootstrapAdminEmail    string `json:"bootstrap_admin_email"`
		BootstrapAdminFullName string `json:"bootstrap_admin_full_name"`
		BootstrapPasswordSet   bool   `json:"bootstrap_admin_password_set"`
		OIDC                   struct {
			Enabled         bool   `json:"enabled"`
			Issuer          string `json:"issuer"`
			ClientID        string `json:"client_id"`
			ClientSecretSet bool   `json:"client_secret_set"`
			RedirectURL     string `json:"redirect_url"`
			Scopes          string `json:"scopes"`
			EmailClaim      string `json:"email_claim"`
			NameClaim       string `json:"name_claim"`
			GroupsClaim     string `json:"groups_claim"`
		} `json:"oidc"`
	} `json:"auth"`
	LDAP struct {
		Enabled               bool              `json:"enabled"`
		URL                   string            `json:"url"`
		BindDN                string            `json:"bind_dn"`
		BindPasswordSet       bool              `json:"bind_password_set"`
		SearchBase            string            `json:"search_base"`
		SearchFilter          string            `json:"search_filter"`
		EmailAttr             string            `json:"email_attr"`
		NameAttr              string            `json:"name_attr"`
		GroupBase             string            `json:"group_base"`
		GroupFilter           string            `json:"group_filter"`
		GroupNameAttr         string            `json:"group_name_attr"`
		StartTLS              bool              `json:"start_tls"`
		TLSRejectUnauthorized bool              `json:"tls_reject_unauthorized"`
		DefaultRole           string            `json:"default_role"`
		RoleMap               map[string]string `json:"role_map"`
	} `json:"ldap"`
	Portal struct {
		PublicURL string   `json:"public_url"`
		Origins   []string `json:"origins"`
	} `json:"portal"`
}

type ServicePut struct {
	Service struct {
		Listen string `json:"listen"`
		Mode   string `json:"mode"`
	} `json:"service"`
	Defaults struct {
		OrganizationID int64  `json:"organization_id"`
		Organization   string `json:"organization_name"`
	} `json:"defaults"`
	Exchange struct {
		SmartHost            string `json:"smart_host"`
		ReceiveConnectorName string `json:"receive_connector_name"`
	} `json:"exchange"`
	Stores struct {
		RedisAddr string `json:"redis_addr"`
	} `json:"stores"`
	Rspamd struct {
		Endpoint       string `json:"endpoint"`
		TimeoutSeconds int    `json:"timeout_seconds"`
	} `json:"rspamd"`
	Sandbox struct {
		Enabled         bool   `json:"enabled"`
		Endpoint        string `json:"endpoint"`
		TimeoutSeconds  int    `json:"timeout_seconds"`
		MinSuspicionHit int    `json:"min_suspicion_hit"`
	} `json:"sandbox"`
	SIEM struct {
		Enabled        bool   `json:"enabled"`
		WebhookURL     string `json:"webhook_url"`
		TimeoutSeconds int    `json:"timeout_seconds"`
	} `json:"siem"`
	SMTP struct {
		PolicyListen string `json:"policy_listen"`
	} `json:"smtp"`
	Auth struct {
		AccessTTLMinutes       int    `json:"access_ttl_minutes"`
		RefreshTTLHours        int    `json:"refresh_ttl_hours"`
		BootstrapAdminUser     string `json:"bootstrap_admin_user"`
		BootstrapAdminEmail    string `json:"bootstrap_admin_email"`
		BootstrapAdminFullName string `json:"bootstrap_admin_full_name"`
		OIDC                   struct {
			Enabled     bool   `json:"enabled"`
			Issuer      string `json:"issuer"`
			ClientID    string `json:"client_id"`
			RedirectURL string `json:"redirect_url"`
			Scopes      string `json:"scopes"`
			EmailClaim  string `json:"email_claim"`
			NameClaim   string `json:"name_claim"`
			GroupsClaim string `json:"groups_claim"`
		} `json:"oidc"`
	} `json:"auth"`
	LDAP struct {
		Enabled               bool              `json:"enabled"`
		URL                   string            `json:"url"`
		BindDN                string            `json:"bind_dn"`
		SearchBase            string            `json:"search_base"`
		SearchFilter          string            `json:"search_filter"`
		EmailAttr             string            `json:"email_attr"`
		NameAttr              string            `json:"name_attr"`
		GroupBase             string            `json:"group_base"`
		GroupFilter           string            `json:"group_filter"`
		GroupNameAttr         string            `json:"group_name_attr"`
		StartTLS              bool              `json:"start_tls"`
		TLSRejectUnauthorized bool              `json:"tls_reject_unauthorized"`
		DefaultRole           string            `json:"default_role"`
		RoleMap               map[string]string `json:"role_map"`
	} `json:"ldap"`
	Portal struct {
		PublicURL string   `json:"public_url"`
		Origins   []string `json:"origins"`
	} `json:"portal"`
	Secrets ServiceSecrets `json:"secrets"`
}

func (cfg ServiceConfig) PublicView() ServiceView {
	var view ServiceView
	view.Service.Listen = cfg.Service.Listen
	view.Service.Mode = cfg.Service.Mode
	view.Defaults.OrganizationID = cfg.Defaults.OrganizationID
	view.Defaults.Organization = cfg.Defaults.Organization
	view.Exchange.SmartHost = cfg.Exchange.SmartHost
	view.Exchange.ReceiveConnectorName = cfg.Exchange.ReceiveConnectorName
	view.Stores.PostgresDSNSet = strings.TrimSpace(cfg.Stores.PostgresDSN) != ""
	view.Stores.RedisAddr = cfg.Stores.RedisAddr
	view.Rspamd.Endpoint = cfg.Rspamd.Endpoint
	view.Rspamd.TimeoutSeconds = cfg.Rspamd.TimeoutSeconds
	view.Sandbox.Enabled = cfg.Sandbox.Enabled
	view.Sandbox.Endpoint = cfg.Sandbox.Endpoint
	view.Sandbox.APIKeySet = strings.TrimSpace(cfg.Sandbox.APIKey) != ""
	view.Sandbox.TimeoutSeconds = cfg.Sandbox.TimeoutSeconds
	view.Sandbox.MinSuspicionHit = cfg.Sandbox.MinSuspicionHit
	view.SIEM.Enabled = cfg.SIEM.Enabled
	view.SIEM.WebhookURL = cfg.SIEM.WebhookURL
	view.SIEM.BearerTokenSet = strings.TrimSpace(cfg.SIEM.BearerToken) != ""
	view.SIEM.TimeoutSeconds = cfg.SIEM.TimeoutSeconds
	view.SMTP.PolicyListen = cfg.SMTP.PolicyListen
	view.Auth.AccessSecretSet = strings.TrimSpace(cfg.Auth.AccessSecret) != ""
	view.Auth.RefreshSecretSet = strings.TrimSpace(cfg.Auth.RefreshSecret) != ""
	view.Auth.AccessTTLMinutes = cfg.Auth.AccessTTLMinutes
	view.Auth.RefreshTTLHours = cfg.Auth.RefreshTTLHours
	view.Auth.BootstrapAdminUser = cfg.Auth.BootstrapAdminUser
	view.Auth.BootstrapAdminEmail = cfg.Auth.BootstrapAdminEmail
	view.Auth.BootstrapAdminFullName = cfg.Auth.BootstrapAdminFullName
	view.Auth.BootstrapPasswordSet = strings.TrimSpace(cfg.Auth.BootstrapAdminPassword) != ""
	view.Auth.OIDC.Enabled = cfg.Auth.OIDC.Enabled
	view.Auth.OIDC.Issuer = cfg.Auth.OIDC.Issuer
	view.Auth.OIDC.ClientID = cfg.Auth.OIDC.ClientID
	view.Auth.OIDC.ClientSecretSet = strings.TrimSpace(cfg.Auth.OIDC.ClientSecret) != ""
	view.Auth.OIDC.RedirectURL = cfg.Auth.OIDC.RedirectURL
	view.Auth.OIDC.Scopes = cfg.Auth.OIDC.Scopes
	view.Auth.OIDC.EmailClaim = cfg.Auth.OIDC.EmailClaim
	view.Auth.OIDC.NameClaim = cfg.Auth.OIDC.NameClaim
	view.Auth.OIDC.GroupsClaim = cfg.Auth.OIDC.GroupsClaim
	view.LDAP.Enabled = cfg.LDAP.Enabled
	view.LDAP.URL = cfg.LDAP.URL
	view.LDAP.BindDN = cfg.LDAP.BindDN
	view.LDAP.BindPasswordSet = strings.TrimSpace(cfg.LDAP.BindPassword) != ""
	view.LDAP.SearchBase = cfg.LDAP.SearchBase
	view.LDAP.SearchFilter = cfg.LDAP.SearchFilter
	view.LDAP.EmailAttr = cfg.LDAP.EmailAttr
	view.LDAP.NameAttr = cfg.LDAP.NameAttr
	view.LDAP.GroupBase = cfg.LDAP.GroupBase
	view.LDAP.GroupFilter = cfg.LDAP.GroupFilter
	view.LDAP.GroupNameAttr = cfg.LDAP.GroupNameAttr
	view.LDAP.StartTLS = cfg.LDAP.StartTLS
	view.LDAP.TLSRejectUnauthorized = cfg.LDAP.TLSRejectUnauthorized
	view.LDAP.DefaultRole = cfg.LDAP.DefaultRole
	view.LDAP.RoleMap = cfg.LDAP.RoleMap
	view.Portal.PublicURL = cfg.Portal.PublicURL
	view.Portal.Origins = append([]string(nil), cfg.Portal.Origins...)
	return view
}

func MergeServicePut(current ServiceConfig, put ServicePut) (ServiceConfig, []string) {
	next := current
	var restart []string
	note := func(field string) {
		restart = append(restart, field)
	}
	if put.Service.Listen != "" && put.Service.Listen != current.Service.Listen {
		next.Service.Listen = put.Service.Listen
		note("service.listen")
	}
	if put.Service.Mode != "" && put.Service.Mode != current.Service.Mode {
		next.Service.Mode = put.Service.Mode
		note("service.mode")
	}
	if put.Defaults.OrganizationID > 0 && put.Defaults.OrganizationID != current.Defaults.OrganizationID {
		next.Defaults.OrganizationID = put.Defaults.OrganizationID
		note("defaults.organization_id")
	}
	if strings.TrimSpace(put.Defaults.Organization) != "" {
		next.Defaults.Organization = strings.TrimSpace(put.Defaults.Organization)
	}
	next.Exchange.SmartHost = put.Exchange.SmartHost
	next.Exchange.ReceiveConnectorName = put.Exchange.ReceiveConnectorName
	if put.Exchange.SmartHost != current.Exchange.SmartHost {
		note("exchange.smart_host")
	}
	if put.Stores.RedisAddr != current.Stores.RedisAddr {
		next.Stores.RedisAddr = put.Stores.RedisAddr
		note("stores.redis_addr")
	}
	next.Rspamd.Endpoint = strings.TrimSpace(put.Rspamd.Endpoint)
	if put.Rspamd.TimeoutSeconds > 0 {
		next.Rspamd.TimeoutSeconds = put.Rspamd.TimeoutSeconds
	}
	next.Sandbox.Enabled = put.Sandbox.Enabled
	next.Sandbox.Endpoint = strings.TrimSpace(put.Sandbox.Endpoint)
	if put.Sandbox.TimeoutSeconds > 0 {
		next.Sandbox.TimeoutSeconds = put.Sandbox.TimeoutSeconds
	}
	if put.Sandbox.MinSuspicionHit > 0 {
		next.Sandbox.MinSuspicionHit = put.Sandbox.MinSuspicionHit
	}
	next.SIEM.Enabled = put.SIEM.Enabled
	next.SIEM.WebhookURL = strings.TrimSpace(put.SIEM.WebhookURL)
	if put.SIEM.TimeoutSeconds > 0 {
		next.SIEM.TimeoutSeconds = put.SIEM.TimeoutSeconds
	}
	if strings.TrimSpace(put.SMTP.PolicyListen) != "" && put.SMTP.PolicyListen != current.SMTP.PolicyListen {
		next.SMTP.PolicyListen = strings.TrimSpace(put.SMTP.PolicyListen)
		note("smtp.policy_listen")
	}
	if put.Auth.AccessTTLMinutes > 0 {
		next.Auth.AccessTTLMinutes = put.Auth.AccessTTLMinutes
	}
	if put.Auth.RefreshTTLHours > 0 {
		next.Auth.RefreshTTLHours = put.Auth.RefreshTTLHours
	}
	if strings.TrimSpace(put.Auth.BootstrapAdminUser) != "" {
		next.Auth.BootstrapAdminUser = strings.TrimSpace(put.Auth.BootstrapAdminUser)
	}
	if strings.TrimSpace(put.Auth.BootstrapAdminEmail) != "" {
		next.Auth.BootstrapAdminEmail = strings.TrimSpace(put.Auth.BootstrapAdminEmail)
	}
	if strings.TrimSpace(put.Auth.BootstrapAdminFullName) != "" {
		next.Auth.BootstrapAdminFullName = strings.TrimSpace(put.Auth.BootstrapAdminFullName)
	}
	next.Auth.OIDC.Enabled = put.Auth.OIDC.Enabled
	next.Auth.OIDC.Issuer = strings.TrimSpace(put.Auth.OIDC.Issuer)
	next.Auth.OIDC.ClientID = strings.TrimSpace(put.Auth.OIDC.ClientID)
	next.Auth.OIDC.RedirectURL = strings.TrimSpace(put.Auth.OIDC.RedirectURL)
	if strings.TrimSpace(put.Auth.OIDC.Scopes) != "" {
		next.Auth.OIDC.Scopes = strings.TrimSpace(put.Auth.OIDC.Scopes)
	}
	if strings.TrimSpace(put.Auth.OIDC.EmailClaim) != "" {
		next.Auth.OIDC.EmailClaim = strings.TrimSpace(put.Auth.OIDC.EmailClaim)
	}
	if strings.TrimSpace(put.Auth.OIDC.NameClaim) != "" {
		next.Auth.OIDC.NameClaim = strings.TrimSpace(put.Auth.OIDC.NameClaim)
	}
	if strings.TrimSpace(put.Auth.OIDC.GroupsClaim) != "" {
		next.Auth.OIDC.GroupsClaim = strings.TrimSpace(put.Auth.OIDC.GroupsClaim)
	}
	next.LDAP.Enabled = put.LDAP.Enabled
	next.LDAP.URL = strings.TrimSpace(put.LDAP.URL)
	next.LDAP.BindDN = strings.TrimSpace(put.LDAP.BindDN)
	next.LDAP.SearchBase = strings.TrimSpace(put.LDAP.SearchBase)
	next.LDAP.SearchFilter = strings.TrimSpace(put.LDAP.SearchFilter)
	next.LDAP.EmailAttr = strings.TrimSpace(put.LDAP.EmailAttr)
	next.LDAP.NameAttr = strings.TrimSpace(put.LDAP.NameAttr)
	next.LDAP.GroupBase = strings.TrimSpace(put.LDAP.GroupBase)
	next.LDAP.GroupFilter = strings.TrimSpace(put.LDAP.GroupFilter)
	next.LDAP.GroupNameAttr = strings.TrimSpace(put.LDAP.GroupNameAttr)
	next.LDAP.StartTLS = put.LDAP.StartTLS
	next.LDAP.TLSRejectUnauthorized = put.LDAP.TLSRejectUnauthorized
	if strings.TrimSpace(put.LDAP.DefaultRole) != "" {
		next.LDAP.DefaultRole = strings.TrimSpace(put.LDAP.DefaultRole)
	}
	if put.LDAP.RoleMap != nil {
		next.LDAP.RoleMap = put.LDAP.RoleMap
	}
	if strings.TrimSpace(put.Portal.PublicURL) != "" {
		next.Portal.PublicURL = strings.TrimSpace(put.Portal.PublicURL)
	}
	if put.Portal.Origins != nil {
		next.Portal.Origins = compactOrigins(put.Portal.Origins)
	}
	applySecret := func(field string, current *string, incoming string) {
		incoming = strings.TrimSpace(incoming)
		if incoming == "" || incoming == "********" {
			return
		}
		if *current != incoming {
			*current = incoming
			note(field)
		}
	}
	applySecret("stores.postgres_dsn", &next.Stores.PostgresDSN, put.Secrets.PostgresDSN)
	applySecret("auth.access_secret", &next.Auth.AccessSecret, put.Secrets.AccessSecret)
	applySecret("auth.refresh_secret", &next.Auth.RefreshSecret, put.Secrets.RefreshSecret)
	if pw := strings.TrimSpace(put.Secrets.BootstrapAdminPassword); pw != "" && pw != "********" && pw != next.Auth.BootstrapAdminPassword {
		next.Auth.BootstrapAdminPassword = pw
		note("auth.bootstrap_admin_password")
	}
	if secret := strings.TrimSpace(put.Secrets.OIDCClientSecret); secret != "" && secret != "********" {
		next.Auth.OIDC.ClientSecret = secret
	}
	if secret := strings.TrimSpace(put.Secrets.LDAPBindPassword); secret != "" && secret != "********" {
		next.LDAP.BindPassword = secret
	}
	if secret := strings.TrimSpace(put.Secrets.SandboxAPIKey); secret != "" && secret != "********" {
		next.Sandbox.APIKey = secret
	}
	if secret := strings.TrimSpace(put.Secrets.SIEMBearerToken); secret != "" && secret != "********" {
		next.SIEM.BearerToken = secret
	}
	return next, restart
}

func compactOrigins(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, raw := range in {
		origin := strings.TrimRight(strings.TrimSpace(raw), "/")
		if origin == "" {
			continue
		}
		if _, ok := seen[origin]; ok {
			continue
		}
		seen[origin] = struct{}{}
		out = append(out, origin)
	}
	return out
}

func SaveServiceConfig(path string, cfg ServiceConfig) error {
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal service config: %w", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("write service config: %w", err)
	}
	return nil
}
