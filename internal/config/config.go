package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type ServiceConfig struct {
	Service struct {
		Listen string `yaml:"listen"`
		Mode   string `yaml:"mode"`
	} `yaml:"service"`
	Defaults struct {
		OrganizationID int64  `yaml:"organization_id"`
		Organization   string `yaml:"organization_name"`
	} `yaml:"defaults"`
	Exchange struct {
		SmartHost            string `yaml:"smart_host"`
		ReceiveConnectorName string `yaml:"receive_connector_name"`
	} `yaml:"exchange"`
	Stores struct {
		PostgresDSN string `yaml:"postgres_dsn"`
		RedisAddr   string `yaml:"redis_addr"`
	} `yaml:"stores"`
	Rspamd struct {
		Endpoint       string `yaml:"endpoint"`
		TimeoutSeconds int    `yaml:"timeout_seconds"`
	} `yaml:"rspamd"`
	Sandbox struct {
		Enabled         bool   `yaml:"enabled"`
		Endpoint        string `yaml:"endpoint"`
		APIKey          string `yaml:"api_key"`
		TimeoutSeconds  int    `yaml:"timeout_seconds"`
		MinSuspicionHit int    `yaml:"min_suspicion_hit"`
	} `yaml:"sandbox"`
	SIEM struct {
		Enabled        bool   `yaml:"enabled"`
		WebhookURL     string `yaml:"webhook_url"`
		BearerToken    string `yaml:"bearer_token"`
		TimeoutSeconds int    `yaml:"timeout_seconds"`
	} `yaml:"siem"`
	SMTP struct {
		PolicyListen string `yaml:"policy_listen"`
	} `yaml:"smtp"`
	Auth struct {
		AccessSecret           string `yaml:"access_secret"`
		RefreshSecret          string `yaml:"refresh_secret"`
		AccessTTLMinutes       int    `yaml:"access_ttl_minutes"`
		RefreshTTLHours        int    `yaml:"refresh_ttl_hours"`
		BootstrapAdminUser     string `yaml:"bootstrap_admin_user"`
		BootstrapAdminEmail    string `yaml:"bootstrap_admin_email"`
		BootstrapAdminFullName string `yaml:"bootstrap_admin_full_name"`
		BootstrapAdminPassword string `yaml:"bootstrap_admin_password"`
		OIDC                   struct {
			Enabled      bool   `yaml:"enabled"`
			Issuer       string `yaml:"issuer"`
			ClientID     string `yaml:"client_id"`
			ClientSecret string `yaml:"client_secret"`
			RedirectURL  string `yaml:"redirect_url"`
			Scopes       string `yaml:"scopes"`
			EmailClaim   string `yaml:"email_claim"`
			NameClaim    string `yaml:"name_claim"`
			GroupsClaim  string `yaml:"groups_claim"`
		} `yaml:"oidc"`
	} `yaml:"auth"`
	LDAP struct {
		Enabled               bool              `yaml:"enabled"`
		URL                   string            `yaml:"url"`
		BindDN                string            `yaml:"bind_dn"`
		BindPassword          string            `yaml:"bind_password"`
		SearchBase            string            `yaml:"search_base"`
		SearchFilter          string            `yaml:"search_filter"`
		EmailAttr             string            `yaml:"email_attr"`
		NameAttr              string            `yaml:"name_attr"`
		GroupBase             string            `yaml:"group_base"`
		GroupFilter           string            `yaml:"group_filter"`
		GroupNameAttr         string            `yaml:"group_name_attr"`
		StartTLS              bool              `yaml:"start_tls"`
		TLSRejectUnauthorized bool              `yaml:"tls_reject_unauthorized"`
		DefaultRole           string            `yaml:"default_role"`
		RoleMap               map[string]string `yaml:"role_map"`
	} `yaml:"ldap"`
	Portal struct {
		PublicURL string   `yaml:"public_url"`
		Origins   []string `yaml:"origins"`
	} `yaml:"portal"`
}

type SignalCap struct {
	Min float64 `yaml:"min" json:"min"`
	Max float64 `yaml:"max" json:"max"`
}

type PolicyConfig struct {
	Policy struct {
		Inbound struct {
			Reject     float64 `yaml:"reject" json:"reject"`
			Quarantine float64 `yaml:"quarantine" json:"quarantine"`
		} `yaml:"inbound" json:"inbound"`
		Outbound struct {
			Reject     float64 `yaml:"reject" json:"reject"`
			Quarantine float64 `yaml:"quarantine" json:"quarantine"`
			Throttle   struct {
				RecipientsPerHour    int `yaml:"recipients_per_hour" json:"recipients_per_hour"`
				UniqueDomainsPerHour int `yaml:"unique_domains_per_hour" json:"unique_domains_per_hour"`
			} `yaml:"throttle" json:"throttle"`
		} `yaml:"outbound" json:"outbound"`
	} `yaml:"policy" json:"policy"`
	HardBlocks []string             `yaml:"hard_blocks" json:"hard_blocks"`
	Caps       map[string]SignalCap `yaml:"caps" json:"caps"`
}

func LoadServiceConfig(path string) (ServiceConfig, error) {
	var cfg ServiceConfig
	if err := loadYAML(path, &cfg); err != nil {
		return ServiceConfig{}, fmt.Errorf("load service config: %w", err)
	}
	if cfg.Service.Listen == "" {
		cfg.Service.Listen = ":8080"
	}
	if cfg.Service.Mode == "" {
		cfg.Service.Mode = "bootstrap"
	}
	if cfg.Defaults.OrganizationID <= 0 {
		cfg.Defaults.OrganizationID = 1
	}
	if cfg.Defaults.Organization == "" {
		cfg.Defaults.Organization = "default"
	}
	if cfg.SMTP.PolicyListen == "" {
		cfg.SMTP.PolicyListen = ":10031"
	}
	if cfg.Auth.AccessTTLMinutes <= 0 {
		cfg.Auth.AccessTTLMinutes = 15
	}
	if cfg.Auth.RefreshTTLHours <= 0 {
		cfg.Auth.RefreshTTLHours = 24
	}
	if cfg.Auth.BootstrapAdminUser == "" {
		cfg.Auth.BootstrapAdminUser = "admin"
	}
	if cfg.Auth.BootstrapAdminEmail == "" {
		cfg.Auth.BootstrapAdminEmail = "admin@localhost"
	}
	if cfg.Auth.BootstrapAdminFullName == "" {
		cfg.Auth.BootstrapAdminFullName = "Mail Warden Admin"
	}
	if cfg.Auth.OIDC.Scopes == "" {
		cfg.Auth.OIDC.Scopes = "openid profile email"
	}
	if cfg.Auth.OIDC.EmailClaim == "" {
		cfg.Auth.OIDC.EmailClaim = "email"
	}
	if cfg.Auth.OIDC.NameClaim == "" {
		cfg.Auth.OIDC.NameClaim = "name"
	}
	if cfg.Auth.OIDC.GroupsClaim == "" {
		cfg.Auth.OIDC.GroupsClaim = "groups"
	}
	if cfg.Sandbox.TimeoutSeconds <= 0 {
		cfg.Sandbox.TimeoutSeconds = 10
	}
	if cfg.Sandbox.MinSuspicionHit <= 0 {
		cfg.Sandbox.MinSuspicionHit = 1
	}
	if cfg.SIEM.TimeoutSeconds <= 0 {
		cfg.SIEM.TimeoutSeconds = 5
	}
	if strings.TrimSpace(cfg.Portal.PublicURL) == "" {
		cfg.Portal.PublicURL = "http://localhost:5173"
	}
	if len(cfg.Portal.Origins) == 0 {
		cfg.Portal.Origins = []string{"http://localhost:5173", "http://127.0.0.1:5173"}
	}

	// Environment overrides for production deployment.
	if v := os.Getenv("POSTGRES_DSN"); v != "" {
		cfg.Stores.PostgresDSN = v
	}
	if v := os.Getenv("REDIS_ADDR"); v != "" {
		cfg.Stores.RedisAddr = v
	}
	cfg.Auth.AccessSecret = envOrFile("MAILWARDEN_ACCESS_SECRET", "MAILWARDEN_ACCESS_SECRET_FILE", cfg.Auth.AccessSecret)
	cfg.Auth.RefreshSecret = envOrFile("MAILWARDEN_REFRESH_SECRET", "MAILWARDEN_REFRESH_SECRET_FILE", cfg.Auth.RefreshSecret)
	cfg.Auth.BootstrapAdminPassword = envOrFile("MAILWARDEN_BOOTSTRAP_ADMIN_PASSWORD", "MAILWARDEN_BOOTSTRAP_ADMIN_PASSWORD_FILE", cfg.Auth.BootstrapAdminPassword)
	cfg.LDAP.BindPassword = envOrFile("MAILWARDEN_LDAP_BIND_PASSWORD", "MAILWARDEN_LDAP_BIND_PASSWORD_FILE", cfg.LDAP.BindPassword)
	cfg.Auth.OIDC.ClientSecret = envOrFile("MAILWARDEN_OIDC_CLIENT_SECRET", "MAILWARDEN_OIDC_CLIENT_SECRET_FILE", cfg.Auth.OIDC.ClientSecret)
	cfg.Sandbox.APIKey = envOrFile("MAILWARDEN_SANDBOX_API_KEY", "MAILWARDEN_SANDBOX_API_KEY_FILE", cfg.Sandbox.APIKey)
	cfg.SIEM.BearerToken = envOrFile("MAILWARDEN_SIEM_BEARER_TOKEN", "MAILWARDEN_SIEM_BEARER_TOKEN_FILE", cfg.SIEM.BearerToken)
	if err := applyVaultOverrides(&cfg); err != nil {
		return ServiceConfig{}, err
	}
	if err := cfg.ValidateRuntimeSafety(); err != nil {
		return ServiceConfig{}, err
	}
	return cfg, nil
}

func (cfg ServiceConfig) IsBootstrapMode() bool {
	mode := strings.ToLower(strings.TrimSpace(cfg.Service.Mode))
	return mode == "" || mode == "bootstrap" || mode == "dev" || mode == "development"
}

func (cfg ServiceConfig) ValidateRuntimeSafety() error {
	if cfg.IsBootstrapMode() {
		return nil
	}
	var issues []string
	if strings.TrimSpace(cfg.Stores.PostgresDSN) == "" {
		issues = append(issues, "stores.postgres_dsn is required outside bootstrap mode")
	}
	if insecureSharedSecret(cfg.Auth.AccessSecret) {
		issues = append(issues, "auth.access_secret must be set to a non-default value outside bootstrap mode")
	}
	if insecureSharedSecret(cfg.Auth.RefreshSecret) {
		issues = append(issues, "auth.refresh_secret must be set to a non-default value outside bootstrap mode")
	}
	if strings.TrimSpace(cfg.Auth.BootstrapAdminPassword) != "" && insecureBootstrapPassword(cfg.Auth.BootstrapAdminPassword) {
		issues = append(issues, "auth.bootstrap_admin_password must not use a default/placeholder value")
	}
	if len(issues) > 0 {
		return fmt.Errorf("runtime safety validation failed: %s", strings.Join(issues, "; "))
	}
	return nil
}

func insecureSharedSecret(v string) bool {
	secret := strings.TrimSpace(v)
	if secret == "" {
		return true
	}
	lower := strings.ToLower(secret)
	defaults := map[string]struct{}{
		"change-me-access-secret":       {},
		"change-me-refresh-secret":      {},
		"mailwarden-access-dev-secret":  {},
		"mailwarden-refresh-dev-secret": {},
	}
	_, found := defaults[lower]
	return found
}

func insecureBootstrapPassword(v string) bool {
	lower := strings.ToLower(strings.TrimSpace(v))
	defaults := map[string]struct{}{
		"change-this-password": {},
		"changeme":             {},
		"password":             {},
		"admin":                {},
	}
	_, found := defaults[lower]
	return found
}

func envOrFile(envKey, fileEnvKey, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(envKey)); v != "" {
		return v
	}
	if fp := strings.TrimSpace(os.Getenv(fileEnvKey)); fp != "" {
		b, err := os.ReadFile(fp)
		if err == nil {
			if v := strings.TrimSpace(string(b)); v != "" {
				return v
			}
		}
	}
	return fallback
}

func LoadPolicyConfig(path string) (PolicyConfig, error) {
	var cfg PolicyConfig
	if err := loadYAML(path, &cfg); err != nil {
		return PolicyConfig{}, fmt.Errorf("load policy config: %w", err)
	}
	return cfg, nil
}

func loadYAML(path string, out any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(b, out); err != nil {
		return err
	}
	return nil
}
