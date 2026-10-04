package identity

import "testing"

func TestValidateLDAPConfig(t *testing.T) {
	t.Parallel()

	cfg, err := ValidateLDAPConfig(LDAPConfig{
		URL:          "ldaps://ldap.example.com:636",
		SearchBase:   "dc=example,dc=com",
		SearchFilter: "(&(objectClass=user)(uid={{username}}))",
	})
	if err != nil {
		t.Fatalf("validate ldap config: %v", err)
	}
	if cfg.EmailAttr != "mail" {
		t.Fatalf("expected default email attr, got %s", cfg.EmailAttr)
	}
}

func TestEscapeLDAPFilterValue(t *testing.T) {
	t.Parallel()

	got := EscapeLDAPFilterValue("a*(b)")
	if got == "a*(b)" {
		t.Fatalf("expected escaped ldap filter value, got %q", got)
	}
}

func TestValidateProviderInputLDAPRequiresConfig(t *testing.T) {
	t.Parallel()

	_, err := ValidateProviderInput(Provider{
		Type:   ProviderTypeLDAP,
		Config: map[string]any{},
	})
	if err == nil {
		t.Fatal("expected validation error for missing ldap config")
	}
}

func TestValidateProviderInputOIDCRequiresConfig(t *testing.T) {
	t.Parallel()

	_, err := ValidateProviderInput(Provider{
		Type: ProviderTypeOIDC,
		Config: map[string]any{
			"issuer": "https://login.example.com",
		},
	})
	if err == nil {
		t.Fatal("expected validation error for incomplete oidc config")
	}
}

func TestValidateProviderInputNormalizesLocalProvider(t *testing.T) {
	t.Parallel()

	out, err := ValidateProviderInput(Provider{
		Type:     "LOCAL",
		Priority: 100,
	})
	if err != nil {
		t.Fatalf("validate provider: %v", err)
	}
	if out.Type != ProviderTypeLocal {
		t.Fatalf("expected normalized provider type local, got %s", out.Type)
	}
	if out.Name != "local" {
		t.Fatalf("expected inferred provider name local, got %s", out.Name)
	}
}
