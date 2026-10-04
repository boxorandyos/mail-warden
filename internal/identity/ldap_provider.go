package identity

import (
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type LDAPIdentity struct {
	Username   string
	Email      string
	FullName   string
	ExternalID string
	Groups     []string
	Role       Role
}

type LDAPProvider struct {
	cfg LDAPConfig
}

func NewLDAPProvider(cfg LDAPConfig) (*LDAPProvider, error) {
	valid, err := ValidateLDAPConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &LDAPProvider{cfg: valid}, nil
}

func (p *LDAPProvider) Authenticate(username, password string) (LDAPIdentity, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return LDAPIdentity{}, fmt.Errorf("invalid credentials")
	}

	conn, err := ldap.DialURL(p.cfg.URL, ldap.DialWithTLSConfig(&tls.Config{
		InsecureSkipVerify: !p.cfg.TLSRejectUnauthorized, //nolint:gosec
	}))
	if err != nil {
		return LDAPIdentity{}, fmt.Errorf("ldap connect: %w", err)
	}
	defer conn.Close()
	conn.SetTimeout(10 * time.Second)

	if p.cfg.StartTLS {
		if err := conn.StartTLS(&tls.Config{InsecureSkipVerify: !p.cfg.TLSRejectUnauthorized}); err != nil { //nolint:gosec
			return LDAPIdentity{}, fmt.Errorf("ldap starttls: %w", err)
		}
	}

	if p.cfg.BindDN != "" {
		if err := conn.Bind(p.cfg.BindDN, p.cfg.BindPassword); err != nil {
			return LDAPIdentity{}, fmt.Errorf("ldap service bind: %w", err)
		}
	}

	filter := strings.ReplaceAll(p.cfg.SearchFilter, "{{username}}", EscapeLDAPFilterValue(username))
	req := ldap.NewSearchRequest(
		p.cfg.SearchBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,
		10,
		false,
		filter,
		[]string{"dn", p.cfg.EmailAttr, p.cfg.NameAttr},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil || len(res.Entries) == 0 {
		return LDAPIdentity{}, fmt.Errorf("invalid credentials")
	}
	entry := res.Entries[0]
	userDN := entry.DN

	if err := conn.Bind(userDN, password); err != nil {
		return LDAPIdentity{}, fmt.Errorf("invalid credentials")
	}

	groups, _ := p.fetchGroups(conn, userDN)
	email := entry.GetAttributeValue(p.cfg.EmailAttr)
	if email == "" {
		email = username + "@ldap.local"
	}
	fullName := entry.GetAttributeValue(p.cfg.NameAttr)
	if fullName == "" {
		fullName = username
	}

	return LDAPIdentity{
		Username:   username,
		Email:      email,
		FullName:   fullName,
		ExternalID: userDN,
		Groups:     groups,
		Role:       MapGroupsToRole(groups, p.cfg.RoleMap, p.cfg.DefaultRole),
	}, nil
}

func (p *LDAPProvider) fetchGroups(conn *ldap.Conn, userDN string) ([]string, error) {
	if p.cfg.GroupBase == "" || p.cfg.GroupFilter == "" {
		return nil, nil
	}
	filter := strings.ReplaceAll(p.cfg.GroupFilter, "{{dn}}", EscapeLDAPFilterValue(userDN))
	req := ldap.NewSearchRequest(
		p.cfg.GroupBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		200,
		10,
		false,
		filter,
		[]string{p.cfg.GroupNameAttr},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		if name := e.GetAttributeValue(p.cfg.GroupNameAttr); name != "" {
			out = append(out, name)
		}
	}
	return out, nil
}
