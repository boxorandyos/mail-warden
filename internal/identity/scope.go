package identity

import (
	"errors"
	"strings"
)

var ErrScopeForbidden = errors.New("scope=all is not allowed for this role")

func ResolveScope(role Role, requested string) (bool, error) {
	switch strings.TrimSpace(requested) {
	case "", "own":
		return false, nil
	case "all":
		if !CanScopeAll(role) {
			return false, ErrScopeForbidden
		}
		return true, nil
	default:
		return false, errors.New("invalid scope")
	}
}

func OwnsMail(email, sender string, recipients []string) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(sender), email) {
		return true
	}
	for _, recipient := range recipients {
		if strings.EqualFold(strings.TrimSpace(recipient), email) {
			return true
		}
	}
	return false
}

func CanScopeAll(role Role) bool {
	return role == RoleAdmin || role == RoleModerator
}
