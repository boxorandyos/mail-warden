package identity

import (
	"testing"
	"time"
)

func TestTokenIssueAndVerify(t *testing.T) {
	t.Parallel()

	issuer, err := NewTokenIssuer("access-secret", "refresh-secret", 15*time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}

	pair, err := issuer.Issue(Claims{
		UserID: "u1",
		OrgID:  1,
		Role:   RoleAdmin,
		Email:  "admin@example.com",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if pair.RefreshJTI == "" {
		t.Fatal("expected refresh jti")
	}

	claims, err := issuer.VerifyAccess(pair.AccessToken)
	if err != nil {
		t.Fatalf("verify access: %v", err)
	}
	if claims.UserID != "u1" {
		t.Fatalf("unexpected user id: %s", claims.UserID)
	}
}
