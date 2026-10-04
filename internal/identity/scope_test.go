package identity

import (
	"errors"
	"testing"
)

func TestOwnsMailRecipientOrSender(t *testing.T) {
	t.Parallel()
	recipients := []string{"Other@Company.com", "ada@company.com"}
	if !OwnsMail("Ada@Company.com", "ext@outside.test", recipients) {
		t.Fatal("expected recipient match")
	}
	if !OwnsMail("ada@company.com", "Ada@Company.com", []string{"other@company.com"}) {
		t.Fatal("expected sender match")
	}
	if OwnsMail("ada@company.com", "ext@outside.test", []string{"other@company.com"}) {
		t.Fatal("expected unrelated mail to be hidden")
	}
	if OwnsMail("  ", "ada@company.com", recipients) {
		t.Fatal("empty viewer email must not match")
	}
}

func TestResolveScopeViewerForbidden(t *testing.T) {
	t.Parallel()
	if _, err := ResolveScope(RoleViewer, "all"); !errors.Is(err, ErrScopeForbidden) {
		t.Fatalf("expected forbidden, got %v", err)
	}
	all, err := ResolveScope(RoleModerator, "all")
	if err != nil || !all {
		t.Fatalf("moderator scope=all: all=%v err=%v", all, err)
	}
	all, err = ResolveScope(RoleAdmin, "")
	if err != nil || all {
		t.Fatalf("default scope should be own mail: all=%v err=%v", all, err)
	}
}

func TestCanScopeAll(t *testing.T) {
	t.Parallel()
	if !CanScopeAll(RoleAdmin) || !CanScopeAll(RoleModerator) {
		t.Fatal("admin and moderator may request scope=all")
	}
	if CanScopeAll(RoleViewer) {
		t.Fatal("viewer must not request scope=all")
	}
}
