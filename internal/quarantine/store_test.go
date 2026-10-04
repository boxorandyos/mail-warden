package quarantine

import (
	"context"
	"testing"
)

func TestStoreAddAndRelease(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewStore()
	msg, err := store.Add(ctx, Message{
		From:    "attacker@example.net",
		To:      []string{"user@company.com"},
		Subject: "Invoice",
		Reason:  "malicious_url",
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	if msg.ID == "" {
		t.Fatal("expected generated id")
	}
	if msg.Status != StatusQuarantined {
		t.Fatalf("expected quarantined status, got %s", msg.Status)
	}

	released, err := store.Release(ctx, msg.ID)
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if released.Status != StatusReleased {
		t.Fatalf("expected released status, got %s", released.Status)
	}
	if released.ReleasedAt == nil {
		t.Fatal("expected released_at to be set")
	}
}
