package quarantine

import (
	"context"

	"github.com/boxorandyos/mail-warden/internal/scoring"
)

type Repository interface {
	Add(ctx context.Context, msg Message) (Message, error)
	List(ctx context.Context, limit int) ([]Message, error)
	ListScoped(ctx context.Context, limit int, email string) ([]Message, error)
	Get(ctx context.Context, id string) (Message, error)
	Release(ctx context.Context, id string) (Message, error)
	UpdateAfterRescan(ctx context.Context, id string, decision scoring.Decision, reason string, release bool) (Message, error)
}
