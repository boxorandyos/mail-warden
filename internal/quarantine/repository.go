package quarantine

import "context"

type Repository interface {
	Add(ctx context.Context, msg Message) (Message, error)
	List(ctx context.Context, limit int) ([]Message, error)
	Get(ctx context.Context, id string) (Message, error)
	Release(ctx context.Context, id string) (Message, error)
}
