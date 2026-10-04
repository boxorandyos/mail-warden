package quarantine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/boxorandyos/mail-warden/internal/scoring"
)

var ErrNotFound = errors.New("quarantine message not found")

type Status string

const (
	StatusQuarantined Status = "quarantined"
	StatusReleased    Status = "released"
)

type Message struct {
	ID         string           `json:"id"`
	From       string           `json:"from"`
	To         []string         `json:"to"`
	Subject    string           `json:"subject"`
	Reason     string           `json:"reason"`
	Decision   scoring.Decision `json:"decision"`
	ReceivedAt time.Time        `json:"received_at"`
	Status     Status           `json:"status"`
	ReleasedAt *time.Time       `json:"released_at,omitempty"`
}

type Store struct {
	mu      sync.RWMutex
	counter int64
	items   map[string]Message
	order   []string
}

func NewStore() *Store {
	return &Store{
		items: make(map[string]Message),
		order: make([]string, 0, 128),
	}
}

func (s *Store) Add(_ context.Context, msg Message) (Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.counter++
	msg.ID = fmt.Sprintf("qmsg-%d", s.counter)
	if msg.ReceivedAt.IsZero() {
		msg.ReceivedAt = time.Now().UTC()
	}
	if msg.Status == "" {
		msg.Status = StatusQuarantined
	}
	s.items[msg.ID] = msg
	s.order = append(s.order, msg.ID)
	return msg, nil
}

func (s *Store) List(_ context.Context, limit int) ([]Message, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > len(s.order) {
		limit = len(s.order)
	}
	out := make([]Message, 0, limit)
	for i := len(s.order) - 1; i >= 0; i-- {
		id := s.order[i]
		out = append(out, s.items[id])
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *Store) Get(_ context.Context, id string) (Message, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	msg, ok := s.items[id]
	if !ok {
		return Message{}, ErrNotFound
	}
	return msg, nil
}

func (s *Store) Release(_ context.Context, id string) (Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	msg, ok := s.items[id]
	if !ok {
		return Message{}, ErrNotFound
	}
	now := time.Now().UTC()
	msg.Status = StatusReleased
	msg.ReleasedAt = &now
	s.items[id] = msg
	return msg, nil
}
