package smtp

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
)

var queueIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type HoldReleaser interface {
	ReleaseHold(ctx context.Context, queueID string) error
}

type PostsuperHoldReleaser struct {
	Command string
}

func (p PostsuperHoldReleaser) ReleaseHold(ctx context.Context, queueID string) error {
	if !queueIDPattern.MatchString(queueID) {
		return fmt.Errorf("invalid queue id")
	}
	command := p.Command
	if command == "" {
		command = "postsuper"
	}
	cmd := exec.CommandContext(ctx, command, "-H", queueID)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("release postfix hold: %w: %s", err, out)
	}
	return nil
}

func ValidQueueID(queueID string) bool {
	return queueIDPattern.MatchString(queueID)
}
