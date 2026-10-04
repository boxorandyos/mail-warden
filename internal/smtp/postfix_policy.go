package smtp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/boxorandyos/mail-warden/internal/policy"
	"github.com/boxorandyos/mail-warden/internal/scoring"
)

type PostfixPolicyServer struct {
	Address string
	Engine  *policy.Engine
}

func (s *PostfixPolicyServer) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.Address)
	if err != nil {
		return fmt.Errorf("listen postfix policy server: %w", err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *PostfixPolicyServer) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	req, err := parsePostfixPolicyRequest(conn)
	if err != nil {
		_, _ = conn.Write([]byte("action=dunno\n\n"))
		return
	}

	n := scoring.NormalizedDecisionObject{
		Connection: scoring.ConnectionFacts{
			IP: req["client_address"],
		},
		Envelope: scoring.EnvelopeFacts{
			From:       req["sender"],
			Recipients: []string{req["recipient"]},
		},
		ObservedAt: time.Now().UTC(),
	}
	d := s.Engine.EvaluateByDirection("inbound", n)
	_, _ = conn.Write([]byte("action=" + postfixActionFromDecision(d.Action) + "\n\n"))
}

func parsePostfixPolicyRequest(conn net.Conn) (map[string]string, error) {
	out := make(map[string]string)
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			break
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		out[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func postfixActionFromDecision(action scoring.Action) string {
	switch action {
	case scoring.ActionReject:
		return "reject Mail Warden policy rejection"
	case scoring.ActionQuarantine:
		return "hold Mail Warden quarantine"
	case scoring.ActionThrottle, scoring.ActionTempFailure:
		return "defer_if_permit Mail Warden temporary policy defer"
	default:
		return "dunno"
	}
}
