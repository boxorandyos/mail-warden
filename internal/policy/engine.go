package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/boxorandyos/mail-warden/internal/scoring"
)

type Engine struct {
	scoring *scoring.Engine
}

func NewEngine(cfg scoring.EngineConfig) *Engine {
	return &Engine{
		scoring: scoring.NewEngine(cfg),
	}
}

func DefaultEngineConfig() scoring.EngineConfig {
	return scoring.DefaultEngineConfig()
}

func (e *Engine) Evaluate(n scoring.NormalizedDecisionObject) scoring.Decision {
	return e.scoring.Evaluate(n)
}

func (e *Engine) EvaluateByDirection(direction string, n scoring.NormalizedDecisionObject) scoring.Decision {
	if direction == "" {
		direction = "inbound"
	}
	return e.scoring.EvaluateForDirection(direction, n)
}

type EvaluateRequest struct {
	Direction  string                           `json:"direction"`
	Message    scoring.NormalizedDecisionObject `json:"message"`
	RawMessage string                           `json:"raw_message,omitempty"`
	SourceIP   string                           `json:"source_ip,omitempty"`
	HELO       string                           `json:"helo,omitempty"`
}

func (r *EvaluateRequest) Normalize() {
	if r.Direction == "" {
		r.Direction = "inbound"
	}
}

type DecisionResponse struct {
	Direction string           `json:"direction"`
	Decision  scoring.Decision `json:"decision"`
}

func (r DecisionResponse) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func DecodeRequest(r io.Reader) (EvaluateRequest, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return EvaluateRequest{}, fmt.Errorf("read request body: %w", err)
	}

	var req EvaluateRequest
	if err := json.Unmarshal(raw, &req); err == nil && req.Direction != "" {
		req.Normalize()
		return req, nil
	}

	var n scoring.NormalizedDecisionObject
	if err := json.Unmarshal(raw, &n); err != nil {
		return EvaluateRequest{}, fmt.Errorf("decode normalized object: %w", err)
	}

	return EvaluateRequest{
		Direction: "inbound",
		Message:   n,
	}, nil
}

func DecodeAndEvaluate(r io.Reader, e *Engine) (DecisionResponse, error) {
	req, err := DecodeRequest(r)
	if err != nil {
		return DecisionResponse{}, err
	}
	req.Normalize()

	return DecisionResponse{
		Direction: req.Direction,
		Decision:  e.EvaluateByDirection(req.Direction, req.Message),
	}, nil
}

func WriteHTTPJSON(w http.ResponseWriter, status int, payload any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(payload)
}
