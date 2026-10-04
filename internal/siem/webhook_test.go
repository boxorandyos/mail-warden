package siem

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestForwarderSend(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	f := NewForwarder(true, srv.URL, "", 2)
	if err := f.Send(t.Context(), map[string]any{"event": "test"}); err != nil {
		t.Fatalf("send: %v", err)
	}
}

func TestForwarderReturnsErrorOnRemoteFailure(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	f := NewForwarder(true, srv.URL, "", 2)
	if err := f.Send(t.Context(), map[string]any{"event": "test"}); err == nil {
		t.Fatal("expected forwarder error when SIEM endpoint fails")
	}
}

func TestForwarderSkipsWhenDisabled(t *testing.T) {
	t.Parallel()
	f := NewForwarder(false, "http://127.0.0.1:1", "", 1)
	if err := f.Send(t.Context(), map[string]any{"event": "test"}); err != nil {
		t.Fatalf("disabled forwarder should be no-op: %v", err)
	}
}
