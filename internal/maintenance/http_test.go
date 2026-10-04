package maintenance

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestApplyRequiresKeyAndSchedules(t *testing.T) {
	var got Kind
	deps := Deps{
		Key:  "cluster-key",
		Role: "secondary",
		Schedule: func(_ context.Context, kind Kind) (bool, string, error) {
			got = kind
			return false, "planned: bash scripts/update.sh", nil
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/maintenance/apply", strings.NewReader(`{"kind":"product"}`))
	rec := httptest.NewRecorder()
	deps.Apply(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/maintenance/apply", strings.NewReader(`{"kind":"product"}`))
	req.Header.Set("X-Maintenance-Key", "cluster-key")
	rec = httptest.NewRecorder()
	deps.Apply(rec, req)
	if rec.Code != http.StatusAccepted {
		body, _ := io.ReadAll(rec.Body)
		t.Fatalf("status %d body %s", rec.Code, body)
	}
	if got != Product {
		t.Fatalf("kind %s", got)
	}
}

func TestPrimaryTriggersSecondary(t *testing.T) {
	var called Call
	deps := Deps{
		Key:  "cluster-key",
		Role: "primary",
		ListNodes: func(context.Context) ([]Node, error) {
			return []Node{{Name: "b", Address: "10.0.0.9:8080", Role: "standby"}}, nil
		},
		Post: func(_ context.Context, call Call, key string) (int, string, error) {
			called = call
			if key != "cluster-key" {
				t.Fatal("missing key")
			}
			return http.StatusAccepted, "ok", nil
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/maintenance/slaves", strings.NewReader(`{"kind":"packages"}`))
	rec := httptest.NewRecorder()
	deps.Slaves(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if called.URL != "http://10.0.0.9:8080/api/v1/maintenance/apply" || called.Kind != Packages {
		t.Fatalf("call %+v", called)
	}
}
