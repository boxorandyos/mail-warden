package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

type contextKey string

const claimsContextKey contextKey = "identity.claims"

// ServiceAccountLookup resolves an mw_ bearer token to claims. The environment id pins the account.
var ServiceAccountLookup func(ctx context.Context, token string) (Claims, string, bool)

type environmentContextKey struct{}

func EnvironmentFromContext(ctx context.Context) string {
	value, _ := ctx.Value(environmentContextKey{}).(string)
	return value
}

func AuthMiddleware(tokens *TokenIssuer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := strings.TrimSpace(r.Header.Get("Authorization"))
			if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
				respondUnauthorized(w, "missing bearer token")
				return
			}
			token := strings.TrimSpace(auth[len("Bearer "):])
			if strings.HasPrefix(token, "mw_") && ServiceAccountLookup != nil {
				claims, environmentID, ok := ServiceAccountLookup(r.Context(), token)
				if !ok {
					respondUnauthorized(w, "invalid token")
					return
				}
				ctx := context.WithValue(r.Context(), claimsContextKey, claims)
				ctx = context.WithValue(ctx, environmentContextKey{}, environmentID)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			claims, err := tokens.VerifyAccess(token)
			if err != nil {
				respondUnauthorized(w, "invalid token")
				return
			}
			ctx := context.WithValue(r.Context(), claimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func RequireRoles(roles ...Role) func(http.Handler) http.Handler {
	allowed := make(map[Role]struct{}, len(roles))
	for _, r := range roles {
		allowed[r] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				respondUnauthorized(w, "authentication required")
				return
			}
			if _, exists := allowed[claims.Role]; !exists {
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "forbidden"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func ClaimsFromContext(ctx context.Context) (Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey).(Claims)
	return claims, ok
}

func respondUnauthorized(w http.ResponseWriter, msg string) {
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
