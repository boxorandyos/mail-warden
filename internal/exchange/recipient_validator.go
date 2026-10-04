package exchange

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

type RecipientValidator struct {
	pool           *pgxpool.Pool
	organizationID int64
}

type RecipientProfile struct {
	Address     string `json:"address"`
	Valid       bool   `json:"valid"`
	PolicyClass string `json:"policy_class"`
}

func NewRecipientValidator(pool *pgxpool.Pool, organizationID int64) *RecipientValidator {
	return &RecipientValidator{pool: pool, organizationID: organizationID}
}

func (v *RecipientValidator) ValidateRecipients(ctx context.Context, recipients []string) (map[string]bool, error) {
	profiles, err := v.LookupRecipientProfiles(ctx, recipients)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(profiles))
	for _, p := range profiles {
		out[p.Address] = p.Valid
	}
	return out, nil
}

func (v *RecipientValidator) LookupRecipientProfiles(ctx context.Context, recipients []string) (map[string]RecipientProfile, error) {
	if len(recipients) == 0 {
		return map[string]RecipientProfile{}, nil
	}
	normalized := make([]string, 0, len(recipients))
	profiles := make(map[string]RecipientProfile, len(recipients))
	for _, r := range recipients {
		n := strings.ToLower(strings.TrimSpace(r))
		if n == "" {
			continue
		}
		normalized = append(normalized, n)
		profiles[n] = RecipientProfile{
			Address:     n,
			Valid:       false,
			PolicyClass: "NORMAL",
		}
	}
	if len(normalized) == 0 {
		return profiles, nil
	}

	rows, err := v.pool.Query(ctx, `
		SELECT address, policy_class
		  FROM mailboxes
		 WHERE organization_id = $1
		   AND enabled = true
		   AND lower(address) = ANY($2)
	`, v.organizationID, normalized)
	if err != nil {
		return nil, fmt.Errorf("validate recipients query: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var addr, policyClass string
		if err := rows.Scan(&addr, &policyClass); err != nil {
			return nil, fmt.Errorf("scan valid recipient: %w", err)
		}
		key := strings.ToLower(addr)
		profiles[key] = RecipientProfile{
			Address:     key,
			Valid:       true,
			PolicyClass: strings.ToUpper(strings.TrimSpace(policyClass)),
		}
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("iterate recipients: %w", rows.Err())
	}
	return profiles, nil
}
