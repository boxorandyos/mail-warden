package identity

type Role string

const (
	RoleAdmin     Role = "admin"
	RoleModerator Role = "moderator"
	RoleViewer    Role = "viewer"
)

type User struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	Email        string `json:"email"`
	FullName     string `json:"full_name"`
	Role         Role   `json:"role"`
	AuthProvider string `json:"auth_provider"`
	ExternalID   string `json:"external_id,omitempty"`
	Enabled      bool   `json:"enabled"`
}

type Claims struct {
	UserID string `json:"user_id"`
	OrgID  int64  `json:"org_id"`
	Role   Role   `json:"role"`
	Email  string `json:"email"`
}
