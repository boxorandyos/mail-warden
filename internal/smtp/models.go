package smtp

type Session struct {
	ClientIP string
	HELO     string
	From     string
	To       []string
}
