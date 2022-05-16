package oauth2

import "time"

type Config struct {
	CertURL   string
	Audiences []string
	Issuers   []string
	MaxExpiry time.Duration
}
