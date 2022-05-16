package google

import (
	"github.com/pinealctx/oauth2"
)

const (
	// OAuth2CertsURL Google Sign on certificates.
	OAuth2CertsURL = "https://www.googleapis.com/oauth2/v3/certs"
)

// Issuers is the allowed oauth token issuers
var Issuers = []string{"accounts.google.com", "https://accounts.google.com"}

type Payload struct {
	*oauth2.ClaimSet
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Locale        string `json:"locale"`
}

type Client struct {
	cli *oauth2.Client
}

func New(audiences ...string) *Client {
	return &Client{
		cli: oauth2.New(&oauth2.Config{
			CertURL:   OAuth2CertsURL,
			Audiences: audiences,
			Issuers:   Issuers,
		}),
	}
}

func (c *Client) VerifyIDToken(token string) (*Payload, error) {
	var payload = &Payload{}
	var err = c.cli.VerifyIDToken(token, payload)
	if err != nil {
		return nil, err
	}
	return payload, nil
}
