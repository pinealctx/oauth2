package apple

import "github.com/pinealctx/oauth2"

const (
	OAuth2CertsURL = "https://appleid.apple.com/auth/keys"
)

// Issuers is the allowed oauth token issuers
var Issuers = []string{"https://appleid.apple.com"}

type Payload struct {
	*oauth2.ClaimSet
	// The hash of the authorization code. It's only used when you need to validate the authorization code.
	CHash string `json:"c_hash"`
	// The email address of the user.
	Email string `json:"email"`
	// Whether the email is verified. Note that it's a string JSON type.
	EmailVerified string `json:"email_verified"`
	// The time in epoch at which the authentication happened.
	AuthTime int64 `json:"auth_time"`
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
