// nolint: gosec
package facebook

import (
	"context"
	"fmt"
	"github.com/pinealctx/restgo"
	"time"
)

const (
	OAuthTokenURL = "https://graph.facebook.com/oauth/access_token"
	DebugTokenURL = "https://graph.facebook.com/debug_token"
)

type Client struct {
	appid     string
	appSecret string

	cli *restgo.Client
}

func New(appid, appSecret string) *Client {
	return &Client{
		appid:     appid,
		appSecret: appSecret,
		cli:       restgo.New(),
	}
}

func (c *Client) VerifyToken(ctx context.Context, token string) (*DebugTokenResponse, error) {
	var accessToken, err = c.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	var debugToken *DebugTokenResponse
	debugToken, err = c.debugToken(ctx, token, accessToken.AccessToken)
	if err != nil {
		return nil, err
	}
	return debugToken, nil
}

type DebugTokenResponseData struct {
	AppID               string                 `json:"app_id"`
	Type                string                 `json:"type"`
	Application         string                 `json:"application"`
	DataAccessExpiresAt int64                  `json:"data_access_expires_at"`
	ExpiresAt           int64                  `json:"expires_at"`
	IsValid             bool                   `json:"is_valid"`
	IssuedAt            int64                  `json:"issued_at"`
	Metadata            map[string]interface{} `json:"metadata"`
	Scopes              []string               `json:"scopes"`
	UserID              string                 `json:"user_id"`
}

type DebugTokenResponse struct {
	DebugTokenResponseData `json:"data"`
}

func (c *Client) debugToken(ctx context.Context, inputToken, accessToken string) (*DebugTokenResponse, error) {
	var response, err = c.cli.Get(ctx, DebugTokenURL,
		restgo.NewURLQueryParam("input_token", inputToken),
		restgo.NewURLQueryParam("access_token", accessToken),
	)
	if err != nil {
		return nil, err
	}
	var rsp DebugTokenResponse
	err = response.JSONUnmarshal(&rsp)
	if err != nil {
		return nil, err
	}
	var now = time.Now().Unix()
	if !rsp.IsValid {
		return nil, fmt.Errorf("invalid token")
	}
	if rsp.ExpiresAt < time.Now().Unix() {
		return nil, fmt.Errorf("token already expired, expires_at(%d) < now(%d)", rsp.ExpiresAt, now)
	}
	return &rsp, nil
}

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

func (c *Client) accessToken(ctx context.Context) (*AccessTokenResponse, error) {
	var response, err = c.cli.Get(ctx, OAuthTokenURL,
		restgo.NewURLQueryParam("client_id", c.appid),
		restgo.NewURLQueryParam("client_secret", c.appSecret),
		restgo.NewURLQueryParam("grant_type", "client_credentials"),
	)
	if err != nil {
		return nil, err
	}
	var rsp AccessTokenResponse
	err = response.JSONUnmarshal(&rsp)
	if err != nil {
		return nil, err
	}
	return &rsp, nil
}
