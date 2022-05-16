package google

import (
	"os"
	"testing"
)

const (
	envTestGoogleAudience = "ENV_GOOGLE_AUDIENCE"
	envTestGoogleToken    = "ENV_GOOGLE_TOKEN"
)

var (
	audience = os.Getenv(envTestGoogleAudience)
	token    = os.Getenv(envTestGoogleToken)
)

func Test_VerifyIDToken(t *testing.T) {
	var cli = New(audience)
	var ticket, err = cli.VerifyIDToken(token)
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(ticket)
}
