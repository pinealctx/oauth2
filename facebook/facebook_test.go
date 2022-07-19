package facebook

import (
	"github.com/pinealctx/neptune/jsonx"
	"testing"
)

func Test_Unmarshal(t *testing.T) {
	var j = `{
    "data": {
        "app_id": "",
        "type": "USER",
        "application": "",
        "data_access_expires_at": 1666006375,
        "expires_at": 1663414350,
        "is_valid": true,
        "issued_at": 1658230350,
        "metadata": {
            "auth_type": "rerequest",
            "sso": "android"
        },
        "scopes": [
            "email",
            "openid",
            "public_profile"
        ],
        "user_id": ""
    }
}`
	var r DebugTokenResponse
	var err = jsonx.JSONUnmarshal([]byte(j), &r)
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(r)
}
