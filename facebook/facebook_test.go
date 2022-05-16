package facebook

import (
	"github.com/pinealctx/neptune/jsonx"
	"testing"
)

func Test_Unmarshal(t *testing.T) {
	var j = `{
    "data": {
        "app_id": 138483919580948, 
        "type": "USER",
        "application": "Social Cafe", 
        "expires_at": 1352419328, 
        "is_valid": true, 
        "issued_at": 1347235328, 
        "metadata": {
            "sso": "iphone-safari"
        }, 
        "scopes": [
            "email", 
            "publish_actions"
        ], 
        "user_id": "1207059"
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
