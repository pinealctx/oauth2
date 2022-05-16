package oauth2

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

type Certs struct {
	Keys   map[string]*rsa.PublicKey
	Expiry time.Time
}

type PublicKey struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"Kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type response struct {
	Keys []*PublicKey `json:"keys"`
}

func (c *Client) GetFederatedSignOnCerts() (*Certs, error) {
	c.certsLocker.Lock()
	defer c.certsLocker.Unlock()
	if c.certs != nil {
		if time.Now().Before(c.certs.Expiry) {
			return c.certs, nil
		}
	}
	resp, err := http.Get(c.certURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	cacheControl := resp.Header.Get("cache-control")
	cacheAge := int64(7200) // Set default cacheAge to 2 hours
	if len(cacheControl) > 0 {
		var ca int64
		ca, err = matchCacheAge(cacheControl)
		if err != nil {
			return nil, err
		}
		if ca != 0 {
			cacheAge = ca
		}
	}

	res := &response{}
	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return nil, err
	}

	keys := map[string]*rsa.PublicKey{}
	for _, key := range res.Keys {
		if key.Use == "sig" && key.Kty == "RSA" {
			var k *rsa.PublicKey
			k, err = makePublicKey(key)
			if err != nil {
				return nil, err
			}
			keys[key.Kid] = k
		}
	}
	c.certs = &Certs{
		Keys:   keys,
		Expiry: time.Now().Add(time.Second * time.Duration(cacheAge)),
	}

	return c.certs, nil
}

func matchCacheAge(cacheControl string) (int64, error) {
	re := regexp.MustCompile(`max-age=(\d*)`)
	match := re.FindAllStringSubmatch(cacheControl, -1)
	if len(match) > 0 {
		if len(match[0]) == 2 {
			maxAge := match[0][1]
			return strconv.ParseInt(maxAge, 10, 64)
		}
	}
	return 0, nil
}

func makePublicKey(k *PublicKey) (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	e, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	ei := big.NewInt(0).SetBytes(e).Int64()
	if err != nil {
		return nil, err
	}
	return &rsa.PublicKey{
		N: big.NewInt(0).SetBytes(n),
		E: int(ei),
	}, nil
}
