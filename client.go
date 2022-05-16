package oauth2

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	// MaxTokenLifetime is one day
	MaxTokenLifetime = time.Second * 86400
	// ClockSkew - five minutes
	ClockSkew = time.Minute * 5
)

type Client struct {
	certURL     string
	certs       *Certs
	certsLocker sync.Mutex

	audiences []string
	issuers   []string

	maxExpiry time.Duration
}

func New(c *Config) *Client {
	return &Client{
		certURL:   c.CertURL,
		audiences: c.Audiences,
		issuers:   c.Issuers,
		maxExpiry: c.MaxExpiry,
	}
}

type Header struct {
	// The algorithm used for signature.
	Algorithm string `json:"alg"`

	// Represents the token type.
	Typ string `json:"typ"`

	// The optional hint of which key is being used.
	KeyID string `json:"kid,omitempty"`
}

type ClaimSet struct {
	Iss   string `json:"iss"`             // email address of the client_id of the application making the access token request
	Scope string `json:"scope,omitempty"` // space-delimited list of the permissions the application requests
	Aud   string `json:"aud"`             // descriptor of the intended target of the assertion (Optional).
	Exp   int64  `json:"exp"`             // the expiration time of the assertion (seconds since Unix epoch)
	Iat   int64  `json:"iat"`             // the time the assertion was issued (seconds since Unix epoch)
	Typ   string `json:"typ,omitempty"`   // token type (Optional).

	// Email for which the application is requesting delegated access (Optional).
	Sub string `json:"sub,omitempty"`

	// The old name of Sub. Client keeps setting Prn to be
	// compliant with legacy OAuth 2.0 providers. (Optional)
	Prn string `json:"prn,omitempty"`
}

func (c *ClaimSet) GetClaimSet() *ClaimSet {
	return c
}

type Payload interface {
	GetClaimSet() *ClaimSet
}

func (c *Client) VerifyIDToken(jwt string, payload Payload) error {
	var segments = strings.Split(jwt, ".")
	if len(segments) != 3 {
		return fmt.Errorf("wrong number of segments in token")
	}
	var envelopePart, payloadPart, signaturePart = segments[0], segments[1], segments[2]
	envelopeBytes, err := base64.RawURLEncoding.DecodeString(envelopePart)
	if err != nil {
		return fmt.Errorf("can't parse token envelope[base64]: %s, %s", envelopePart, err.Error())
	}
	var envelope = &Header{}
	if err = json.Unmarshal(envelopeBytes, envelope); err != nil {
		return fmt.Errorf("can't parse token envelope[json]: %s, %s", envelopePart, err.Error())
	}
	var certs *Certs
	certs, err = c.GetFederatedSignOnCerts()
	if err != nil {
		return err
	}
	var cert, ok = certs.Keys[envelope.KeyID]
	if !ok {
		return fmt.Errorf("no pem found for envelope: %s", string(envelopeBytes))
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		return fmt.Errorf("can't parse token payload[base64]: %s, %s", payloadPart, err.Error())
	}
	if err = json.Unmarshal(payloadBytes, &payload); err != nil {
		return fmt.Errorf("can't parse token payload[json]: %s, %s", payloadPart, err.Error())
	}
	if envelope.Algorithm == "ES256" {
		// TODO: js code convert
		// signaturePart = formatEcdsa.joseToDer(signature, 'ES256').toString('base64');
		_ = signaturePart
	}
	var signed = envelopePart + "." + payloadPart
	if err = verify(cert, signed, signaturePart); err != nil {
		return fmt.Errorf("invalid token signature: %s", jwt)
	}
	var claimSet = payload.GetClaimSet()
	if claimSet.Iat == 0 {
		return errors.New("iat field using invalid format")
	}
	if claimSet.Exp == 0 {
		return errors.New("exp field using invalid format")
	}
	var now = time.Now().Unix()
	var maxExpiry = c.maxExpiry
	if maxExpiry == 0 {
		maxExpiry = MaxTokenLifetime
	}
	if claimSet.Exp >= now+int64(maxExpiry.Seconds()) {
		return fmt.Errorf("expiration time too far in future: %s", string(payloadBytes))
	}
	var earliest = claimSet.Iat - int64(ClockSkew.Seconds())
	var latest = claimSet.Exp + int64(ClockSkew.Seconds())
	if now < earliest {
		return fmt.Errorf("token used too early, %d < %d: %s", now, earliest, string(payloadBytes))
	}
	if now > latest {
		return fmt.Errorf("token used too late, %d > %d: %s", now, latest, string(payloadBytes))
	}
	if !inStringSlice(c.issuers, claimSet.Iss) {
		return fmt.Errorf("invalid issuer, expected one of [%v], but got %s", c.issuers, claimSet.Iss)
	}
	if !inStringSlice(c.audiences, claimSet.Aud) {
		return fmt.Errorf("invalid audienc, expected one of [%v], but got %s", c.audiences, claimSet.Aud)
	}
	return nil
}

func inStringSlice(slice []string, item string) bool {
	for _, i := range slice {
		if i == item {
			return true
		}
	}
	return false
}

func verify(cert *rsa.PublicKey, signed, signature string) error {
	var signatureBytes, err = base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	var h = sha256.New()
	h.Write([]byte(signed))
	return rsa.VerifyPKCS1v15(cert, crypto.SHA256, h.Sum(nil), signatureBytes)
}
