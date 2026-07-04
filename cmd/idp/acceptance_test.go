package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/infobloxopen/devedge-idp/internal/idp"
	"github.com/infobloxopen/devedge-sdk/server"
)

const (
	testClientID     = "devedge-idp-example"
	testClientSecret = "dev-secret"
	testRedirectURI  = "http://127.0.0.1:38080/callback"
)

// discovery is the subset of the OIDC discovery document we assert on.
type discovery struct {
	Issuer                      string `json:"issuer"`
	AuthorizationEndpoint       string `json:"authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	JwksURI                     string `json:"jwks_uri"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
}

// startIDP boots the IdP through the exact server.New(...).Serve(ctx) path the
// binary uses, on ephemeral loopback ports, and returns the base URL.
func startIDP(t *testing.T) (base string) {
	t.Helper()
	handlers, _, err := idp.New(idp.Config{RedirectURIs: []string{testRedirectURI}})
	if err != nil {
		t.Fatalf("idp.New: %v", err)
	}
	srv, err := server.New(server.Config{
		GRPCAddr:     "127.0.0.1:0",
		HTTPAddr:     "127.0.0.1:0",
		HTTPHandlers: handlers,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ha := srv.HTTPAddr(); ha != "" && ha != "127.0.0.1:0" {
			return "http://" + ha
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("server did not bind within 5s")
	return ""
}

// noRedirectClient never follows redirects, so we can inspect each Location.
func noRedirectClient() *http.Client {
	return &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// getRedirect issues a GET to rawURL and returns the (absolute) Location of the
// 302 response.
func getRedirect(t *testing.T, c *http.Client, rawURL string) *url.URL {
	t.Helper()
	resp, err := c.Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s: status %d, want redirect; body=%s", rawURL, resp.StatusCode, body)
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("GET %s: no Location: %v", rawURL, err)
	}
	return loc
}

func randString(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// TestAcceptance_AuthCodePKCE is the P0 acceptance criterion: a confidential
// client completes an auth-code + PKCE round-trip headlessly and receives a
// JWKS-verifiable identity assertion carrying ONLY coarse claims.
func TestAcceptance_AuthCodePKCE(t *testing.T) {
	base := startIDP(t)
	client := noRedirectClient()

	// (2) Discovery.
	var disc discovery
	resp, err := http.Get(base + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("discovery status %d: %s", resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, &disc); err != nil {
		t.Fatalf("discovery decode: %v (%s)", err, body)
	}
	for name, got := range map[string]string{
		"issuer":                        disc.Issuer,
		"authorization_endpoint":        disc.AuthorizationEndpoint,
		"token_endpoint":                disc.TokenEndpoint,
		"jwks_uri":                      disc.JwksURI,
		"device_authorization_endpoint": disc.DeviceAuthorizationEndpoint,
	} {
		if got == "" {
			t.Fatalf("discovery: %s missing", name)
		}
	}

	// (3) PKCE S256.
	verifier := randString(t, 32)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state := randString(t, 16)
	nonce := randString(t, 16)

	// authorization_endpoint -> redirect to /login?authRequestID=...
	authz := disc.AuthorizationEndpoint + "?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {testClientID},
		"redirect_uri":          {testRedirectURI},
		"scope":                 {"openid profile email"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()
	loginLoc := getRedirect(t, client, authz)
	authRequestID := loginLoc.Query().Get("authRequestID")
	if authRequestID == "" {
		t.Fatalf("authorize redirect had no authRequestID: %s", loginLoc)
	}

	// (3b) Headless passwordless login as alice -> redirect to auth callback.
	loginURL := base + "/login?" + url.Values{
		"authRequestID": {authRequestID},
		"identity":      {"alice"},
	}.Encode()
	callbackLoc := getRedirect(t, client, loginURL)

	// callback -> redirect to redirect_uri?code=...&state=...
	codeLoc := getRedirect(t, client, callbackLoc.String())
	if got := codeLoc.Query().Get("state"); got != state {
		t.Fatalf("state mismatch: got %q want %q", got, state)
	}
	code := codeLoc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect: %s", codeLoc)
	}

	// (3c) Exchange code at token_endpoint (confidential client + PKCE verifier).
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {testRedirectURI},
		"code_verifier": {verifier},
	}
	tokReq, _ := http.NewRequest(http.MethodPost, disc.TokenEndpoint, strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokReq.SetBasicAuth(testClientID, testClientSecret)
	tokResp, err := http.DefaultClient.Do(tokReq)
	if err != nil {
		t.Fatalf("token POST: %v", err)
	}
	tokBody, _ := io.ReadAll(tokResp.Body)
	tokResp.Body.Close()
	if tokResp.StatusCode != 200 {
		t.Fatalf("token status %d: %s", tokResp.StatusCode, tokBody)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(tokBody, &tok); err != nil {
		t.Fatalf("token decode: %v (%s)", err, tokBody)
	}
	if tok.IDToken == "" {
		t.Fatalf("no id_token in token response: %s", tokBody)
	}

	// (4) Verify id_token signature against the served JWKS.
	claims := verifyIDToken(t, disc.JwksURI, tok.IDToken)

	// (4b) iss / aud / exp.
	if claims["iss"] != disc.Issuer {
		t.Errorf("iss = %v, want %v", claims["iss"], disc.Issuer)
	}
	if !audienceContains(claims["aud"], testClientID) {
		t.Errorf("aud = %v, want to contain %q", claims["aud"], testClientID)
	}
	exp, ok := claims["exp"].(float64)
	if !ok || int64(exp) <= time.Now().Unix() {
		t.Errorf("exp = %v, want a future unix time", claims["exp"])
	}

	// (5) Coarse claims present.
	if claims["sub"] != "alice" {
		t.Errorf("sub = %v, want \"alice\"", claims["sub"])
	}
	if claims["name"] != "Alice Admin" {
		t.Errorf("name = %v, want \"Alice Admin\"", claims["name"])
	}
	apps, ok := claims["apps"].([]any)
	if !ok || len(apps) == 0 {
		t.Errorf("apps claim missing or empty: %v", claims["apps"])
	} else if apps[0] != testClientID {
		t.Errorf("apps[0] = %v, want %q", apps[0], testClientID)
	}

	// (5b) Downstream (app-identity) claims MUST be absent from the id_token.
	for _, forbidden := range []string{"roles", "tenant", "groups", "permissions", "scope", "scopes"} {
		if _, present := claims[forbidden]; present {
			t.Errorf("id_token must NOT carry %q (downstream app-identity claim), got %v", forbidden, claims[forbidden])
		}
	}
}

// TestAcceptance_DeviceGrant checks the device_authorization endpoint issues a
// code (RFC 8628), the sub-test the CLI will later rely on.
func TestAcceptance_DeviceGrant(t *testing.T) {
	base := startIDP(t)
	form := url.Values{"client_id": {testClientID}, "scope": {"openid"}}
	req, _ := http.NewRequest(http.MethodPost, base+"/device_authorization", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(testClientID, testClientSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("device POST: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("device status %d: %s", resp.StatusCode, b)
	}
	var dev struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
	}
	if err := json.Unmarshal(b, &dev); err != nil {
		t.Fatalf("device decode: %v (%s)", err, b)
	}
	if dev.DeviceCode == "" || dev.UserCode == "" {
		t.Fatalf("device grant missing codes: %s", b)
	}
}

// verifyIDToken fetches the JWKS, verifies the JWT signature with the matching
// key, and returns the decoded claims.
func verifyIDToken(t *testing.T, jwksURI, idToken string) map[string]any {
	t.Helper()
	jws, err := jose.ParseSigned(idToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("parse id_token: %v", err)
	}
	if len(jws.Signatures) == 0 {
		t.Fatal("id_token has no signatures")
	}
	kid := jws.Signatures[0].Header.KeyID

	resp, err := http.Get(jwksURI)
	if err != nil {
		t.Fatalf("JWKS GET: %v", err)
	}
	jwksBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(jwksBody, &jwks); err != nil {
		t.Fatalf("JWKS decode: %v (%s)", err, jwksBody)
	}
	keys := jwks.Key(kid)
	if len(keys) == 0 {
		t.Fatalf("no JWKS key for kid %q; JWKS=%s", kid, jwksBody)
	}
	payload, err := jws.Verify(keys[0])
	if err != nil {
		t.Fatalf("id_token signature verification failed: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("claims decode: %v", err)
	}
	return claims
}

func audienceContains(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}
