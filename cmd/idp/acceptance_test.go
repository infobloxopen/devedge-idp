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
	"path/filepath"
	"slices"
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
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	DeviceAuthorizationEndpoint       string   `json:"device_authorization_endpoint"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

// getDiscovery fetches and decodes the OIDC discovery document.
func getDiscovery(t *testing.T, base string) discovery {
	t.Helper()
	resp, err := http.Get(base + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status %d: %s", resp.StatusCode, body)
	}
	var disc discovery
	if err := json.Unmarshal(body, &disc); err != nil {
		t.Fatalf("discovery decode: %v (%s)", err, body)
	}
	return disc
}

// pkceS256 returns a fresh PKCE code_verifier and its S256 code_challenge.
func pkceS256(t *testing.T) (verifier, challenge string) {
	t.Helper()
	verifier = randString(t, 32)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// postToken POSTs a form to the token endpoint (no client authentication unless
// the caller set it on the form) and returns the status and body.
func postToken(t *testing.T, tokenEndpoint string, form url.Values) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token POST: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
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

// TestAcceptance_PublicClientPKCE is the public-client acceptance criterion. A
// client declared in the clients file with token_endpoint_auth_method: none
// (RFC 8252 style — no secret) (a) is refused at /authorize unless it sends
// PKCE S256: the OP relays error=invalid_request to its redirect_uri; (b)
// completes the auth-code + PKCE S256 round-trip with NO client authentication
// at the token endpoint and receives a JWKS-verifiable id_token for itself; (c)
// cannot redeem the code without the code_verifier; while (d) a confidential
// client in the same file keeps today's behaviour (PKCE optional). The public
// client registers a portless loopback redirect_uri and the request uses an
// ephemeral port, the RFC 8252 §7.3 CLI pattern.
func TestAcceptance_PublicClientPKCE(t *testing.T) {
	const (
		publicClientID       = "orders-cli"
		publicRedirectURI    = "http://127.0.0.1:38081/callback" // registered as http://127.0.0.1/callback
		confidentialClientID = "orders"
		confidentialRedirect = "https://orders.app.dev.test/callback"
	)
	path := filepath.Join(t.TempDir(), "idp-clients.yaml")
	writeClientsFile(t, path, `
- client_id: orders-cli
  token_endpoint_auth_method: none
  redirect_uris:
    - http://127.0.0.1/callback
  tile:
    name: Orders CLI
- client_id: orders
  client_secret: dev-secret-orders
  redirect_uris:
    - https://orders.app.dev.test/callback
  tile:
    name: Orders
`)
	base := startIDPWithClients(t, path, 50*time.Millisecond)
	client := noRedirectClient()
	disc := getDiscovery(t, base)
	if !slices.Contains(disc.TokenEndpointAuthMethodsSupported, "none") {
		t.Errorf("discovery token_endpoint_auth_methods_supported = %v, want it to include \"none\"", disc.TokenEndpointAuthMethodsSupported)
	}

	authorizeURL := func(clientID, redirectURI, state string, pkce url.Values) string {
		q := url.Values{
			"response_type": {"code"},
			"client_id":     {clientID},
			"redirect_uri":  {redirectURI},
			"scope":         {"openid profile email"},
			"state":         {state},
		}
		for k, v := range pkce {
			q[k] = v
		}
		return disc.AuthorizationEndpoint + "?" + q.Encode()
	}

	// (a) Without PKCE S256 the public client is refused with invalid_request,
	// delivered to its redirect_uri with the state echoed back.
	_, someChallenge := pkceS256(t)
	for _, tc := range []struct {
		name string
		pkce url.Values
	}{
		{"no PKCE", url.Values{}},
		{"plain method", url.Values{"code_challenge": {someChallenge}, "code_challenge_method": {"plain"}}},
		{"S256 method without a challenge", url.Values{"code_challenge_method": {"S256"}}},
	} {
		state := randString(t, 8)
		loc := getRedirect(t, client, authorizeURL(publicClientID, publicRedirectURI, state, tc.pkce))
		if loc.Host != "127.0.0.1:38081" || loc.Path != "/callback" {
			t.Fatalf("%s: redirected to %s, want the client's redirect_uri", tc.name, loc)
		}
		if got := loc.Query().Get("error"); got != "invalid_request" {
			t.Errorf("%s: error = %q, want \"invalid_request\" (%s)", tc.name, got, loc)
		}
		if got := loc.Query().Get("state"); got != state {
			t.Errorf("%s: state = %q, want %q", tc.name, got, state)
		}
		if loc.Query().Get("code") != "" {
			t.Errorf("%s: a code was issued without PKCE S256: %s", tc.name, loc)
		}
	}

	// (b) With PKCE S256 the public client completes the flow: /authorize →
	// /login (headless pick) → callback → code → token exchange with client_id
	// in the form and NO Basic auth.
	authorizeAndLogin := func(challenge string) (code string) {
		t.Helper()
		state := randString(t, 8)
		loginLoc := getRedirect(t, client, authorizeURL(publicClientID, publicRedirectURI, state, url.Values{
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}))
		authRequestID := loginLoc.Query().Get("authRequestID")
		if !strings.HasSuffix(loginLoc.Path, "/login") || authRequestID == "" {
			t.Fatalf("public client with PKCE S256 did not reach /login: %s", loginLoc)
		}
		callbackLoc := getRedirect(t, client, base+"/login?"+url.Values{"authRequestID": {authRequestID}, "identity": {"alice"}}.Encode())
		codeLoc := getRedirect(t, client, callbackLoc.String())
		if got := codeLoc.Query().Get("state"); got != state {
			t.Fatalf("state mismatch: got %q want %q", got, state)
		}
		if code = codeLoc.Query().Get("code"); code == "" {
			t.Fatalf("no code in redirect: %s", codeLoc)
		}
		return code
	}

	verifier, challenge := pkceS256(t)
	code := authorizeAndLogin(challenge)
	status, tokBody := postToken(t, disc.TokenEndpoint, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {publicClientID},
		"code":          {code},
		"redirect_uri":  {publicRedirectURI},
		"code_verifier": {verifier},
	})
	if status != http.StatusOK {
		t.Fatalf("public client token exchange status %d: %s", status, tokBody)
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(tokBody, &tok); err != nil || tok.IDToken == "" {
		t.Fatalf("token decode: %v (%s)", err, tokBody)
	}
	claims := verifyIDToken(t, disc.JwksURI, tok.IDToken)
	if !audienceContains(claims["aud"], publicClientID) {
		t.Errorf("aud = %v, want to contain %q", claims["aud"], publicClientID)
	}
	if claims["sub"] != "alice" {
		t.Errorf("sub = %v, want \"alice\"", claims["sub"])
	}
	if apps, _ := claims["apps"].([]any); !slices.Contains(apps, any(publicClientID)) {
		t.Errorf("apps = %v, want to contain %q (dev identities are entitled to every registered client)", claims["apps"], publicClientID)
	}

	// (c) The code cannot be redeemed without the code_verifier.
	_, challenge2 := pkceS256(t)
	code2 := authorizeAndLogin(challenge2)
	status, body := postToken(t, disc.TokenEndpoint, url.Values{
		"grant_type":   {"authorization_code"},
		"client_id":    {publicClientID},
		"code":         {code2},
		"redirect_uri": {publicRedirectURI},
	})
	if status != http.StatusBadRequest || !strings.Contains(string(body), `"invalid_request"`) {
		t.Errorf("token exchange without code_verifier: status %d body %s, want 400 invalid_request", status, body)
	}

	// (d) The confidential client in the same file is unchanged: no PKCE still
	// reaches /login.
	loginLoc := getRedirect(t, client, authorizeURL(confidentialClientID, confidentialRedirect, "xyz", nil))
	if !strings.HasSuffix(loginLoc.Path, "/login") || loginLoc.Query().Get("authRequestID") == "" {
		t.Fatalf("confidential client without PKCE did not reach /login (regression): %s", loginLoc)
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
