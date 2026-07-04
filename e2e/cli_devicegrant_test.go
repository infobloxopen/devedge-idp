// This file adds TestE2E_CLIDeviceGrant, the WS-026 P3 acceptance test for the
// CLI consumer path. It proves a headless CLI (no browser) obtains an identity
// via the RFC 8628 device authorization grant and that identity drives the SAME
// two-tier chain the browser/auth-code path does:
//
//	device grant  — the CLI POSTs /device_authorization, the device is approved
//	                 headlessly as alice (the dev, passwordless analogue of a
//	                 human typing the user_code and picking themselves), and the
//	                 CLI polls /oauth/token for grant_type=device_code until it
//	                 receives an id_token — the coarse identity (sub + apps only).
//	app identity  — a StaticClaimsMapper authors the app-specific principal
//	                 (tenant/groups) and an Issuer mints + signs the app bearer.
//	microservice  — a devedge-sdk server VERIFIES the app bearer against the
//	                 APP's issuer/JWKS and authorizes from the verified principal.
//
// The device+token endpoints are driven directly with net/http. That is exactly
// the RFC 8628 sequence devedge-cli-sdk's clikit/auth/oidc.Provider performs
// (its requestDeviceCode → poll postToken with
// grant_type=urn:ietf:params:oauth:grant-type:device_code); driving the endpoints
// here lets the test authenticate the seeded CONFIDENTIAL client with its
// client_secret (clikit targets public clients and sends none) and stay fast and
// deterministic — no real poll interval to wait out.
package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/infobloxopen/devedge-sdk/authn"
	"github.com/infobloxopen/devedge-sdk/authn/oidc"
	"github.com/infobloxopen/devedge-sdk/authz"
	"github.com/infobloxopen/devedge-sdk/server"
)

// deviceGrantType is the RFC 8628 token-endpoint grant_type for polling a device
// authorization.
const deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// TestE2E_CLIDeviceGrant proves the CLI consumer path end to end: a device-grant
// id_token → the app identity mints the app bearer → the microservice verifies it.
func TestE2E_CLIDeviceGrant(t *testing.T) {
	ctx := context.Background()
	base := startIDP(t)
	disc := fetchDiscovery(t, base)
	if disc.DeviceAuthorizationEndpoint == "" {
		t.Fatalf("discovery missing device_authorization_endpoint: %+v", disc)
	}

	// --- The CLI front door: RFC 8628 device authorization grant. ---
	// (a) Request a device + user code.
	da := requestDeviceCode(t, disc.DeviceAuthorizationEndpoint)
	if da.DeviceCode == "" || da.UserCode == "" {
		t.Fatalf("device authorization missing codes: %+v", da)
	}
	// The verification_uri the CLI shows its user is the IdP's /login approval path.
	if !strings.Contains(da.VerificationURI, "/login") {
		t.Fatalf("verification_uri %q does not target the /login approval path", da.VerificationURI)
	}

	// (b) Poll BEFORE approval: the OP must answer authorization_pending (no token).
	if tok, code := pollDeviceToken(t, disc.TokenEndpoint, da.DeviceCode); tok != nil || code != "authorization_pending" {
		t.Fatalf("before approval: want authorization_pending, got token=%v code=%q", tok, code)
	}
	t.Log("PENDING: device grant not yet approved -> authorization_pending")

	// (c) Approve headlessly as alice via the /login device-approval path.
	approveDeviceAsAlice(t, base, da.UserCode)
	t.Log("APPROVED: /login?user_code=…&identity=alice completed the device authorization")

	// (d) Poll again -> id_token. The CLI now "has a session".
	tok, code := pollDeviceToken(t, disc.TokenEndpoint, da.DeviceCode)
	if tok == nil {
		t.Fatalf("after approval: want a token, got error code %q", code)
	}
	if tok.IDToken == "" {
		t.Fatal("after approval: token response carried no id_token")
	}
	t.Log("SESSION: device grant exchanged for an id_token")

	// (e) The id_token is the COARSE identity assertion: sub=alice + apps, no more.
	claims := verifyIDTokenClaims(t, disc.JwksURI, tok.IDToken)
	if claims["sub"] != "alice" {
		t.Fatalf("id_token sub = %v, want alice", claims["sub"])
	}
	if apps, ok := claims["apps"].([]any); !ok || len(apps) == 0 {
		t.Fatalf("id_token apps claim missing/empty: %v", claims["apps"])
	}
	for _, forbidden := range []string{"roles", "tenant", "groups", "permissions", "scope", "scopes"} {
		if _, present := claims[forbidden]; present {
			t.Errorf("coarse id_token must NOT carry %q (downstream app-identity claim), got %v", forbidden, claims[forbidden])
		}
	}

	// --- Role 2: the app identity authors the app-specific principal and mints
	// + signs the app bearer (same as twotier_test.go, from the CLI identity). ---
	id := identityFromClaims(claims)
	mapper := authn.NewStaticClaimsMapper(seededClientID, map[string]authz.Principal{
		"alice": {Tenant: "tenant-a", Groups: []string{"admin"}},
	}, authn.WithRequireEntitlement())
	principal, err := mapper.MapClaims(ctx, id)
	if err != nil {
		t.Fatalf("MapClaims: %v", err)
	}
	if principal.Subject != "alice" || principal.Tenant != "tenant-a" || len(principal.Groups) != 1 || principal.Groups[0] != "admin" {
		t.Fatalf("authored principal = %+v, want {alice tenant-a [admin]}", principal)
	}
	iss, err := oidc.NewIssuer(appIssuerURL, []string{appAudience})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	appBearer, err := iss.Mint(ctx, principal)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// --- Role 3: the microservice verifies THE APP's bearer (never the IdP). ---
	auth, err := oidc.NewAuthenticator(oidc.Config{
		Keys:             oidc.StaticKeySet{Keys: iss.KeySet()},
		ExpectedIssuer:   appIssuerURL,
		ExpectedAudience: appAudience,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	addr := serveProbe(t, server.Config{
		GRPCAddr: ":0",
		Rules:    []authz.MethodRule{{Method: probeMethod, Verb: authz.Get, Resource: "order"}},
		Authorizer: authz.NewDevAuthorizer(authz.Grant{
			Tenant: "tenant-a", Subjects: []string{"group:admin"}, Verbs: []authz.Verb{"*"}, Resource: "*",
		}),
		Authenticator: auth,
	})
	conn := dial(t, addr)

	// The money assertion: the CLI-originated identity resolves to an allowed call.
	if err := call(conn, bearerMD(appBearer)); err != nil {
		t.Fatalf("CLI two-tier chain: app bearer must be allowed, got %v", err)
	}
	t.Log("ALLOW: CLI device-grant identity -> app bearer -> microservice OK")
	// No bearer -> empty verified principal -> default-deny.
	if err := call(conn, nil); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("no bearer: want PermissionDenied, got %v", err)
	}
	// Garbage bearer -> fail closed at authn.
	if err := call(conn, bearerMD("garbage.not.a.jwt")); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("garbage bearer: want Unauthenticated, got %v", err)
	}
}

// --- RFC 8628 device-grant client helpers (a faithful headless CLI) ----------

// deviceAuthResponse is the RFC 8628 device-authorization response subset.
type deviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// requestDeviceCode POSTs the device-authorization endpoint as the seeded client
// (confidential -> client_secret via Basic auth) and returns the device+user code.
func requestDeviceCode(t *testing.T, deviceEndpoint string) deviceAuthResponse {
	t.Helper()
	form := url.Values{"client_id": {seededClientID}, "scope": {"openid profile email"}}
	req, _ := http.NewRequest(http.MethodPost, deviceEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(seededClientID, seededClientSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("device_authorization POST: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("device_authorization status %d: %s", resp.StatusCode, body)
	}
	var da deviceAuthResponse
	if err := json.Unmarshal(body, &da); err != nil {
		t.Fatalf("device_authorization decode: %v (%s)", err, body)
	}
	return da
}

// deviceTokenResponse is the token-endpoint payload for the device grant.
type deviceTokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
}

// pollDeviceToken issues one device-grant poll of the token endpoint. On success
// it returns the token response and an empty code; before approval it returns
// (nil, "authorization_pending") — the RFC 8628 pending signal a CLI loops on.
func pollDeviceToken(t *testing.T, tokenEndpoint, deviceCode string) (*deviceTokenResponse, string) {
	t.Helper()
	form := url.Values{"grant_type": {deviceGrantType}, "device_code": {deviceCode}}
	req, _ := http.NewRequest(http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(seededClientID, seededClientSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token POST: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var tr deviceTokenResponse
	_ = json.Unmarshal(body, &tr)
	if resp.StatusCode != http.StatusOK {
		if tr.Error == "" {
			t.Fatalf("token status %d with no error code: %s", resp.StatusCode, body)
		}
		return nil, tr.Error
	}
	return &tr, ""
}

// approveDeviceAsAlice approves the device authorization headlessly as alice via
// the IdP's /login device-approval path.
func approveDeviceAsAlice(t *testing.T, base, userCode string) {
	t.Helper()
	u := base + "/login?" + url.Values{"user_code": {userCode}, "identity": {"alice"}}.Encode()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatalf("device approval GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("device approval status %d: %s", resp.StatusCode, body)
	}
}

// verifyIDTokenClaims fetches the JWKS, verifies the id_token signature with the
// matching key, and returns the decoded claims. It is the app identity's job to
// verify the coarse assertion before authoring app claims.
func verifyIDTokenClaims(t *testing.T, jwksURI, idToken string) map[string]any {
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

// identityFromClaims builds the coarse [authn.Identity] from verified id_token
// claims — the same extraction the SDK's RelyingParty.Exchange performs, here for
// the device-grant path which has no auth-code exchange.
func identityFromClaims(claims map[string]any) authn.Identity {
	id := authn.Identity{Raw: map[string]any{}}
	if s, ok := claims["sub"].(string); ok {
		id.Subject = s
	}
	if s, ok := claims["name"].(string); ok {
		id.Name = s
	}
	if s, ok := claims["email"].(string); ok {
		id.Email = s
	}
	if apps, ok := claims["apps"].([]any); ok {
		for _, a := range apps {
			if s, ok := a.(string); ok {
				id.Apps = append(id.Apps, s)
			}
		}
	}
	for k, v := range claims {
		if k == "apps" {
			continue
		}
		id.Raw[k] = v
	}
	return id
}
