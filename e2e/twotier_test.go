// Package e2e is the end-to-end acceptance test for the WS-026 two-tier token
// trust chain. It stitches the REAL dev IdP (devedge-idp) together with the
// devedge-sdk authn seams and proves the whole model works headlessly:
//
//	Role 1 — the IdP issues a COARSE identity assertion (id_token: identity +
//	         app-access only). It never mints an API bearer.
//	Role 2 — the app identity is a confidential OIDC relying party that completes
//	         the auth-code + PKCE dance with the IdP, authors the rich app claims
//	         (tenant/groups) via a ClaimsMapper, and MINTS + signs its own app
//	         bearer with its own Issuer.
//	Role 3 — the microservice VERIFIES the app bearer against the APP's
//	         issuer/JWKS (signature + iss/aud/exp) and drives authz from the
//	         verified principal — fail closed.
//
// TestE2E_TwoTierTrustChain proves the default (two-tier) topology; the
// microservice's Authenticator references only the app's issuer/JWKS, never the
// IdP — so pointing the relying party at a different upstream needs zero
// microservice change (D2). TestE2E_SingleIssuer proves the same verify seam is
// topology-agnostic: trusting the IdP directly is only a config change.
package e2e

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/infobloxopen/devedge-idp/internal/idp"
	"github.com/infobloxopen/devedge-sdk/authn"
	"github.com/infobloxopen/devedge-sdk/authn/oidc"
	"github.com/infobloxopen/devedge-sdk/authz"
	"github.com/infobloxopen/devedge-sdk/server"
)

// Seeded dev client credentials (internal/idp/clients.go) and the app identity's
// callback (seeded into the IdP as an allowed redirect_uri by startIDP). alice's
// app-access entitlement (internal/idp/identities.go) is ["devedge-idp-example"],
// so the claims-mapper's app name below must match it for WithRequireEntitlement.
const (
	seededClientID     = "devedge-idp-example"
	seededClientSecret = "dev-secret"
	appRedirectURI     = "http://127.0.0.1:38080/callback"
)

// The app identity's own issuer + the microservice's audience. These belong to
// the APP, not the IdP — the microservice trusts only these in two-tier.
const (
	appIssuerURL = "https://orders.app.dev.test"
	appAudience  = "orders-api"
)

// probeMethod / probeServiceDesc: a one-method gRPC service whose handler is a
// no-op, used to drive a real request through the interceptor chain server.New
// builds (mirrors devedge-sdk server_test.go).
const probeMethod = "/test.v1.Svc/Do"

var probeServiceDesc = grpc.ServiceDesc{
	ServiceName: "test.v1.Svc",
	HandlerType: (*any)(nil),
	Methods: []grpc.MethodDesc{{
		MethodName: "Do",
		Handler: func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
			in := new(emptypb.Empty)
			if err := dec(in); err != nil {
				return nil, err
			}
			h := func(ctx context.Context, req any) (any, error) { return &emptypb.Empty{}, nil }
			if interceptor == nil {
				return h(ctx, in)
			}
			return interceptor(ctx, in, &grpc.UnaryServerInfo{Server: srv, FullMethod: probeMethod}, h)
		},
	}},
}

// TestE2E_TwoTierTrustChain is the money test: identity from the real IdP → the
// app identity authors claims and mints the app bearer → the microservice
// verifies THE APP's bearer and authorizes from the verified principal.
func TestE2E_TwoTierTrustChain(t *testing.T) {
	ctx := context.Background()
	base := startIDP(t)
	client := noRedirectClient()

	// --- Role 2: the app identity completes the OIDC dance with the IdP. ---
	rp, err := oidc.NewRelyingParty(ctx, oidc.RelyingPartyConfig{
		IssuerURL:    base,
		ClientID:     seededClientID,
		ClientSecret: seededClientSecret,
		RedirectURL:  appRedirectURI,
		Scopes:       []string{"profile", "email"},
	})
	if err != nil {
		t.Fatalf("NewRelyingParty: %v", err)
	}
	verifier := oauth2.GenerateVerifier()
	state := randString(t, 16)
	code := driveLoginAsAlice(t, base, client, rp.AuthCodeURL(state, verifier))

	id, err := rp.Exchange(ctx, code, verifier)
	if err != nil {
		t.Fatalf("RelyingParty.Exchange: %v", err)
	}
	// The IdP asserts COARSE identity only.
	if id.Subject != "alice" {
		t.Fatalf("identity subject = %q, want \"alice\"", id.Subject)
	}
	if len(id.Apps) == 0 {
		t.Fatalf("identity app-access (Apps) is empty; want the coarse entitlement")
	}
	// No downstream (app-identity) claims may ride on the coarse assertion.
	for _, forbidden := range []string{"tenant", "roles", "groups", "scope", "scopes", "permissions"} {
		if _, present := id.Raw[forbidden]; present {
			t.Errorf("coarse id assertion must NOT carry %q, got %v", forbidden, id.Raw[forbidden])
		}
	}

	// --- Role 2: author the app-specific principal (tenant/groups). ---
	// The mapper's app name matches alice's app-access entitlement, so
	// WithRequireEntitlement passes; a non-entitled identity would be rejected.
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

	// --- Role 2: mint + sign the app bearer for the authored principal. ---
	iss, err := oidc.NewIssuer(appIssuerURL, []string{appAudience})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	appBearer, err := iss.Mint(ctx, principal)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// --- Role 3: the microservice verifies the APP's bearer. ---
	// It references only the app's issuer + JWKS (iss.KeySet()); it has NO
	// reference to the IdP anywhere below. THIS is the "swap the upstream IdP =
	// no microservice change" proof: point the relying party (Role 2) at Okta or
	// Keycloak and nothing here changes, because the trust anchor is the app.
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

	// (1) The money assertion: the full chain resolves to an allowed call.
	if err := call(conn, bearerMD(appBearer)); err != nil {
		t.Fatalf("two-tier chain: app bearer must be allowed, got %v", err)
	}
	// (2) No bearer -> empty verified principal -> default-deny.
	if err := call(conn, nil); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("no bearer: want PermissionDenied, got %v", err)
	}
	// (3) Garbage bearer -> fail closed at authn.
	if err := call(conn, bearerMD("garbage.not.a.jwt")); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("garbage bearer: want Unauthenticated, got %v", err)
	}
	// (4) Bearer minted by a DIFFERENT (untrusted) issuer -> fail closed: the
	// microservice trusts only the app's issuer/JWKS, so neither its key nor its
	// `iss` is accepted here.
	evil, err := oidc.NewIssuer("https://evil.example", []string{appAudience})
	if err != nil {
		t.Fatalf("NewIssuer(evil): %v", err)
	}
	evilBearer, err := evil.Mint(ctx, principal)
	if err != nil {
		t.Fatalf("Mint(evil): %v", err)
	}
	if err := call(conn, bearerMD(evilBearer)); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("wrong-issuer bearer: want Unauthenticated, got %v", err)
	}
}

// TestE2E_SingleIssuer proves the verify seam is topology-agnostic: with only a
// config change (trust the IdP's issuer/JWKS directly, aud = the client_id the
// IdP puts on id_tokens) a microservice authorizes the IdP's own id_token — no
// Role 2 mint. Single-issuer carries only coarse claims, so authz grants the
// subject directly.
func TestE2E_SingleIssuer(t *testing.T) {
	base := startIDP(t)
	client := noRedirectClient()
	disc := fetchDiscovery(t, base)

	// Role 1 only: drive the IdP login as alice and take the RAW id_token.
	rawIDToken := loginForIDToken(t, base, client, disc)

	// Role 3: this microservice trusts the IdP DIRECTLY (single-issuer config).
	auth, err := oidc.NewAuthenticator(oidc.Config{
		Keys:             &oidc.RemoteJWKS{URL: disc.JwksURI},
		ExpectedIssuer:   disc.Issuer,
		ExpectedAudience: seededClientID, // id_tokens carry aud = client_id
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	addr := serveProbe(t, server.Config{
		GRPCAddr: ":0",
		Rules:    []authz.MethodRule{{Method: probeMethod, Verb: authz.Get, Resource: "order"}},
		Authorizer: authz.NewDevAuthorizer(authz.Grant{
			Tenant: "*", Subjects: []string{"alice"}, Verbs: []authz.Verb{"*"}, Resource: "*",
		}),
		Authenticator: auth,
	})
	conn := dial(t, addr)

	// The IdP's id_token verifies against the IdP's JWKS and authorizes.
	if err := call(conn, bearerMD(rawIDToken)); err != nil {
		t.Fatalf("single-issuer: IdP id_token must be allowed, got %v", err)
	}
	// Still fail closed on a garbage token.
	if err := call(conn, bearerMD("garbage.not.a.jwt")); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("single-issuer garbage bearer: want Unauthenticated, got %v", err)
	}
}

// --- IdP boot + flow-driver helpers (mirror cmd/idp/acceptance_test.go) ------

// startIDP boots the real IdP through the exact server.New(...).Serve(ctx) path
// the binary uses, on ephemeral loopback ports, seeding appRedirectURI as an
// allowed redirect, and returns its base URL (which is also its dynamic issuer).
func startIDP(t *testing.T) (base string) {
	t.Helper()
	handlers, _, err := idp.New(idp.Config{RedirectURIs: []string{appRedirectURI}})
	if err != nil {
		t.Fatalf("idp.New: %v", err)
	}
	srv, err := server.New(server.Config{
		GRPCAddr:     "127.0.0.1:0",
		HTTPAddr:     "127.0.0.1:0",
		HTTPHandlers: handlers,
	})
	if err != nil {
		t.Fatalf("server.New(idp): %v", err)
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
	t.Fatal("idp did not bind within 5s")
	return ""
}

// noRedirectClient never follows redirects, so each Location can be inspected.
func noRedirectClient() *http.Client {
	return &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// getRedirect issues a GET to rawURL and returns the (absolute) Location of the
// redirect response.
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

// driveLoginAsAlice follows the auth-code redirect chain headlessly —
// authorize -> /login (pick alice) -> callback -> redirect_uri?code=... — and
// returns the authorization code. authURL is the fully-built authorization URL
// (from RelyingParty.AuthCodeURL or an assembled single-issuer URL).
func driveLoginAsAlice(t *testing.T, base string, client *http.Client, authURL string) string {
	t.Helper()
	loginLoc := getRedirect(t, client, authURL)
	authRequestID := loginLoc.Query().Get("authRequestID")
	if authRequestID == "" {
		t.Fatalf("authorize redirect had no authRequestID: %s", loginLoc)
	}
	loginURL := base + "/login?" + url.Values{
		"authRequestID": {authRequestID},
		"identity":      {"alice"},
	}.Encode()
	callbackLoc := getRedirect(t, client, loginURL)
	codeLoc := getRedirect(t, client, callbackLoc.String())
	code := codeLoc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in final redirect: %s", codeLoc)
	}
	return code
}

// discovery is the subset of the OIDC discovery document the single-issuer test
// needs.
type discovery struct {
	Issuer                      string `json:"issuer"`
	AuthorizationEndpoint       string `json:"authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	JwksURI                     string `json:"jwks_uri"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
}

func fetchDiscovery(t *testing.T, base string) discovery {
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
	if disc.Issuer == "" || disc.AuthorizationEndpoint == "" || disc.TokenEndpoint == "" || disc.JwksURI == "" {
		t.Fatalf("discovery missing endpoints: %+v", disc)
	}
	return disc
}

// loginForIDToken drives the IdP auth-code + PKCE login as alice and exchanges
// the code for the RAW id_token string (the single-issuer bearer).
func loginForIDToken(t *testing.T, base string, client *http.Client, disc discovery) string {
	t.Helper()
	verifier := randString(t, 32)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state := randString(t, 16)

	authURL := disc.AuthorizationEndpoint + "?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {seededClientID},
		"redirect_uri":          {appRedirectURI},
		"scope":                 {"openid profile email"},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()
	code := driveLoginAsAlice(t, base, client, authURL)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {appRedirectURI},
		"code_verifier": {verifier},
	}
	req, _ := http.NewRequest(http.MethodPost, disc.TokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(seededClientID, seededClientSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token POST: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token status %d: %s", resp.StatusCode, body)
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		t.Fatalf("token decode: %v (%s)", err, body)
	}
	if tok.IDToken == "" {
		t.Fatalf("no id_token in token response: %s", body)
	}
	return tok.IDToken
}

func randString(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// --- microservice (Role 3) test rig ------------------------------------------

// serveProbe builds a microservice from cfg, registers the probe service, serves
// it on a loopback listener, and returns the dial address. It stops on cleanup.
func serveProbe(t *testing.T, cfg server.Config) (addr string) {
	t.Helper()
	s, err := server.New(cfg)
	if err != nil {
		t.Fatalf("server.New(microservice): %v", err)
	}
	s.GRPCServer().RegisterService(&probeServiceDesc, struct{}{})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = s.GRPCServer().Serve(lis) }()
	t.Cleanup(func() { s.GRPCServer().Stop() })
	return lis.Addr().String()
}

func dial(t *testing.T, addr string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func call(conn *grpc.ClientConn, md metadata.MD) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if md != nil {
		ctx = metadata.NewOutgoingContext(ctx, md)
	}
	return conn.Invoke(ctx, probeMethod, &emptypb.Empty{}, &emptypb.Empty{})
}

func bearerMD(token string) metadata.MD {
	return metadata.Pairs("authorization", "Bearer "+token)
}
