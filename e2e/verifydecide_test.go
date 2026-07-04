// This file adds TestE2E_VerifyDecide, the WS-026 P1b acceptance test for the
// "dev security suite": it stitches the REAL dev IdP (identity) together with the
// out-of-process dev authz service (decisions) and proves the full two-stage
// pipeline a request traverses in a microservice built on devedge-sdk:
//
//	VERIFY (authn) — the microservice verifies the app bearer against the APP's
//	                 issuer/JWKS (signature + iss/aud/exp) and stashes the
//	                 verified principal. An invalid bearer fails closed here,
//	                 before authz is ever consulted.
//	DECIDE (authz) — the microservice asks the dev authz service (devsvc.Client,
//	                 the same authz.Authorizer seam opaauthz implements in prod)
//	                 whether the verified principal may perform the method's
//	                 verb on its resource. No grant → deny.
//
// The money assertion is the LIVE GRANT FLIP: with a valid, verified bearer the
// SAME call is denied (empty grant store) and then allowed (grant added at
// runtime) with NO restart — proving VERIFY and DECIDE are distinct stages and
// that dev authorization is manipulable live.
package e2e

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/infobloxopen/devedge-sdk/authn"
	"github.com/infobloxopen/devedge-sdk/authn/oidc"
	"github.com/infobloxopen/devedge-sdk/authz"
	"github.com/infobloxopen/devedge-sdk/authz/devsvc"
	"github.com/infobloxopen/devedge-sdk/server"
)

// TestE2E_VerifyDecide proves the full VERIFY→DECIDE pipeline and the live grant
// flip: identity from the real IdP → the app identity authors claims and mints
// the app bearer → the microservice VERIFIES the app bearer, then DECIDES via a
// live dev authz service whose grants flip at runtime.
func TestE2E_VerifyDecide(t *testing.T) {
	ctx := context.Background()
	base := startIDP(t)
	client := noRedirectClient()

	// --- Role 2: the app identity completes the OIDC dance with the IdP, authors
	// the app-specific principal, and mints + signs the app bearer. (Same flow as
	// TestE2E_TwoTierTrustChain.) ---
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

	mapper := authn.NewStaticClaimsMapper(seededClientID, map[string]authz.Principal{
		"alice": {Tenant: "tenant-a", Groups: []string{"admin"}},
	}, authn.WithRequireEntitlement())
	principal, err := mapper.MapClaims(ctx, id)
	if err != nil {
		t.Fatalf("MapClaims: %v", err)
	}
	iss, err := oidc.NewIssuer(appIssuerURL, []string{appAudience})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	appBearer, err := iss.Mint(ctx, principal)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// --- Decisions tier: stand up the dev authz service, EMPTY = default-deny. ---
	store := devsvc.NewStore()
	authzSrv := httptest.NewServer(devsvc.NewHandler(store, devsvc.HandlerOptions{EnableAdmin: true}))
	t.Cleanup(authzSrv.Close)

	// --- Role 3: the microservice with BOTH seams wired. VERIFY = trust the APP's
	// issuer/JWKS (never the IdP). DECIDE = call the dev authz service.
	//
	// Swapping to production is Authorizer: opaauthz.New(...) instead of
	// &devsvc.Client{} — the same authz.Authorizer seam, no other code change. ---
	auth, err := oidc.NewAuthenticator(oidc.Config{
		Keys:             oidc.StaticKeySet{Keys: iss.KeySet()},
		ExpectedIssuer:   appIssuerURL,
		ExpectedAudience: appAudience,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	addr := serveProbe(t, server.Config{
		GRPCAddr:      ":0",
		Rules:         []authz.MethodRule{{Method: probeMethod, Verb: authz.Get, Resource: "order"}},
		Authenticator: auth,
		Authorizer:    &devsvc.Client{BaseURL: authzSrv.URL},
	})
	conn := dial(t, addr)

	// (1) VERIFY passes (alice is a valid, verified principal) but DECIDE denies:
	// the dev authz service has NO grant yet. PermissionDenied (not Unauthenticated)
	// proves authn succeeded and authz is a distinct, second stage.
	if err := call(conn, bearerMD(appBearer)); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("empty grants: verify must pass and decide must DENY -> want PermissionDenied, got %v", err)
	}
	t.Log("DENY: verified bearer, no grant in the dev authz service -> PermissionDenied")

	// (2) FLIP A GRANT LIVE via store.Replace — no restart. The SAME call now
	// returns OK. This is the P1b acceptance.
	store.Replace(authz.Grant{
		Tenant: "tenant-a", Subjects: []string{"group:admin"}, Verbs: []authz.Verb{"*"}, Resource: "*",
	})
	if err := call(conn, bearerMD(appBearer)); err != nil {
		t.Fatalf("after live grant flip (store.Replace): same call must now be ALLOWED, got %v", err)
	}
	t.Log("ALLOW: grant flipped live via store.Replace -> same call now OK")

	// (2b) The admin PUT /v1/grants path flips decisions live too. Clear the store
	// (deny again), then PUT a granting rule set over the wire and re-assert allow.
	store.Replace() // clear -> default-deny
	if err := call(conn, bearerMD(appBearer)); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("after clearing grants: want PermissionDenied, got %v", err)
	}
	putGrants(t, authzSrv.URL, `[{"Tenant":"tenant-a","Subjects":["group:admin"],"Verbs":["*"],"Resource":"*"}]`)
	if err := call(conn, bearerMD(appBearer)); err != nil {
		t.Fatalf("after admin PUT /v1/grants: same call must be ALLOWED, got %v", err)
	}
	t.Log("ALLOW: grant flipped live via PUT /v1/grants -> same call now OK")

	// (3) A garbage bearer fails closed at VERIFY, before authz is even consulted.
	if err := call(conn, bearerMD("garbage.not.a.jwt")); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("garbage bearer: verify must fail closed -> want Unauthenticated, got %v", err)
	}
	t.Log("UNAUTHENTICATED: garbage bearer rejected at verify, before decide")
}

// putGrants replaces the dev authz service's grant set via its admin endpoint.
func putGrants(t *testing.T, baseURL, jsonBody string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, baseURL+"/v1/grants", bytes.NewReader([]byte(jsonBody)))
	if err != nil {
		t.Fatalf("build PUT /v1/grants: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("PUT /v1/grants: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT /v1/grants status = %d, want 204", resp.StatusCode)
	}
}
