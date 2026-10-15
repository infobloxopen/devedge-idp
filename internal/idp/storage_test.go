package idp

import (
	"context"
	"errors"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// newPublicAndConfidentialStorage builds a storage with one public client
// ("orders-cli", token_endpoint_auth_method none) and one confidential client
// ("orders", client_secret_basic).
func newPublicAndConfidentialStorage(t *testing.T) *Storage {
	t.Helper()
	st, err := NewStorage(map[string]*Client{
		"orders-cli": {id: "orders-cli", authMethod: oidc.AuthMethodNone, redirectURIs: []string{"http://127.0.0.1/callback"}},
		"orders":     {id: "orders", secret: "dev-secret-orders", authMethod: oidc.AuthMethodBasic, redirectURIs: []string{"https://orders.app.dev.test/callback"}},
	})
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	return st
}

// TestCreateAuthRequest_PublicClientRequiresPKCES256 guards the /authorize PKCE
// gate: a public client must send code_challenge + code_challenge_method=S256 or
// the request fails with an oidc invalid_request error (which the OP relays to
// the redirect_uri); a confidential client is unaffected — PKCE stays optional
// for it, exactly as before.
func TestCreateAuthRequest_PublicClientRequiresPKCES256(t *testing.T) {
	st := newPublicAndConfidentialStorage(t)
	ctx := context.Background()

	tests := []struct {
		name      string
		clientID  string
		challenge string
		method    oidc.CodeChallengeMethod
		wantErr   bool
	}{
		{"public: S256 challenge accepted", "orders-cli", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", oidc.CodeChallengeMethodS256, false},
		{"public: plain method rejected", "orders-cli", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", oidc.CodeChallengeMethodPlain, true},
		{"public: unknown method rejected", "orders-cli", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", oidc.CodeChallengeMethod("S512"), true},
		{"public: no PKCE at all rejected", "orders-cli", "", "", true},
		{"public: S256 method without a challenge rejected", "orders-cli", "", oidc.CodeChallengeMethodS256, true},
		{"confidential: no PKCE accepted (unchanged)", "orders", "", "", false},
		{"confidential: plain accepted (unchanged)", "orders", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", oidc.CodeChallengeMethodPlain, false},
		{"confidential: S256 accepted", "orders", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", oidc.CodeChallengeMethodS256, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ar := &oidc.AuthRequest{
				ClientID:            tc.clientID,
				RedirectURI:         st.clients[tc.clientID].redirectURIs[0],
				ResponseType:        oidc.ResponseTypeCode,
				Scopes:              []string{oidc.ScopeOpenID},
				State:               "xyz",
				CodeChallenge:       tc.challenge,
				CodeChallengeMethod: tc.method,
			}
			req, err := st.CreateAuthRequest(ctx, ar, "")
			if tc.wantErr {
				var oe *oidc.Error
				if !errors.As(err, &oe) || oe.ErrorType != oidc.InvalidRequest {
					t.Fatalf("CreateAuthRequest error = %v, want an oidc invalid_request error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("CreateAuthRequest: %v", err)
			}
			// The accepted request is stored, and its PKCE challenge is recorded
			// as sent so the token endpoint can verify the code_verifier against it.
			stored, err := st.AuthRequestByID(ctx, req.GetID())
			if err != nil {
				t.Fatalf("AuthRequestByID(%q): %v", req.GetID(), err)
			}
			got := stored.GetCodeChallenge()
			switch {
			case tc.challenge == "" && got != nil:
				t.Errorf("stored code challenge = %+v, want none", got)
			case tc.challenge != "" && (got == nil || got.Challenge != tc.challenge || got.Method != tc.method):
				t.Errorf("stored code challenge = %+v, want {%s %s}", got, tc.challenge, tc.method)
			}
		})
	}

	t.Run("unknown client fails closed", func(t *testing.T) {
		_, err := st.CreateAuthRequest(ctx, &oidc.AuthRequest{ClientID: "ghost", RedirectURI: "https://ghost/cb"}, "")
		if err == nil {
			t.Fatal("CreateAuthRequest for an unregistered client succeeded, want an error")
		}
	})
}

// TestAuthorizeClientIDSecret_PublicClientHasNoSecret guards the token-endpoint
// side: no presented secret — not even the empty string a secretless client
// stores — authenticates a public client, while a confidential client still
// authenticates with its secret and only its secret.
func TestAuthorizeClientIDSecret_PublicClientHasNoSecret(t *testing.T) {
	st := newPublicAndConfidentialStorage(t)
	ctx := context.Background()

	for _, secret := range []string{"", "dev-secret-orders", "anything"} {
		if err := st.AuthorizeClientIDSecret(ctx, "orders-cli", secret); err == nil {
			t.Errorf("AuthorizeClientIDSecret(public client, %q) = nil, want an error", secret)
		}
	}
	if err := st.AuthorizeClientIDSecret(ctx, "orders", "dev-secret-orders"); err != nil {
		t.Errorf("AuthorizeClientIDSecret(confidential client, its secret) = %v, want nil", err)
	}
	for _, secret := range []string{"", "wrong"} {
		if err := st.AuthorizeClientIDSecret(ctx, "orders", secret); err == nil {
			t.Errorf("AuthorizeClientIDSecret(confidential client, %q) = nil, want an error", secret)
		}
	}
}
