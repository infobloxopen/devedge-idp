package idp

import (
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// loginPath is where the OP redirects an unauthenticated auth request. The
// passwordless login handler (login.go) serves it.
const loginPath = "/login"

// Tile is the launchpad presentation metadata for a client (app). It drives the
// Okta-style app-tile launchpad (login.go / launchpad.go): one tile per
// registered client. It is purely cosmetic and dev-only — it authorizes
// nothing. The JSON tags match the syncable idp-clients.json contract that a
// sibling `de idp clients sync` writes.
type Tile struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	IconURL     string `json:"icon_url"`
	LaunchURL   string `json:"launch_url"`
}

// Client is the storage model of a confidential OAuth2 client — an "app
// identity" in the WS-026 model. For P0 these are dev fixtures with guessable
// secrets; that is intended (dev-only). It implements op.Client.
type Client struct {
	id           string
	secret       string
	redirectURIs []string
	grantTypes   []oidc.GrantType
	authMethod   oidc.AuthMethod
	tile         Tile
}

var _ op.Client = (*Client)(nil)

// GetID returns the client_id.
func (c *Client) GetID() string { return c.id }

// Tile returns the launchpad presentation metadata for this client.
func (c *Client) Tile() Tile { return c.tile }

// RedirectURIs returns the registered redirect_uris for the code flow.
func (c *Client) RedirectURIs() []string { return c.redirectURIs }

// PostLogoutRedirectURIs returns registered post-logout redirects (none in dev).
func (c *Client) PostLogoutRedirectURIs() []string { return []string{} }

// ApplicationType reports the client as a confidential web app.
func (c *Client) ApplicationType() op.ApplicationType { return op.ApplicationTypeWeb }

// AuthMethod is how the client authenticates at the token endpoint.
func (c *Client) AuthMethod() oidc.AuthMethod { return c.authMethod }

// ResponseTypes are the allowed authorization response types (code flow only).
func (c *Client) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}

// GrantTypes are the allowed token grants.
func (c *Client) GrantTypes() []oidc.GrantType { return c.grantTypes }

// LoginURL is where to send the user agent to authenticate. All clients share
// the one passwordless login page.
func (c *Client) LoginURL(id string) string {
	return loginPath + "?" + queryAuthRequestID + "=" + id
}

// AccessTokenType selects opaque bearer access tokens. The IdP does NOT mint
// app API bearers; the access token here is an OIDC-flow artifact only. The
// identity assertion the caller cares about is the signed id_token.
func (c *Client) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeBearer }

// IDTokenLifetime keeps id_tokens short-lived (dev-sane).
func (c *Client) IDTokenLifetime() time.Duration { return 15 * time.Minute }

// DevMode is off; redirect URIs must match exactly.
func (c *Client) DevMode() bool { return false }

// RestrictAdditionalIdTokenScopes passes scopes through unchanged; the IdP
// constrains claims in storage, not here.
func (c *Client) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}

// RestrictAdditionalAccessTokenScopes passes scopes through unchanged.
func (c *Client) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}

// IsScopeAllowed rejects custom scopes; the IdP only understands standard OIDC
// scopes (openid/profile/email). App-specific scopes are the app identity's job.
func (c *Client) IsScopeAllowed(scope string) bool { return false }

// IDTokenUserinfoClaimsAssertion asserts the coarse userinfo claims (name,
// email, apps) into the id_token even though an access token is issued, so a
// consumer gets the identity assertion without a userinfo round-trip.
func (c *Client) IDTokenUserinfoClaimsAssertion() bool { return true }

// ClockSkew applies no clock skew.
func (c *Client) ClockSkew() time.Duration { return 0 }

// --- Client registry -------------------------------------------------------

// exampleClientID / exampleClientSecret are the seeded dev client credentials.
// Guessable by design (dev-only).
const (
	exampleClientID     = "devedge-idp-example"
	exampleClientSecret = "dev-secret"
)

// seedClients returns the initial in-memory client set. Edit here to add more
// dev clients. The example client supports the auth-code (with PKCE), refresh,
// and device grants so the same client can drive every P0 flow.
func seedClients(redirectURIs ...string) map[string]*Client {
	if len(redirectURIs) == 0 {
		redirectURIs = []string{"http://127.0.0.1:0/callback"}
	}
	return map[string]*Client{
		exampleClientID: {
			id:           exampleClientID,
			secret:       exampleClientSecret,
			redirectURIs: redirectURIs,
			authMethod:   oidc.AuthMethodBasic,
			grantTypes: []oidc.GrantType{
				oidc.GrantTypeCode,
				oidc.GrantTypeRefreshToken,
				oidc.GrantTypeDeviceCode,
			},
			tile: Tile{
				Name:        "devedge IdP Example",
				Description: "The seeded example app identity.",
			},
		},
	}
}
