// Package idp implements devedge-idp, a development-only OpenID Provider.
//
// devedge-idp is the "who you are" tier of the WS-026 two-tier token model: it
// authenticates a developer passwordlessly and issues a signed identity
// assertion (id_token). It does NOT mint app API bearer tokens, and it does NOT
// author in-app roles/tenant/scopes — a separate "app identity" does the OIDC
// dance with this IdP and mints the real app bearer downstream. The id_token
// therefore carries only coarse claims: identity (sub/name/email) plus an
// app-access entitlement (apps). See EmittedClaims and setCoarseUserinfo.
//
// It is NON-PRODUCTION: passwordless, dummy client secrets, in-memory state.
package idp

import (
	"crypto/sha256"
	"log/slog"
	"time"

	"golang.org/x/text/language"

	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/infobloxopen/devedge-sdk/server"
)

// Config configures the dev IdP wiring.
type Config struct {
	// Issuer, when set, pins a static issuer (e.g. "http://idp.dev.test"). When
	// empty the issuer is derived per-request from the Host header, which lets the
	// OP run on an ephemeral (:0) port without knowing its address in advance.
	Issuer string
	// RedirectURIs seeds the example client's allowed redirect_uris.
	RedirectURIs []string
	// Logger is passed to the OP; defaults to slog.Default().
	Logger *slog.Logger
}

// New builds the OP plus the passwordless login handler and returns them as SDK
// HTTPHandlers ready to mount via server.Config.HTTPHandlers. It also returns
// the Storage so a caller can register more clients at runtime (the seam the
// future `de idp clients sync` uses).
//
// The OP claims the "/" pattern — it serves discovery, authorize, token, keys
// and the device endpoint on its own subpaths. The login page is mounted on the
// more specific "/login", which the SDK mux routes ahead of the "/" catch-all.
func New(cfg Config) ([]server.HTTPHandler, *Storage, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	storage, err := NewStorage(seedClients(cfg.RedirectURIs...))
	if err != nil {
		return nil, nil, err
	}
	provider, err := newProvider(cfg.Issuer, storage, logger)
	if err != nil {
		return nil, nil, err
	}
	login := newLoginHandler(storage, provider)
	handlers := []server.HTTPHandler{
		{Pattern: loginPath, Handler: login},
		{Pattern: "/", Handler: provider},
	}
	return handlers, storage, nil
}

func newProvider(issuer string, storage op.Storage, logger *slog.Logger) (op.OpenIDProvider, error) {
	// Dev token-encryption key: deterministic and non-secret. Fine for dev; a
	// real deployment supplies a securely-managed random key.
	key := sha256.Sum256([]byte("devedge-idp-dev-key"))
	config := &op.Config{
		CryptoKey:             key,
		CodeMethodS256:        true, // enables PKCE (S256)
		AuthMethodPost:        true, // allow client_secret_post as well as Basic
		GrantTypeRefreshToken: true,
		SupportedUILocales:    []language.Tag{language.English},
		DeviceAuthorization: op.DeviceAuthorizationConfig{
			Lifetime:     5 * time.Minute,
			PollInterval: 5 * time.Second,
			UserFormPath: loginPath,
			UserCode:     op.UserCodeBase20,
		},
	}
	opts := []op.Option{
		op.WithAllowInsecure(), // dev: permit http issuers
		op.WithLogger(logger.WithGroup("op")),
	}
	if issuer != "" {
		return op.NewOpenIDProvider(issuer, config, storage, opts...)
	}
	// Dynamic issuer derived from the request Host; path "" => issuer has no path.
	return op.NewDynamicOpenIDProvider("", config, storage, opts...)
}
