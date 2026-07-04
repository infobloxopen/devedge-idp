package idp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// EmittedClaims is the exhaustive, documented set of claim keys the IdP will
// ever put on an id_token: coarse identity plus the app-access entitlement.
// It is intentionally small. The keys explicitly NOT here — tenant, roles,
// groups, permissions, scope-as-authz — are authored downstream by the app
// identity, never by the IdP (WS-026 rule D11). appsClaim is the app-access
// claim name.
const appsClaim = "apps"

var EmittedClaims = []string{"sub", "name", "email", "email_verified", appsClaim}

// Storage is an in-memory op.Storage for the dev IdP. It is passwordless:
// authentication is completing an auth request for a chosen built-in identity,
// with no credential check. Everything lives in memory and resets on restart.
type Storage struct {
	lock         sync.Mutex
	authRequests map[string]*authRequest
	codes        map[string]string // code -> authRequestID
	tokens       map[string]*token
	refreshers   map[string]*refreshToken
	clients      map[string]*Client
	signingKey   signingKey
	deviceCodes  map[string]*deviceEntry // deviceCode -> entry
	userCodes    map[string]string       // userCode -> deviceCode
}

// Compile-time proof we satisfy the interfaces the OP needs.
var (
	_ op.Storage                    = (*Storage)(nil)
	_ op.DeviceAuthorizationStorage = (*Storage)(nil)
	_ op.CanSetUserinfoFromRequest  = (*Storage)(nil)
)

// NewStorage builds the storage, generating a fresh RSA signing key at boot
// (one key is fine for P0; rotation is a later concern). clients is the seeded
// client registry.
func NewStorage(clients map[string]*Client) (*Storage, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	return &Storage{
		authRequests: map[string]*authRequest{},
		codes:        map[string]string{},
		tokens:       map[string]*token{},
		refreshers:   map[string]*refreshToken{},
		clients:      clients,
		signingKey: signingKey{
			id:        uuid.NewString(),
			algorithm: jose.RS256,
			key:       key,
		},
		deviceCodes: map[string]*deviceEntry{},
		userCodes:   map[string]string{},
	}, nil
}

// RegisterClient adds or replaces a confidential client at runtime. This is the
// seam the future `de idp clients sync` will call; it is intentionally exported
// and unused by the P0 wiring.
func (s *Storage) RegisterClient(c *Client) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.clients[c.id] = c
}

// CompleteAuthRequest is the passwordless "login": it binds a chosen built-in
// identity to an auth request and marks it done. No credential is checked. It
// fails closed if the request or identity is unknown.
func (s *Storage) CompleteAuthRequest(authRequestID, subject string) error {
	if identityBySubject(subject) == nil {
		return fmt.Errorf("unknown identity %q", subject)
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	req, ok := s.authRequests[authRequestID]
	if !ok {
		return fmt.Errorf("auth request not found")
	}
	req.userID = subject
	req.authTime = time.Now()
	req.done = true
	return nil
}

// --- signing key -----------------------------------------------------------

type signingKey struct {
	id        string
	algorithm jose.SignatureAlgorithm
	key       *rsa.PrivateKey
}

func (s *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return s.algorithm }
func (s *signingKey) Key() any                                    { return s.key }
func (s *signingKey) ID() string                                  { return s.id }

type publicKey struct{ signingKey }

func (p *publicKey) ID() string                         { return p.id }
func (p *publicKey) Algorithm() jose.SignatureAlgorithm { return p.algorithm }
func (p *publicKey) Use() string                        { return "sig" }
func (p *publicKey) Key() any                           { return &p.signingKey.key.PublicKey }

func (s *Storage) SigningKey(context.Context) (op.SigningKey, error) {
	return &s.signingKey, nil
}

func (s *Storage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{s.signingKey.algorithm}, nil
}

func (s *Storage) KeySet(context.Context) ([]op.Key, error) {
	return []op.Key{&publicKey{s.signingKey}}, nil
}

// --- clients ---------------------------------------------------------------

func (s *Storage) GetClientByClientID(_ context.Context, clientID string) (op.Client, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	c, ok := s.clients[clientID]
	if !ok {
		return nil, fmt.Errorf("client %q not found", clientID)
	}
	return c, nil
}

func (s *Storage) AuthorizeClientIDSecret(_ context.Context, clientID, clientSecret string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	c, ok := s.clients[clientID]
	if !ok {
		return fmt.Errorf("client %q not found", clientID)
	}
	// Dev-only: plain comparison. A real IdP stores a hash.
	if c.secret != clientSecret {
		return errors.New("invalid client secret")
	}
	return nil
}

// --- auth requests ---------------------------------------------------------

func (s *Storage) CreateAuthRequest(_ context.Context, ar *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	if len(ar.Prompt) == 1 && ar.Prompt[0] == "none" {
		// prompt=none can't complete without a session; fail per spec.
		return nil, oidc.ErrLoginRequired()
	}
	req := authRequestFromOIDC(ar, userID)
	req.id = uuid.NewString()
	s.lock.Lock()
	defer s.lock.Unlock()
	s.authRequests[req.id] = req
	return req, nil
}

func (s *Storage) AuthRequestByID(_ context.Context, id string) (op.AuthRequest, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	req, ok := s.authRequests[id]
	if !ok {
		return nil, fmt.Errorf("auth request not found")
	}
	return req, nil
}

func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	s.lock.Lock()
	id, ok := s.codes[code]
	s.lock.Unlock()
	if !ok {
		return nil, fmt.Errorf("code invalid or expired")
	}
	return s.AuthRequestByID(ctx, id)
}

func (s *Storage) SaveAuthCode(_ context.Context, id, code string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.codes[code] = id
	return nil
}

func (s *Storage) DeleteAuthRequest(_ context.Context, id string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	delete(s.authRequests, id)
	for code, reqID := range s.codes {
		if reqID == id {
			delete(s.codes, code)
		}
	}
	return nil
}

// --- tokens ----------------------------------------------------------------

type token struct {
	id            string
	applicationID string
	subject       string
	refreshID     string
	audience      []string
	expiration    time.Time
	scopes        []string
}

type refreshToken struct {
	id            string
	authTime      time.Time
	amr           []string
	audience      []string
	userID        string
	applicationID string
	expiration    time.Time
	scopes        []string
	accessTokenID string
}

func (s *Storage) accessToken(appID, refreshID, subject string, audience, scopes []string) *token {
	t := &token{
		id:            uuid.NewString(),
		applicationID: appID,
		refreshID:     refreshID,
		subject:       subject,
		audience:      audience,
		scopes:        scopes,
		expiration:    time.Now().Add(15 * time.Minute),
	}
	s.tokens[t.id] = t
	return t
}

func (s *Storage) CreateAccessToken(_ context.Context, req op.TokenRequest) (string, time.Time, error) {
	var appID string
	if ar, ok := req.(*authRequest); ok {
		appID = ar.applicationID
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	t := s.accessToken(appID, "", req.GetSubject(), req.GetAudience(), req.GetScopes())
	return t.id, t.expiration, nil
}

func (s *Storage) CreateAccessAndRefreshTokens(_ context.Context, req op.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	appID, authTime, amr := infoFromRequest(req)
	s.lock.Lock()
	defer s.lock.Unlock()

	if currentRefreshToken == "" {
		refreshID := uuid.NewString()
		t := s.accessToken(appID, refreshID, req.GetSubject(), req.GetAudience(), req.GetScopes())
		rt := &refreshToken{
			id:            refreshID,
			authTime:      authTime,
			amr:           amr,
			audience:      t.audience,
			userID:        t.subject,
			applicationID: t.applicationID,
			scopes:        t.scopes,
			expiration:    time.Now().Add(24 * time.Hour),
			accessTokenID: t.id,
		}
		s.refreshers[rt.id] = rt
		return t.id, rt.id, t.expiration, nil
	}

	// Rotation on refresh.
	newRefreshID := uuid.NewString()
	t := s.accessToken(appID, newRefreshID, req.GetSubject(), req.GetAudience(), req.GetScopes())
	old, ok := s.refreshers[currentRefreshToken]
	if !ok {
		return "", "", time.Time{}, errors.New("invalid refresh token")
	}
	delete(s.refreshers, currentRefreshToken)
	delete(s.tokens, old.accessTokenID)
	if old.expiration.Before(time.Now()) {
		return "", "", time.Time{}, errors.New("expired refresh token")
	}
	old.id = newRefreshID
	old.accessTokenID = t.id
	old.expiration = time.Now().Add(24 * time.Hour)
	s.refreshers[newRefreshID] = old
	return t.id, newRefreshID, t.expiration, nil
}

func (s *Storage) TokenRequestByRefreshToken(_ context.Context, refreshTokenID string) (op.RefreshTokenRequest, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	rt, ok := s.refreshers[refreshTokenID]
	if !ok {
		return nil, fmt.Errorf("invalid refresh_token")
	}
	return &refreshTokenRequest{rt}, nil
}

func (s *Storage) TerminateSession(_ context.Context, userID, clientID string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	for id, t := range s.tokens {
		if t.applicationID == clientID && t.subject == userID {
			delete(s.tokens, id)
			delete(s.refreshers, t.refreshID)
		}
	}
	return nil
}

func (s *Storage) GetRefreshTokenInfo(_ context.Context, _ string, tokenOrID string) (string, string, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	rt, ok := s.refreshers[tokenOrID]
	if !ok {
		return "", "", op.ErrInvalidRefreshToken
	}
	return rt.userID, rt.id, nil
}

func (s *Storage) RevokeToken(_ context.Context, tokenOrTokenID, _, clientID string) *oidc.Error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if t, ok := s.tokens[tokenOrTokenID]; ok {
		if t.applicationID != clientID {
			return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
		}
		delete(s.tokens, t.id)
		return nil
	}
	if rt, ok := s.refreshers[tokenOrTokenID]; ok {
		if rt.applicationID != clientID {
			return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
		}
		delete(s.refreshers, rt.id)
		delete(s.tokens, rt.accessTokenID)
	}
	return nil
}

// --- claims (the coarse-claims constraint lives here) ----------------------

// setCoarseUserinfo populates userinfo with ONLY the coarse identity assertion:
// sub, name (profile scope), email (email scope), and the app-access `apps`
// claim (always). It never sets tenant/roles/groups/scope-as-authz — those are
// downstream (app-identity) claims. This one function is the enforcement point
// for WS-026 rule D11.
func (s *Storage) setCoarseUserinfo(info *oidc.UserInfo, subject string, scopes []string) error {
	id := identityBySubject(subject)
	if id == nil {
		return fmt.Errorf("identity %q not found", subject)
	}
	info.Subject = id.Subject
	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeProfile:
			info.Name = id.Name
		case oidc.ScopeEmail:
			if id.Email != "" {
				info.Email = id.Email
				info.EmailVerified = oidc.Bool(true)
			}
		}
	}
	// The app-access entitlement is core to the identity assertion, so it is
	// emitted regardless of the profile/email scopes. It is the only
	// authorization-shaped claim the IdP asserts.
	info.AppendClaims(appsClaim, append([]string(nil), id.Apps...))
	return nil
}

func (s *Storage) SetUserinfoFromRequest(_ context.Context, info *oidc.UserInfo, req op.IDTokenRequest, scopes []string) error {
	return s.setCoarseUserinfo(info, req.GetSubject(), scopes)
}

func (s *Storage) SetUserinfoFromScopes(_ context.Context, _ *oidc.UserInfo, _, _ string, _ []string) error {
	// Deprecated hook; claim assertion is done in SetUserinfoFromRequest.
	return nil
}

func (s *Storage) SetUserinfoFromToken(_ context.Context, info *oidc.UserInfo, tokenID, _, _ string) error {
	s.lock.Lock()
	t, ok := s.tokens[tokenID]
	s.lock.Unlock()
	if !ok {
		return fmt.Errorf("token invalid or expired")
	}
	if t.expiration.Before(time.Now()) {
		return fmt.Errorf("token expired")
	}
	return s.setCoarseUserinfo(info, t.subject, t.scopes)
}

func (s *Storage) SetIntrospectionFromToken(ctx context.Context, resp *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	s.lock.Lock()
	t, ok := s.tokens[tokenID]
	s.lock.Unlock()
	if !ok {
		return fmt.Errorf("token invalid")
	}
	if t.expiration.Before(time.Now()) {
		return fmt.Errorf("token expired")
	}
	for _, aud := range t.audience {
		if aud == clientID {
			info := new(oidc.UserInfo)
			if err := s.setCoarseUserinfo(info, t.subject, t.scopes); err != nil {
				return err
			}
			resp.SetUserInfo(info)
			resp.Scope = t.scopes
			resp.ClientID = t.applicationID
			resp.Expiration = oidc.FromTime(t.expiration)
			return nil
		}
	}
	return fmt.Errorf("token not valid for this client")
}

// GetPrivateClaimsFromScopes returns no custom claims: the IdP does not author
// app-specific claims (that is the app identity's job).
func (s *Storage) GetPrivateClaimsFromScopes(context.Context, string, string, []string) (map[string]any, error) {
	return nil, nil
}

// GetKeyByIDAndClientID is unused: the dev IdP has no JWT-profile clients.
func (s *Storage) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, errors.New("JWT profile clients are not supported")
}

// ValidateJWTProfileScopes allows only the openid scope (JWT profile unused).
func (s *Storage) ValidateJWTProfileScopes(_ context.Context, _ string, scopes []string) ([]string, error) {
	allowed := make([]string, 0, len(scopes))
	for _, sc := range scopes {
		if sc == oidc.ScopeOpenID {
			allowed = append(allowed, sc)
		}
	}
	return allowed, nil
}

func (s *Storage) Health(context.Context) error { return nil }

// --- device authorization (RFC 8628) ---------------------------------------

type deviceEntry struct {
	deviceCode string
	userCode   string
	state      *op.DeviceAuthorizationState
}

func (s *Storage) StoreDeviceAuthorization(_ context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes []string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if _, ok := s.clients[clientID]; !ok {
		return errors.New("client not found")
	}
	if _, ok := s.userCodes[userCode]; ok {
		return op.ErrDuplicateUserCode
	}
	s.deviceCodes[deviceCode] = &deviceEntry{
		deviceCode: deviceCode,
		userCode:   userCode,
		state: &op.DeviceAuthorizationState{
			ClientID: clientID,
			Scopes:   scopes,
			Expires:  expires,
		},
	}
	s.userCodes[userCode] = deviceCode
	return nil
}

func (s *Storage) GetDeviceAuthorizatonState(ctx context.Context, clientID, deviceCode string) (*op.DeviceAuthorizationState, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	e, ok := s.deviceCodes[deviceCode]
	if !ok || e.state.ClientID != clientID {
		return nil, errors.New("device code not found for client")
	}
	return e.state, nil
}

func (s *Storage) GetDeviceAuthorizationByUserCode(_ context.Context, userCode string) (*op.DeviceAuthorizationState, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	e, ok := s.deviceCodes[s.userCodes[userCode]]
	if !ok {
		return nil, errors.New("user code not found")
	}
	return e.state, nil
}

// CompleteDeviceAuthorization binds a chosen identity to a device flow
// (passwordless). Left as a seam for a device login UI; unused by P0 tests.
func (s *Storage) CompleteDeviceAuthorization(_ context.Context, userCode, subject string) error {
	if identityBySubject(subject) == nil {
		return fmt.Errorf("unknown identity %q", subject)
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	e, ok := s.deviceCodes[s.userCodes[userCode]]
	if !ok {
		return errors.New("user code not found")
	}
	e.state.Subject = subject
	e.state.Done = true
	return nil
}

func (s *Storage) DenyDeviceAuthorization(_ context.Context, userCode string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	e, ok := s.deviceCodes[s.userCodes[userCode]]
	if !ok {
		return errors.New("user code not found")
	}
	e.state.Denied = true
	return nil
}

// infoFromRequest pulls the client id, auth time and AMR out of a token request.
func infoFromRequest(req op.TokenRequest) (clientID string, authTime time.Time, amr []string) {
	if ar, ok := req.(*authRequest); ok {
		return ar.applicationID, ar.authTime, ar.GetAMR()
	}
	if rr, ok := req.(*refreshTokenRequest); ok {
		return rr.applicationID, rr.authTime, rr.amr
	}
	return "", time.Time{}, nil
}
