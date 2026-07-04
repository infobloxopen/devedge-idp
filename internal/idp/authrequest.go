package idp

import (
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// authRequest is the in-memory model of an in-flight authorization request. It
// implements op.AuthRequest. The audience is always just the client_id: the
// id_token is an assertion FOR the app identity that requested it.
type authRequest struct {
	id            string
	applicationID string
	callbackURI   string
	state         string
	nonce         string
	scopes        []string
	responseType  oidc.ResponseType
	responseMode  oidc.ResponseMode
	prompt        []string
	codeChallenge *oidc.CodeChallenge

	userID   string
	authTime time.Time
	done     bool
}

var _ op.AuthRequest = (*authRequest)(nil)

func authRequestFromOIDC(ar *oidc.AuthRequest, userID string) *authRequest {
	var challenge *oidc.CodeChallenge
	if ar.CodeChallenge != "" {
		method := oidc.CodeChallengeMethodPlain
		if ar.CodeChallengeMethod == oidc.CodeChallengeMethodS256 {
			method = oidc.CodeChallengeMethodS256
		}
		challenge = &oidc.CodeChallenge{Challenge: ar.CodeChallenge, Method: method}
	}
	return &authRequest{
		applicationID: ar.ClientID,
		callbackURI:   ar.RedirectURI,
		state:         ar.State,
		nonce:         ar.Nonce,
		scopes:        ar.Scopes,
		responseType:  ar.ResponseType,
		responseMode:  ar.ResponseMode,
		prompt:        oidcPromptToInternal(ar.Prompt),
		codeChallenge: challenge,
		userID:        userID,
	}
}

func oidcPromptToInternal(prompt oidc.SpaceDelimitedArray) []string {
	out := make([]string, 0, len(prompt))
	for _, p := range prompt {
		switch p {
		case oidc.PromptNone, oidc.PromptLogin, oidc.PromptConsent, oidc.PromptSelectAccount:
			out = append(out, p)
		}
	}
	return out
}

func (a *authRequest) GetID() string  { return a.id }
func (a *authRequest) GetACR() string { return "" }
func (a *authRequest) GetAMR() []string {
	if a.done {
		// Passwordless login: no shared-secret factor was presented.
		return []string{"none"}
	}
	return nil
}
func (a *authRequest) GetAudience() []string                 { return []string{a.applicationID} }
func (a *authRequest) GetAuthTime() time.Time                { return a.authTime }
func (a *authRequest) GetClientID() string                   { return a.applicationID }
func (a *authRequest) GetCodeChallenge() *oidc.CodeChallenge { return a.codeChallenge }
func (a *authRequest) GetNonce() string                      { return a.nonce }
func (a *authRequest) GetRedirectURI() string                { return a.callbackURI }
func (a *authRequest) GetResponseType() oidc.ResponseType    { return a.responseType }
func (a *authRequest) GetResponseMode() oidc.ResponseMode    { return a.responseMode }
func (a *authRequest) GetScopes() []string                   { return a.scopes }
func (a *authRequest) GetState() string                      { return a.state }
func (a *authRequest) GetSubject() string                    { return a.userID }
func (a *authRequest) Done() bool                            { return a.done }

// refreshTokenRequest adapts a stored refresh token to op.RefreshTokenRequest.
type refreshTokenRequest struct{ *refreshToken }

var _ op.RefreshTokenRequest = (*refreshTokenRequest)(nil)

func (r *refreshTokenRequest) GetAMR() []string                 { return r.amr }
func (r *refreshTokenRequest) GetAudience() []string            { return r.audience }
func (r *refreshTokenRequest) GetAuthTime() time.Time           { return r.authTime }
func (r *refreshTokenRequest) GetClientID() string              { return r.applicationID }
func (r *refreshTokenRequest) GetScopes() []string              { return r.scopes }
func (r *refreshTokenRequest) GetSubject() string               { return r.userID }
func (r *refreshTokenRequest) SetCurrentScopes(scopes []string) { r.scopes = scopes }
