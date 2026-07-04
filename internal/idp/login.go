package idp

import (
	"context"
	"fmt"
	"html"
	"net/http"

	"github.com/zitadel/oidc/v3/pkg/op"
)

// queryAuthRequestID is the query parameter carrying the OP's auth request id
// through the login step.
const queryAuthRequestID = "authRequestID"

// queryIdentity selects a built-in identity for headless (non-interactive)
// login, so an automated test or CLI can complete the flow without a browser.
const queryIdentity = "identity"

// loginHandler serves the passwordless login page. Unauthenticated auth requests
// are redirected here by the OP (see Client.LoginURL). A user "logs in" by
// picking a built-in identity — no credential is checked. It supports both a
// minimal interactive HTML page and a headless selection via the `identity`
// parameter. It is wrapped in an issuer interceptor so op.AuthCallbackURL can
// build the absolute callback URL from the request host.
type loginHandler struct {
	storage  *Storage
	callback func(context.Context, string) string
}

// newLoginHandler wires the login handler to the provider's auth callback and
// issuer, and returns a ready-to-mount http.Handler.
func newLoginHandler(storage *Storage, provider op.OpenIDProvider) http.Handler {
	l := &loginHandler{
		storage:  storage,
		callback: op.AuthCallbackURL(provider),
	}
	interceptor := op.NewIssuerInterceptor(provider.IssuerFromRequest)
	return interceptor.Handler(http.HandlerFunc(l.serve))
}

func (l *loginHandler) serve(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "cannot parse form: "+err.Error(), http.StatusBadRequest)
		return
	}
	authRequestID := r.Form.Get(queryAuthRequestID)
	if authRequestID == "" {
		http.Error(w, "missing "+queryAuthRequestID, http.StatusBadRequest)
		return
	}

	// Headless / non-interactive selection: complete immediately.
	if identity := r.Form.Get(queryIdentity); identity != "" {
		if err := l.storage.CompleteAuthRequest(authRequestID, identity); err != nil {
			http.Error(w, "login failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, l.callback(r.Context(), authRequestID), http.StatusFound)
		return
	}

	// Interactive: render a minimal identity picker.
	l.renderPicker(w, authRequestID)
}

func (l *loginHandler) renderPicker(w http.ResponseWriter, authRequestID string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8">`+
		`<title>devedge-idp — pick an identity</title></head><body>`+
		`<h1>devedge-idp (development only)</h1>`+
		`<p>Passwordless dev login. Pick who you are — no credential is checked.</p><ul>`)
	for _, id := range Identities {
		href := fmt.Sprintf("%s?%s=%s&%s=%s",
			loginPath, queryAuthRequestID, html.EscapeString(authRequestID),
			queryIdentity, html.EscapeString(id.Subject))
		fmt.Fprintf(w, `<li><a href="%s">%s — %s</a></li>`,
			href, html.EscapeString(id.Subject), html.EscapeString(id.Name))
	}
	fmt.Fprint(w, `</ul></body></html>`)
}
