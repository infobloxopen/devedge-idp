package idp

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/url"

	"github.com/zitadel/oidc/v3/pkg/op"
)

// queryAuthRequestID is the query parameter carrying the OP's auth request id
// through the login step.
const queryAuthRequestID = "authRequestID"

// queryIdentity selects a built-in identity for headless (non-interactive)
// login, so an automated test or CLI can complete the flow without a browser.
const queryIdentity = "identity"

// queryUserCode carries the RFC 8628 device grant's user_code through the
// device-approval step. The OP points a device flow's verification_uri at this
// same /login path (op.DeviceAuthorizationConfig.UserFormPath), so a device is
// approved with GET/POST /login?user_code=<code>&identity=<sub>.
const queryUserCode = "user_code"

// loginHandler serves the passwordless login page. Unauthenticated auth requests
// are redirected here by the OP (see Client.LoginURL). A user "logs in" by
// picking a built-in identity — no credential is checked. It supports both a
// minimal interactive HTML page and a headless selection via the `identity`
// parameter. It also serves the RFC 8628 device-grant approval step (the
// verification_uri the OP hands a CLI is this same path): a `user_code` request
// approves that device authorization for the chosen identity. It is wrapped in an
// issuer interceptor so op.AuthCallbackURL can build the absolute callback URL
// from the request host.
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

	// Device-grant approval (RFC 8628 user-verification step). The device flow
	// directs the CLI's user to verification_uri, which is this path
	// (op.DeviceAuthorizationConfig.UserFormPath). Headless dev analogue:
	// user_code + identity approves the device — the passwordless equivalent of a
	// human typing the code shown on the device and picking themselves.
	if userCode := r.Form.Get(queryUserCode); userCode != "" {
		l.serveDeviceApproval(w, r, userCode)
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

// serveDeviceApproval handles the device-grant verification step. With an
// `identity` it completes the device authorization headlessly (the dev,
// passwordless analogue of a human approving the code) and shows a confirmation;
// without one it renders the interactive device picker. It fails closed on an
// unknown identity or user_code (CompleteDeviceAuthorization returns an error).
func (l *loginHandler) serveDeviceApproval(w http.ResponseWriter, r *http.Request, userCode string) {
	identity := r.Form.Get(queryIdentity)
	if identity == "" {
		l.renderDevicePicker(w, userCode)
		return
	}
	if err := l.storage.CompleteDeviceAuthorization(r.Context(), userCode, identity); err != nil {
		http.Error(w, "device approval failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8">`+
		`<title>devedge-idp — device approved</title></head><body>`+
		`<h1>Device approved</h1>`+
		`<p>Approved as <strong>%s</strong>. Return to the command line — it now `+
		`has a session.</p></body></html>`, html.EscapeString(identity))
}

// renderDevicePicker renders the interactive device-approval page: it shows the
// user_code being approved and links to approve it as each built-in identity.
func (l *loginHandler) renderDevicePicker(w http.ResponseWriter, userCode string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8">`+
		`<title>devedge-idp — approve device</title></head><body>`+
		`<h1>devedge-idp (development only)</h1>`+
		`<p>Approve the device requesting code <code>%s</code>. Pick who you are — `+
		`no credential is checked.</p><ul>`, html.EscapeString(userCode))
	for _, id := range Identities {
		href := fmt.Sprintf("%s?%s=%s&%s=%s",
			loginPath, queryUserCode, url.QueryEscape(userCode),
			queryIdentity, url.QueryEscape(id.Subject))
		fmt.Fprintf(w, `<li><a href="%s">%s — %s</a></li>`,
			href, html.EscapeString(id.Subject), html.EscapeString(id.Name))
	}
	fmt.Fprint(w, `</ul></body></html>`)
}
