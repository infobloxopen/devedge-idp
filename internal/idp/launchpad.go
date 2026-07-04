package idp

import (
	"embed"
	"encoding/json"
	"fmt"
	"html"
	"io/fs"
	"net/http"
)

// uiAssets is the built launchpad frontend (ui/, bundled from the
// devedge-ufe-sdk core). The bundle is committed so `go build` and the tests
// need no Node toolchain; rebuild it with `npm --prefix ui run build`.
//
//go:embed all:assets
var uiAssets embed.FS

const (
	// sessionCookie is the IdP-owned SSO session cookie. Its value is the chosen
	// built-in identity's subject. Dev-only: the IdP trusts it as-is (no signing);
	// it maps to a passwordless built-in identity and there is no credential. The
	// launchpad reads it; the IdP owns it.
	sessionCookie = "idp_session"
	// uiScriptPath is the launchpad frontend bundle, served from the embedded
	// assets and loaded by both the picker and the launchpad pages.
	uiScriptPath = "/ui/launchpad.js"
)

// launchpad serves the IdP's own UI through the SDK HTTPHandlers mount seam: a
// public passwordless identity picker (shown with NO SSO session) and an
// Okta-style app-tile launchpad (shown when an SSO session exists). It is
// dev-only — picking an identity checks no credential.
type launchpad struct {
	storage *Storage
}

func newLaunchpad(storage *Storage) *launchpad { return &launchpad{storage: storage} }

// assetsHandler serves the built frontend bundle from the embedded FS at /ui/.
func (l *launchpad) assetsHandler() http.Handler {
	sub, err := fs.Sub(uiAssets, "assets")
	if err != nil {
		panic(err) // the embed directive guarantees assets/ exists
	}
	return http.StripPrefix("/ui/", http.FileServer(http.FS(sub)))
}

// rootWithFallback serves the launchpad/picker on the exact "/" path and
// delegates every other path to the OpenID Provider. The OP owns the "/"
// catch-all in the SDK mux (discovery/authorize/token/keys/device); this
// wrapper carves the home page out for the launchpad while leaving all OIDC
// endpoints with the OP untouched.
func (l *launchpad) rootWithFallback(op http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			l.home(w, r)
			return
		}
		op.ServeHTTP(w, r)
	})
}

// --- SSO session cookie (IdP-owned) ----------------------------------------

func setSessionCookie(w http.ResponseWriter, subject string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    subject,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// sessionIdentity resolves the SSO cookie to a built-in identity, or nil when
// there is no session (or the cookie names an unknown identity).
func sessionIdentity(r *http.Request) *Identity {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	return identityBySubject(c.Value)
}

// --- handlers ---------------------------------------------------------------

// pick establishes the IdP SSO session for a chosen built-in identity
// (passwordless) and lands on the launchpad. It is the standalone-home sibling
// of the mid-/authorize `/login?identity=` path: both share the built-in
// identity list and neither checks a credential.
func (l *launchpad) pick(w http.ResponseWriter, r *http.Request) {
	subject := r.URL.Query().Get(queryIdentity)
	if identityBySubject(subject) == nil {
		http.Error(w, "unknown identity", http.StatusBadRequest)
		return
	}
	setSessionCookie(w, subject)
	http.Redirect(w, r, "/", http.StatusFound)
}

// logout clears the IdP SSO session and returns to the picker.
func (l *launchpad) logout(w http.ResponseWriter, r *http.Request) {
	clearSessionCookie(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

// switchUser is logout plus a return to the picker to choose another identity.
func (l *launchpad) switchUser(w http.ResponseWriter, r *http.Request) {
	clearSessionCookie(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

// --- launchpad data (hydration + machine-assertable JSON) -------------------

type identityView struct {
	Subject string   `json:"subject"`
	Name    string   `json:"name"`
	Email   string   `json:"email,omitempty"`
	Apps    []string `json:"apps,omitempty"`
}

type launchpadData struct {
	Authenticated bool           `json:"authenticated"`
	Identity      *identityView  `json:"identity"`
	Identities    []identityView `json:"identities"`
	Tiles         []ClientTile   `json:"tiles"`
}

func identityViews() []identityView {
	out := make([]identityView, 0, len(Identities))
	for _, id := range Identities {
		out = append(out, identityView{Subject: id.Subject, Name: id.Name})
	}
	return out
}

func (l *launchpad) buildData(r *http.Request) launchpadData {
	d := launchpadData{
		Identities: identityViews(),
		Tiles:      l.storage.ClientTiles(),
	}
	if id := sessionIdentity(r); id != nil {
		d.Authenticated = true
		d.Identity = &identityView{Subject: id.Subject, Name: id.Name, Email: id.Email, Apps: id.Apps}
	}
	return d
}

// data serves the launchpad model as JSON. The frontend hydrates from the inline
// copy on the page; this endpoint is the same model over the wire (used by tests
// and any external tooling that wants the live tile set).
func (l *launchpad) data(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(l.buildData(r))
}

// --- server-rendered pages (progressive enhancement) ------------------------
//
// The pages are rendered server-side (identity names, tile names) so the flow
// works with no JavaScript AND is assertable headlessly at the HTTP level. The
// devedge-ufe-sdk bundle then enhances them: it adapts the IdP session to the
// ufe SessionProvider seam and drives logout/switch/tile-launch through it.

func (l *launchpad) home(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := l.buildData(r)
	if !data.Authenticated {
		l.renderPicker(w, data)
		return
	}
	l.renderLaunchpad(w, data)
}

// hydration emits the launchpad model as an inline JSON <script> the frontend
// bundle reads on load (no extra round-trip).
func hydration(data launchpadData) string {
	b, err := json.Marshal(data)
	if err != nil {
		b = []byte("{}")
	}
	// json.Marshal HTML-escapes <, > and & by default, so a "</script>" inside
	// any string field becomes "</script>" and cannot break out of the
	// script element — safe to inline.
	return `<script id="launchpad-data" type="application/json">` +
		string(b) + `</script>`
}

func pageHead(title string) string {
	return `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width, initial-scale=1">` +
		`<title>` + html.EscapeString(title) + `</title>` +
		`<style>body{font-family:system-ui,sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem}` +
		`.tiles{display:flex;flex-wrap:wrap;gap:1rem;list-style:none;padding:0}` +
		`.tile{display:block;width:12rem;padding:1rem;border:1px solid #ccc;border-radius:.5rem;text-decoration:none;color:inherit;cursor:pointer}` +
		`.tile h3{margin:.2rem 0}.muted{color:#666}.bar{display:flex;gap:1rem;align-items:center}</style></head><body>`
}

const pageFoot = `<script type="module" src="` + uiScriptPath + `"></script></body></html>`

func (l *launchpad) renderPicker(w http.ResponseWriter, data launchpadData) {
	fmt.Fprint(w, pageHead("devedge-idp — pick an identity"))
	fmt.Fprint(w, `<h1>devedge-idp <span class="muted">(development only)</span></h1>`+
		`<p>Passwordless dev login. Pick who you are — no credential is checked.</p>`+
		`<ul class="tiles">`)
	for _, id := range data.Identities {
		href := "/pick?" + queryIdentity + "=" + html.EscapeString(id.Subject)
		fmt.Fprintf(w, `<li><a class="tile" data-action="pick" href="%s">`+
			`<h3>%s</h3><p class="muted">%s</p></a></li>`,
			href, html.EscapeString(id.Name), html.EscapeString(id.Subject))
	}
	fmt.Fprint(w, `</ul>`)
	fmt.Fprint(w, hydration(data))
	fmt.Fprint(w, pageFoot)
}

func (l *launchpad) renderLaunchpad(w http.ResponseWriter, data launchpadData) {
	fmt.Fprint(w, pageHead("devedge-idp — launchpad"))
	name := ""
	if data.Identity != nil {
		name = data.Identity.Name
	}
	fmt.Fprintf(w, `<div class="bar"><h1>Your apps</h1>`+
		`<span class="muted">Signed in as %s</span>`+
		`<a href="/logout" data-action="logout">Log out</a>`+
		`<a href="/switch" data-action="switch">Switch user</a></div>`,
		html.EscapeString(name))
	fmt.Fprint(w, `<ul class="tiles">`)
	for _, ct := range data.Tiles {
		display := ct.Tile.Name
		if display == "" {
			display = ct.ClientID
		}
		launch := ct.Tile.LaunchURL
		href := launch
		if href == "" {
			href = "#"
		}
		fmt.Fprintf(w, `<li><a class="tile" data-launch="%s" href="%s">`+
			`<h3>%s</h3><p class="muted">%s</p></a></li>`,
			html.EscapeString(launch), html.EscapeString(href),
			html.EscapeString(display), html.EscapeString(ct.Tile.Description))
	}
	fmt.Fprint(w, `</ul>`)
	fmt.Fprint(w, hydration(data))
	fmt.Fprint(w, pageFoot)
}
