package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/infobloxopen/devedge-idp/internal/idp"
	"github.com/infobloxopen/devedge-sdk/server"
)

// The served HTTP contract the launchpad tests assert against (mirrors the
// unexported constants in internal/idp/launchpad.go).
const (
	sessionCookie = "idp_session"
	uiScriptPath  = "/ui/launchpad.js"
)

// startIDPWithClients boots the IdP exactly as the binary does, additionally
// wiring the clients-file hot-reload (idp.WatchClientsFile) at a fast poll
// interval, and returns the base URL. It fails the test if the initial load
// fails, mirroring main().
func startIDPWithClients(t *testing.T, clientsPath string, interval time.Duration) string {
	t.Helper()
	handlers, storage, err := idp.New(idp.Config{})
	if err != nil {
		t.Fatalf("idp.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	if clientsPath != "" {
		onErr := func(e error) { t.Logf("reload clients file: %v", e) }
		if err := idp.WatchClientsFile(ctx, clientsPath, storage, interval, onErr); err != nil {
			t.Fatalf("WatchClientsFile: %v", err)
		}
	}

	srv, err := server.New(server.Config{
		GRPCAddr:     "127.0.0.1:0",
		HTTPAddr:     "127.0.0.1:0",
		HTTPHandlers: handlers,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	go func() { _ = srv.Serve(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ha := srv.HTTPAddr(); ha != "" && ha != "127.0.0.1:0" {
			return "http://" + ha
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("server did not bind within 5s")
	return ""
}

// tileJSON is the on-disk clients-file (idp-clients.json) shape — the exact
// contract a sibling `de idp clients sync` writes.
func writeClientsFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write clients file: %v", err)
	}
	// Force a distinct mtime so the mtime-polling watcher always detects the
	// edit regardless of filesystem timestamp granularity.
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("chtimes clients file: %v", err)
	}
}

// launchpadModel decodes the /launchpad.json response.
type launchpadModel struct {
	Authenticated bool `json:"authenticated"`
	Identity      *struct {
		Subject string `json:"subject"`
		Name    string `json:"name"`
	} `json:"identity"`
	Identities []struct {
		Subject string `json:"subject"`
		Name    string `json:"name"`
	} `json:"identities"`
	Tiles []struct {
		ClientID string `json:"client_id"`
		Tile     struct {
			Name      string `json:"name"`
			LaunchURL string `json:"launch_url"`
		} `json:"tile"`
	} `json:"tiles"`
}

func fetchLaunchpad(t *testing.T, base string) launchpadModel {
	t.Helper()
	resp, err := http.Get(base + "/launchpad.json")
	if err != nil {
		t.Fatalf("GET /launchpad.json: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/launchpad.json status %d: %s", resp.StatusCode, body)
	}
	var m launchpadModel
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("decode /launchpad.json: %v (%s)", err, body)
	}
	return m
}

func tilePresent(m launchpadModel, clientID string) (name string, ok bool) {
	for _, ct := range m.Tiles {
		if ct.ClientID == clientID {
			return ct.Tile.Name, true
		}
	}
	return "", false
}

// TestClientsFileHotReload proves the WS-026 dev-manipulability requirement:
// boot with a clients file → its client is registered and its tile shows on the
// launchpad; edit the file to add a second client → the new client/tile appears
// with no restart.
func TestClientsFileHotReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "idp-clients.json")

	// One client at boot.
	writeClientsFile(t, path, `[
	  {
	    "client_id": "orders",
	    "client_secret": "dev-secret-orders",
	    "redirect_uris": ["https://orders.app.dev.test/callback"],
	    "tile": { "name": "Orders", "description": "Order management", "icon_url": "", "launch_url": "https://orders.app.dev.test/" }
	  }
	]`)

	base := startIDPWithClients(t, path, 50*time.Millisecond)

	// (a) The file client is registered: its tile is on the launchpad.
	m := fetchLaunchpad(t, base)
	name, ok := tilePresent(m, "orders")
	if !ok {
		t.Fatalf("orders tile not present at boot: %+v", m.Tiles)
	}
	if name != "Orders" {
		t.Errorf("orders tile name = %q, want %q", name, "Orders")
	}
	// The seeded client is still present (file augments the seed).
	if _, ok := tilePresent(m, "devedge-idp-example"); !ok {
		t.Errorf("seeded client tile missing after file load: %+v", m.Tiles)
	}

	// (b) The file client can start an /authorize flow (it is a usable client,
	// not just a tile): authorize redirects to /login with an authRequestID.
	client := noRedirectClient()
	authz := base + "/authorize?" + url.Values{
		"response_type": {"code"},
		"client_id":     {"orders"},
		"redirect_uri":  {"https://orders.app.dev.test/callback"},
		"scope":         {"openid profile"},
		"state":         {"xyz"},
	}.Encode()
	loginLoc := getRedirect(t, client, authz)
	if !strings.HasSuffix(loginLoc.Path, "/login") || loginLoc.Query().Get("authRequestID") == "" {
		t.Fatalf("authorize for file client did not redirect to /login: %s", loginLoc)
	}

	// (c) Edit the file to ADD a second client → it appears with no restart.
	writeClientsFile(t, path, `[
	  {
	    "client_id": "orders",
	    "client_secret": "dev-secret-orders",
	    "redirect_uris": ["https://orders.app.dev.test/callback"],
	    "tile": { "name": "Orders", "description": "Order management", "icon_url": "", "launch_url": "https://orders.app.dev.test/" }
	  },
	  {
	    "client_id": "billing",
	    "client_secret": "dev-secret-billing",
	    "redirect_uris": ["https://billing.app.dev.test/callback"],
	    "tile": { "name": "Billing", "description": "Invoices", "icon_url": "", "launch_url": "https://billing.app.dev.test/" }
	  }
	]`)

	deadline := time.Now().Add(3 * time.Second)
	for {
		m = fetchLaunchpad(t, base)
		if bn, ok := tilePresent(m, "billing"); ok {
			if bn != "Billing" {
				t.Errorf("billing tile name = %q, want %q", bn, "Billing")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("billing tile did not appear after hot-reload: %+v", m.Tiles)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// The original client survives the reload.
	if _, ok := tilePresent(m, "orders"); !ok {
		t.Errorf("orders tile disappeared after adding billing: %+v", m.Tiles)
	}
}

// TestClientsFileBadEditKeepsLastGood proves a broken edit never crashes the
// IdP: the last-good client set is kept.
func TestClientsFileBadEditKeepsLastGood(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "idp-clients.json")
	writeClientsFile(t, path, `[
	  {"client_id":"orders","client_secret":"s","redirect_uris":["https://o/cb"],
	   "tile":{"name":"Orders","description":"","icon_url":"","launch_url":"https://o/"}}
	]`)
	base := startIDPWithClients(t, path, 50*time.Millisecond)
	if _, ok := tilePresent(fetchLaunchpad(t, base), "orders"); !ok {
		t.Fatal("orders tile missing at boot")
	}

	// Corrupt the file; the watcher must keep the last-good set.
	writeClientsFile(t, path, `[ this is not json `)
	time.Sleep(300 * time.Millisecond)
	if _, ok := tilePresent(fetchLaunchpad(t, base), "orders"); !ok {
		t.Fatal("orders tile lost after a bad edit; last-good not kept")
	}
}

// TestLaunchpadPickerFlow proves the picker → launchpad → logout flow at the
// HTTP level: no session serves the picker (lists identities); picking alice
// establishes the SSO session and serves the launchpad (lists the registry's
// tiles); logout clears the session and returns to the picker.
func TestLaunchpadPickerFlow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "idp-clients.json")
	writeClientsFile(t, path, `[
	  {"client_id":"orders","client_secret":"s","redirect_uris":["https://orders.app.dev.test/callback"],
	   "tile":{"name":"Orders","description":"Order management","icon_url":"","launch_url":"https://orders.app.dev.test/"}}
	]`)
	base := startIDPWithClients(t, path, 50*time.Millisecond)
	client := noRedirectClient()

	// (1) Home with NO session → picker lists the built-in identities.
	pickerBody := getBody(t, client, base+"/", nil, http.StatusOK)
	for _, want := range []string{"Alice Admin", "Bob Viewer", "Carol", "/pick?identity=alice", uiScriptPath} {
		if !strings.Contains(pickerBody, want) {
			t.Errorf("picker missing %q\n%s", want, pickerBody)
		}
	}

	// (2) Pick alice → SSO session cookie set, redirect to "/".
	pickResp := do(t, client, base+"/pick?identity=alice", nil)
	if pickResp.StatusCode != http.StatusFound {
		t.Fatalf("/pick status %d, want 302", pickResp.StatusCode)
	}
	if loc, _ := pickResp.Location(); loc == nil || loc.Path != "/" {
		t.Fatalf("/pick Location = %v, want /", loc)
	}
	cookie := sessionCookieFrom(pickResp)
	if cookie == nil || cookie.Value != "alice" {
		t.Fatalf("/pick did not set the SSO session cookie to alice: %v", pickResp.Cookies())
	}

	// (3) Home WITH the session → launchpad lists the tiles (seeded + orders).
	lpBody := getBody(t, client, base+"/", cookie, http.StatusOK)
	for _, want := range []string{"Signed in as Alice Admin", "devedge IdP Example", "Orders", "https://orders.app.dev.test/", `data-action="logout"`, uiScriptPath} {
		if !strings.Contains(lpBody, want) {
			t.Errorf("launchpad missing %q\n%s", want, lpBody)
		}
	}
	// The launchpad JSON reports the session as authenticated as alice.
	lpJSON := fetchLaunchpadWithCookie(t, base, cookie)
	if !lpJSON.Authenticated || lpJSON.Identity == nil || lpJSON.Identity.Subject != "alice" {
		t.Fatalf("/launchpad.json not authenticated as alice: %+v", lpJSON)
	}

	// (4) Logout → clears the session, redirect to "/".
	logoutResp := do(t, client, base+"/logout", cookie)
	if logoutResp.StatusCode != http.StatusFound {
		t.Fatalf("/logout status %d, want 302", logoutResp.StatusCode)
	}
	if cleared := sessionCookieFrom(logoutResp); cleared == nil || cleared.Value != "" {
		t.Fatalf("/logout did not clear the SSO cookie: %v", logoutResp.Cookies())
	}

	// (5) Home again with NO session → picker once more.
	again := getBody(t, client, base+"/", nil, http.StatusOK)
	if !strings.Contains(again, "/pick?identity=alice") {
		t.Errorf("after logout, home is not the picker:\n%s", again)
	}

	// (6) The frontend bundle (built on devedge-ufe-sdk) is served.
	jsResp := do(t, client, base+uiScriptPath, nil)
	if jsResp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status %d, want 200", uiScriptPath, jsResp.StatusCode)
	}
	jsBody, _ := io.ReadAll(jsResp.Body)
	jsResp.Body.Close()
	if !strings.Contains(string(jsBody), "devedge.ufe.authEventBus") {
		t.Errorf("served launchpad.js does not contain the devedge-ufe-sdk auth-event bus")
	}
}

// --- small HTTP helpers (session cookie carried manually) -------------------

func do(t *testing.T, c *http.Client, rawURL string, cookie *http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("new request %s: %v", rawURL, err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	return resp
}

func getBody(t *testing.T, c *http.Client, rawURL string, cookie *http.Cookie, wantStatus int) string {
	t.Helper()
	resp := do(t, c, rawURL, cookie)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("GET %s status %d, want %d; body=%s", rawURL, resp.StatusCode, wantStatus, body)
	}
	return string(body)
}

func sessionCookieFrom(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	return nil
}

func fetchLaunchpadWithCookie(t *testing.T, base string, cookie *http.Cookie) launchpadModel {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, base+"/launchpad.json", nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /launchpad.json: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var m launchpadModel
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("decode /launchpad.json: %v (%s)", err, body)
	}
	return m
}
