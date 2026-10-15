package idp

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"gopkg.in/yaml.v3"
)

// fileClient is the on-disk shape of a client in idp-clients.yaml — the
// dev-manipulable, syncable client registry a sibling `de idp clients sync`
// WRITES. The IdP READS exactly this shape. The file is YAML (friendlier to
// hand-edit); a .json file with the same keys is also accepted (YAML ⊇ JSON).
//
//	# idp-clients.yaml
//	- client_id: orders
//	  client_secret: dev-secret-orders
//	  redirect_uris: [https://orders.app.dev.test/callback]
//	  tile:
//	    name: Orders
//	    description: ""
//	    icon_url: ""
//	    launch_url: https://orders.app.dev.test/
//	- client_id: orders-cli
//	  token_endpoint_auth_method: none   # public client: no secret, PKCE S256 mandatory
//	  redirect_uris: [http://127.0.0.1/callback]
//	  tile:
//	    name: Orders CLI
//
// token_endpoint_auth_method is the RFC 7591 registration key: "client_secret_basic"
// (the default when omitted, keeping existing files confidential) or "none".
type fileClient struct {
	ClientID                string   `json:"client_id" yaml:"client_id"`
	ClientSecret            string   `json:"client_secret" yaml:"client_secret"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method" yaml:"token_endpoint_auth_method"`
	RedirectURIs            []string `json:"redirect_uris" yaml:"redirect_uris"`
	Tile                    Tile     `json:"tile" yaml:"tile"`
}

// authMethodFromFile maps a file client's token_endpoint_auth_method (and
// client_secret) to the OP auth method, rejecting contradictory combinations:
//
//   - "" or "client_secret_basic" → confidential (oidc.AuthMethodBasic); a
//     client_secret is required, so a secretless client can no longer slip in as
//     an un-PKCE'd confidential client by accident.
//   - "none" → public (oidc.AuthMethodNone); a client_secret must NOT be set.
//
// Anything else is unsupported and rejected.
func authMethodFromFile(fc fileClient) (oidc.AuthMethod, error) {
	switch oidc.AuthMethod(fc.TokenEndpointAuthMethod) {
	case "", oidc.AuthMethodBasic:
		if fc.ClientSecret == "" {
			return "", fmt.Errorf("confidential client has an empty client_secret; set one, or declare token_endpoint_auth_method: none for a public (PKCE) client")
		}
		return oidc.AuthMethodBasic, nil
	case oidc.AuthMethodNone:
		if fc.ClientSecret != "" {
			return "", fmt.Errorf("token_endpoint_auth_method none (public client) must not have a client_secret")
		}
		return oidc.AuthMethodNone, nil
	default:
		return "", fmt.Errorf("unsupported token_endpoint_auth_method %q (supported: %s, %s)",
			fc.TokenEndpointAuthMethod, oidc.AuthMethodBasic, oidc.AuthMethodNone)
	}
}

// LoadClientsFile reads idp-clients.yaml (or a .json file with the same keys) and
// builds the clients it declares. Each file client is a dev fixture that supports
// the same grants as the seeded example (auth-code + PKCE, refresh, device). It is
// confidential (client_secret_basic, the default) or, with
// token_endpoint_auth_method: none, public (no secret; PKCE S256 mandatory). A
// client with an empty client_id, a confidential client with no secret, a public
// client with a secret, or an unknown auth method is rejected — a broken file must
// not silently register a nameless or an unintentionally secretless client.
func LoadClientsFile(path string) ([]*Client, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("idp: read clients file %q: %w", path, err)
	}
	var fcs []fileClient
	if err := yaml.Unmarshal(b, &fcs); err != nil {
		return nil, fmt.Errorf("idp: parse clients file %q: %w", path, err)
	}
	clients := make([]*Client, 0, len(fcs))
	for i, fc := range fcs {
		if fc.ClientID == "" {
			return nil, fmt.Errorf("idp: clients file %q: entry %d has an empty client_id", path, i)
		}
		authMethod, err := authMethodFromFile(fc)
		if err != nil {
			return nil, fmt.Errorf("idp: clients file %q: entry %d (client_id %q): %w", path, i, fc.ClientID, err)
		}
		clients = append(clients, &Client{
			id:           fc.ClientID,
			secret:       fc.ClientSecret,
			redirectURIs: fc.RedirectURIs,
			authMethod:   authMethod,
			grantTypes: []oidc.GrantType{
				oidc.GrantTypeCode,
				oidc.GrantTypeRefreshToken,
				oidc.GrantTypeDeviceCode,
			},
			tile: fc.Tile,
		})
	}
	return clients, nil
}

// WatchClientsFile registers the clients declared in path (augmenting the seeded
// set) and hot-reloads them whenever the file's modification time changes,
// polling every interval — zero-dependency, no fsnotify, mirroring
// devsvc.WatchGrantsFile. It loads once immediately, then runs until ctx is
// cancelled. A load/parse error after the initial load is passed to onErr (if
// non-nil) and the LAST-GOOD client set is kept — a bad edit never crashes the
// IdP. It returns the initial load error so a caller can fail fast on a broken
// file at startup. This is the WS-026 dev-manipulability seam: edit the clients
// file → a new app tile appears on the launchpad, no restart.
func WatchClientsFile(ctx context.Context, path string, storage *Storage, interval time.Duration, onErr func(error)) error {
	if interval <= 0 {
		interval = time.Second
	}
	clients, err := LoadClientsFile(path)
	if err != nil {
		return err
	}
	storage.ReplaceFileClients(clients)
	last := clientsModTime(path)

	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				mt := clientsModTime(path)
				if mt.Equal(last) {
					continue
				}
				last = mt
				cs, lerr := LoadClientsFile(path)
				if lerr != nil {
					if onErr != nil {
						onErr(lerr)
					}
					continue // keep last-good clients
				}
				storage.ReplaceFileClients(cs)
			}
		}
	}()
	return nil
}

func clientsModTime(path string) time.Time {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}
