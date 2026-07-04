package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// fileClient is the on-disk shape of a client in idp-clients.json — the
// dev-manipulable, syncable client registry a sibling `de idp clients sync`
// WRITES. The IdP READS exactly this shape.
//
//	[
//	  {
//	    "client_id": "orders",
//	    "client_secret": "dev-secret-orders",
//	    "redirect_uris": ["https://orders.app.dev.test/callback"],
//	    "tile": { "name": "Orders", "description": "", "icon_url": "", "launch_url": "https://orders.app.dev.test/" }
//	  }
//	]
type fileClient struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURIs []string `json:"redirect_uris"`
	Tile         Tile     `json:"tile"`
}

// LoadClientsFile reads idp-clients.json and builds the confidential clients it
// declares. Each file client is a dev fixture that supports the same grants as
// the seeded example (auth-code + PKCE, refresh, device) and authenticates with
// client_secret_basic. A client with an empty client_id is rejected — a broken
// file must not silently register a nameless client.
func LoadClientsFile(path string) ([]*Client, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("idp: read clients file %q: %w", path, err)
	}
	var fcs []fileClient
	if err := json.Unmarshal(b, &fcs); err != nil {
		return nil, fmt.Errorf("idp: parse clients file %q: %w", path, err)
	}
	clients := make([]*Client, 0, len(fcs))
	for i, fc := range fcs {
		if fc.ClientID == "" {
			return nil, fmt.Errorf("idp: clients file %q: entry %d has an empty client_id", path, i)
		}
		clients = append(clients, &Client{
			id:           fc.ClientID,
			secret:       fc.ClientSecret,
			redirectURIs: fc.RedirectURIs,
			authMethod:   oidc.AuthMethodBasic,
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
