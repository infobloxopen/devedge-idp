package idp

import (
	"slices"
	"testing"
)

// TestSyncedClientEntitlesDevIdentities guards finding 096: a client added to the
// registry (as `de idp clients sync` / idp-clients.json does) must make the
// built-in dev identities entitled to it, so authn.WithRequireEntitlement()
// works for a freshly-synced app without hand-editing identities.go.
func TestSyncedClientEntitlesDevIdentities(t *testing.T) {
	st, err := NewStorage(map[string]*Client{
		"devedge-idp-example": {id: "devedge-idp-example", secret: "dev-secret"},
	})
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}

	// Before sync: the seeded client is the only registered app.
	if got := st.allClientIDs(); !slices.Equal(got, []string{"devedge-idp-example"}) {
		t.Fatalf("seeded allClientIDs = %v", got)
	}

	// Simulate `de idp clients sync` adding a new app.
	st.ReplaceFileClients([]*Client{{id: "vaultd", secret: "dev-secret-vaultd"}})

	ids := st.allClientIDs()
	if !slices.Contains(ids, "vaultd") || !slices.Contains(ids, "devedge-idp-example") {
		t.Fatalf("after sync, allClientIDs = %v; want both seeded + synced", ids)
	}

	// The emitted app-access for any dev identity is the union of its declared
	// Apps and every registered client — so the synced app is entitled.
	apps := unionSorted(Identities[0].Apps, st.allClientIDs())
	if !slices.Contains(apps, "vaultd") {
		t.Fatalf("dev identity apps = %v; want it to include the synced app 'vaultd' (finding 096)", apps)
	}
}
