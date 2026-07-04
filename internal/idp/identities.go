package idp

// Identity is a passwordless, built-in developer identity. It is a dev fixture:
// there are no passwords, no user management, and no MFA. "Login" is simply
// picking one of these by its Subject.
//
// The IdP is the "who you are" tier of the WS-026 two-tier token model. It only
// ever emits a COARSE identity assertion (see EmittedClaims): sub, name, an
// optional email, and the app-access entitlement (Apps). The richer profile
// fields below (Tenant, Roles, Groups) are STORED for future use but are
// deliberately NEVER put on the id_token — the downstream "app identity" tier
// authors tenant/roles/scopes when it mints the app bearer token.
type Identity struct {
	// Subject is the stable identifier emitted as the `sub` claim.
	Subject string
	// Name is emitted as the `name` claim (coarse identity).
	Name string
	// Email, when non-empty, is emitted as `email` (only if the email scope was
	// requested).
	Email string
	// Apps is the app-access entitlement: the app/client names this identity may
	// enter. Emitted as the `apps` claim. This is the ONLY authorization-shaped
	// data the IdP asserts, and it is coarse (which apps, not what-inside-an-app).
	Apps []string

	// --- Internal-only profile. STORED, never emitted on the id_token. ---
	// These exist to prove the model: the IdP may know more than it asserts. The
	// downstream app identity authors these kinds of claims itself.
	Tenant string
	Roles  []string
	Groups []string
}

// seededApps are the app/client names the built-in identities are entitled to
// enter. Keep this in sync with the seeded clients in clients.go.
var seededApps = []string{"devedge-idp-example"}

// Identities is the fixed, in-memory set of built-in developer identities. This
// is the single place to edit who can log in — dev-manipulability is the point.
// Order is preserved for a stable login page.
var Identities = []Identity{
	{
		Subject: "alice",
		Name:    "Alice Admin",
		Email:   "alice@dev.test",
		Apps:    seededApps,
		Tenant:  "tenant-a",
		Roles:   []string{"admin"},
		Groups:  []string{"platform"},
	},
	{
		Subject: "bob",
		Name:    "Bob Viewer",
		Email:   "bob@dev.test",
		Apps:    seededApps,
		Tenant:  "tenant-a",
		Roles:   []string{"viewer"},
		Groups:  []string{"platform"},
	},
	{
		Subject: "carol",
		Name:    "Carol (tenant-b)",
		Email:   "carol@dev.test",
		Apps:    seededApps,
		Tenant:  "tenant-b",
		Roles:   []string{"viewer"},
		Groups:  []string{"partners"},
	},
}

// identityBySubject returns the built-in identity with the given subject, or nil.
func identityBySubject(subject string) *Identity {
	for i := range Identities {
		if Identities[i].Subject == subject {
			return &Identities[i]
		}
	}
	return nil
}
