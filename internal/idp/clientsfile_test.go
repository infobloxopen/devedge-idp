package idp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// TestLoadClientsFile_TokenEndpointAuthMethod pins the clients-file contract for
// token_endpoint_auth_method: omitted or client_secret_basic is a confidential
// client (existing files keep working unchanged), none is a public native client,
// and the contradictory / unknown spellings are rejected with an error that names
// the entry — a broken file never registers a half-configured client.
func TestLoadClientsFile_TokenEndpointAuthMethod(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantMethod oidc.AuthMethod
		wantType   op.ApplicationType
		wantErr    string // substring of the load error; "" means the load must succeed
	}{
		{
			name:       "omitted with a secret stays a confidential Basic client (backwards compatible)",
			body:       "- client_id: orders\n  client_secret: dev-secret-orders\n  redirect_uris: [https://orders.app.dev.test/callback]\n",
			wantMethod: oidc.AuthMethodBasic,
			wantType:   op.ApplicationTypeWeb,
		},
		{
			name:       "explicit client_secret_basic",
			body:       "- client_id: orders\n  client_secret: dev-secret-orders\n  token_endpoint_auth_method: client_secret_basic\n",
			wantMethod: oidc.AuthMethodBasic,
			wantType:   op.ApplicationTypeWeb,
		},
		{
			name:       "none is a public native client",
			body:       "- client_id: orders-cli\n  token_endpoint_auth_method: none\n  redirect_uris: [http://127.0.0.1/callback]\n",
			wantMethod: oidc.AuthMethodNone,
			wantType:   op.ApplicationTypeNative,
		},
		{
			name:       "none spelled in JSON is accepted too",
			body:       `[{"client_id":"orders-cli","token_endpoint_auth_method":"none","redirect_uris":["http://127.0.0.1/callback"]}]`,
			wantMethod: oidc.AuthMethodNone,
			wantType:   op.ApplicationTypeNative,
		},
		{
			name:    "none with a client_secret is contradictory",
			body:    "- client_id: orders-cli\n  token_endpoint_auth_method: none\n  client_secret: oops\n",
			wantErr: `(client_id "orders-cli"): token_endpoint_auth_method none (public client) must not have a client_secret`,
		},
		{
			name:    "confidential client with an empty client_secret is rejected",
			body:    "- client_id: orders\n  client_secret: \"\"\n  redirect_uris: [https://orders.app.dev.test/callback]\n",
			wantErr: `(client_id "orders"): confidential client has an empty client_secret`,
		},
		{
			name:    "confidential client with no client_secret key is rejected",
			body:    "- client_id: orders\n  redirect_uris: [https://orders.app.dev.test/callback]\n",
			wantErr: `(client_id "orders"): confidential client has an empty client_secret`,
		},
		{
			name:    "unsupported method is rejected",
			body:    "- client_id: orders\n  client_secret: s\n  token_endpoint_auth_method: private_key_jwt\n",
			wantErr: `unsupported token_endpoint_auth_method "private_key_jwt" (supported: client_secret_basic, none)`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "idp-clients.yaml")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatalf("write clients file: %v", err)
			}
			clients, err := LoadClientsFile(path)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("LoadClientsFile: want error containing %q, got nil (clients=%d)", tc.wantErr, len(clients))
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("LoadClientsFile error = %q, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadClientsFile: %v", err)
			}
			if len(clients) != 1 {
				t.Fatalf("LoadClientsFile returned %d clients, want 1", len(clients))
			}
			c := clients[0]
			if got := c.AuthMethod(); got != tc.wantMethod {
				t.Errorf("AuthMethod() = %q, want %q", got, tc.wantMethod)
			}
			if got := c.ApplicationType(); got != tc.wantType {
				t.Errorf("ApplicationType() = %v, want %v", got, tc.wantType)
			}
			if got, want := c.IsPublic(), tc.wantMethod == oidc.AuthMethodNone; got != want {
				t.Errorf("IsPublic() = %v, want %v", got, want)
			}
		})
	}
}
