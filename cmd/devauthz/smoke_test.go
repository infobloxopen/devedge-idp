package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/infobloxopen/devedge-sdk/authz"
	"github.com/infobloxopen/devedge-sdk/authz/devsvc"
	"github.com/infobloxopen/devedge-sdk/server"
)

// TestSmoke_DevAuthzServer boots the dev authz service on the SAME server harness
// the binary uses (handler mounted at "/v1/") and asserts (a) the SDK /healthz
// probe still wins and (b) the mounted handler returns a decision at
// /v1/authorize. Fast and headless.
func TestSmoke_DevAuthzServer(t *testing.T) {
	store := devsvc.NewStore(authz.Grant{
		Tenant: "tenant-a", Subjects: []string{"group:admin"}, Verbs: []authz.Verb{"*"}, Resource: "*",
	})
	handler := devsvc.NewHandler(store, devsvc.HandlerOptions{EnableAdmin: true})

	srv, err := server.New(server.Config{
		GRPCAddr:     "127.0.0.1:0",
		HTTPAddr:     "127.0.0.1:0",
		HTTPHandlers: []server.HTTPHandler{{Pattern: "/v1/", Handler: handler}},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()

	var base string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ha := srv.HTTPAddr(); ha != "" && ha != "127.0.0.1:0" {
			base = "http://" + ha
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if base == "" {
		t.Fatal("server did not bind within 5s")
	}

	// (a) The SDK liveness probe still wins even though "/v1/" is mounted.
	resp, err := http.Get(base + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz status = %d, want 200", resp.StatusCode)
	}

	// (b) The mounted dev authz handler decides at /v1/authorize. Use the same
	// Client seam a microservice uses, so we exercise the real wire protocol.
	client := &devsvc.Client{BaseURL: base}
	dec, err := client.Authorize(ctx, authz.AccessRequest{
		Principal: authz.Principal{Subject: "alice", Tenant: "tenant-a", Groups: []string{"admin"}},
		Verb:      authz.Get,
		Resource:  authz.Resource{Type: "order"},
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if !dec.Allow {
		t.Fatalf("admin grant present: want allow, got deny (%s)", dec.Reason)
	}
}
