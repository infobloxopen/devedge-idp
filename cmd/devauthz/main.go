// Command devauthz runs the devedge dev authz service — the out-of-process,
// hot-reloadable sibling of the in-process authz.DevAuthorizer — on the
// devedge-sdk server harness. It serves the dev authz wire protocol
// (POST /v1/authorize) that a microservice's devsvc.Client calls to decide a
// request, and, with the admin endpoint on, PUT /v1/grants to replace the grant
// set live. It is the "decisions" tier of the WS-026 dev security suite (the IdP
// is the "identity" tier).
//
// NON-PRODUCTION: an unauthenticated admin endpoint, default-deny with
// developer-editable grants, and in-memory state. Production authorization is
// OPA/PARGS behind the SAME authz.Authorizer seam (opaauthz.New) — swapping to it
// is a one-line change in the calling service, no code change here. Never deploy
// this outside a development environment.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/infobloxopen/devedge-sdk/authz/devsvc"
	"github.com/infobloxopen/devedge-sdk/server"
)

func main() {
	grpcAddr := flag.String("grpc-addr", env("DEVAUTHZ_GRPC_ADDR", ":9091"),
		"gRPC listen address (the harness requires one; no gRPC services are registered — this service is HTTP-only)")
	httpAddr := flag.String("http-addr", env("DEVAUTHZ_HTTP_ADDR", ":8090"),
		"HTTP listen address (serves /v1/authorize and, admin-on, /v1/grants)")
	grantsPath := flag.String("grants", env("DEVAUTHZ_GRANTS", "./grants.yaml"),
		"path to a JSON grants file to load and hot-reload; if it does not exist, start empty (default-deny)")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Start empty = default-deny. A grants file is optional; the admin PUT and the
	// in-memory store work with or without one.
	store := devsvc.NewStore()

	// Wire edit-on-disk hot-reload only when the grants file actually exists — a
	// missing default file is not an error (start empty; admin PUT still works).
	if path := *grantsPath; path != "" {
		if _, statErr := os.Stat(path); statErr == nil {
			onErr := func(e error) { logger.Error("reload grants file", "path", path, "err", e) }
			if err := devsvc.WatchGrantsFile(ctx, path, store, time.Second, onErr); err != nil {
				logger.Error("load grants file", "path", path, "err", err)
				os.Exit(1)
			}
			logger.Info("watching grants file for hot-reload", "path", path, "grants", len(store.Grants()))
		} else {
			logger.Info("no grants file found; starting empty (default-deny)", "path", path)
		}
	}

	// Mount the dev authz handler at "/v1/" so its /v1/authorize and /v1/grants
	// route to it while the SDK's /healthz and /readyz probes still win.
	handler := devsvc.NewHandler(store, devsvc.HandlerOptions{EnableAdmin: true})
	srv, err := server.New(server.Config{
		GRPCAddr:     *grpcAddr,
		HTTPAddr:     *httpAddr,
		HTTPHandlers: []server.HTTPHandler{{Pattern: "/v1/", Handler: handler}},
	})
	if err != nil {
		logger.Error("build server", "err", err)
		os.Exit(1)
	}

	logger.Warn("devauthz is NON-PRODUCTION: unauthenticated admin endpoint, in-memory grants; production authz is opaauthz behind the same authz.Authorizer seam")
	logger.Info("starting devauthz",
		"grpc_addr", *grpcAddr, "http_addr", *httpAddr,
		"authorize", devsvc.DefaultAuthorizePath, "admin_grants", "/v1/grants")
	if err := srv.Serve(ctx); err != nil {
		logger.Error("serve", "err", err)
		os.Exit(1)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
