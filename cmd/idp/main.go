// Command idp runs devedge-idp, a development-only OpenID Provider, on the
// devedge-sdk server harness.
//
// NON-PRODUCTION: passwordless login, dummy client secrets, in-memory state.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/infobloxopen/devedge-idp/internal/idp"
	"github.com/infobloxopen/devedge-sdk/server"
)

func main() {
	grpcAddr := flag.String("grpc-addr", env("IDP_GRPC_ADDR", ":9090"), "gRPC listen address")
	httpAddr := flag.String("http-addr", env("IDP_HTTP_ADDR", ":8080"), "HTTP listen address (OIDC endpoints + login)")
	issuer := flag.String("issuer", env("IDP_ISSUER", ""), "OIDC issuer URL; empty derives it per-request from the Host header")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	handlers, _, err := idp.New(idp.Config{
		Issuer: *issuer,
		Logger: logger,
	})
	if err != nil {
		logger.Error("build idp", "err", err)
		os.Exit(1)
	}

	srv, err := server.New(server.Config{
		GRPCAddr:     *grpcAddr,
		HTTPAddr:     *httpAddr,
		HTTPHandlers: handlers,
	})
	if err != nil {
		logger.Error("build server", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Warn("devedge-idp is NON-PRODUCTION: passwordless login, dummy secrets, in-memory state")
	logger.Info("starting devedge-idp",
		"grpc_addr", *grpcAddr, "http_addr", *httpAddr, "issuer", *issuer,
		"discovery", "/.well-known/openid-configuration", "jwks", "/keys", "login", "/login")
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
