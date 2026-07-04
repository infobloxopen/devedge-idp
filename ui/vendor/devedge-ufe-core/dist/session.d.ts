/**
 * F3 — session/identity interfaces + framework-agnostic primitives.
 *
 * The load-bearing architectural rule: the SHELL owns OIDC. Child uFEs NEVER
 * authenticate. They receive a read-only {@link SessionProvider} view and
 * subscribe to a window-pinned auth-event bus. This module carries only the
 * contract + zero-dependency helpers — no `oidc-client-ts`. The concrete OIDC
 * binding lives in `@infobloxopen/devedge-ufe-oidc`.
 */
/** Decoded identity claims. Shape is issuer-specific beyond `sub`. */
export interface Claims {
    sub?: string;
    [k: string]: unknown;
}
/** Events broadcast as the session's token lifecycle advances. */
export type SessionEvent = {
    type: 'token_acquired';
    token: string;
    expiresAt: number | null;
} | {
    type: 'token_expired';
} | {
    type: 'signed_out';
};
/**
 * The read-only session view handed to uFEs. uFEs can read the token, read
 * claims, subscribe to lifecycle events, and request login/logout — but they
 * cannot construct a session or reach the underlying identity provider.
 */
export interface SessionProvider {
    getToken(): Promise<string>;
    getClaims?(): Promise<Claims | null>;
    subscribe(fn: (e: SessionEvent) => void): () => void;
    login(): Promise<void>;
    logout(): Promise<void>;
}
/** A minimal publish/subscribe bus for {@link SessionEvent}s. */
export interface AuthEventBus {
    publish(e: SessionEvent): void;
    subscribe(fn: (e: SessionEvent) => void): () => void;
}
/**
 * Returns the process-global auth-event bus, creating it once.
 *
 * MUST be window-pinned: the shell and every uFE bundle copy share ONE bus, so
 * an event published by the shell reaches subscribers in a separately-bundled
 * uFE. Falls back to a module-local bus when no `window`/`globalThis` host
 * object is available (SSR / non-jsdom test).
 */
export declare function createAuthEventBus(): AuthEventBus;
/** Options for {@link createAuthedFetch}. */
export interface AuthedFetchOptions {
    /**
     * Extra origins (beyond `location.origin`) that MAY receive the bearer
     * token. Each entry is compared against the request's resolved origin.
     */
    allowedOrigins?: string[];
}
/**
 * Wraps `fetch` so requests carry `Authorization: Bearer <token>` from the
 * session. On a 401 it calls `session.login()` then retries the request ONCE;
 * if that retry also 401s it returns the response. Any other status passes
 * through unchanged.
 *
 * @remarks
 * Same-origin by default: the token is attached ONLY when the request's
 * resolved origin equals the page origin (`location.origin`) — relative URLs
 * resolve to the page origin and are therefore safe — or is listed in
 * `opts.allowedOrigins`. This prevents leaking the bearer token to third-party
 * origins. In a non-browser host (no `location`) the token is attached only
 * when an explicit allowlist matches.
 */
export declare function createAuthedFetch(session: SessionProvider, base?: typeof fetch, opts?: AuthedFetchOptions): typeof fetch;
/**
 * A no-real-auth session for local development and tests. Returns a fixed
 * token, publishes a `token_acquired` on the shared bus, and no-ops on
 * login/logout.
 *
 * @remarks
 * DEVELOPMENT ONLY. This provider performs NO authentication and MUST NOT be
 * used in production. Constructing it emits a `console.warn` so an accidental
 * production bundle surfaces the misuse loudly (it stays functional and does
 * not throw).
 */
export declare class StubSessionProvider implements SessionProvider {
    private readonly token;
    private readonly claims;
    private readonly bus;
    constructor(opts?: {
        token?: string;
        claims?: Claims | null;
    });
    getToken(): Promise<string>;
    getClaims(): Promise<Claims | null>;
    subscribe(fn: (e: SessionEvent) => void): () => void;
    login(): Promise<void>;
    logout(): Promise<void>;
}
//# sourceMappingURL=session.d.ts.map