/**
 * F3 — session/identity interfaces + framework-agnostic primitives.
 *
 * The load-bearing architectural rule: the SHELL owns OIDC. Child uFEs NEVER
 * authenticate. They receive a read-only {@link SessionProvider} view and
 * subscribe to a window-pinned auth-event bus. This module carries only the
 * contract + zero-dependency helpers — no `oidc-client-ts`. The concrete OIDC
 * binding lives in `@infobloxopen/devedge-ufe-oidc`.
 */
function makeLocalBus() {
    const subs = new Set();
    return {
        publish(e) {
            for (const fn of subs)
                fn(e);
        },
        subscribe(fn) {
            subs.add(fn);
            return () => {
                subs.delete(fn);
            };
        },
    };
}
/**
 * The global key under which the single shared bus is pinned. Using a
 * `Symbol.for` (registered symbol) guarantees one identity even across
 * multiple bundle copies of this package loaded on the same window.
 */
const BUS_KEY = Symbol.for('devedge.ufe.authEventBus');
/**
 * Returns the process-global auth-event bus, creating it once.
 *
 * MUST be window-pinned: the shell and every uFE bundle copy share ONE bus, so
 * an event published by the shell reaches subscribers in a separately-bundled
 * uFE. Falls back to a module-local bus when no `window`/`globalThis` host
 * object is available (SSR / non-jsdom test).
 */
export function createAuthEventBus() {
    const host = (typeof globalThis !== 'undefined' ? globalThis : undefined);
    if (!host) {
        return makeLocalBus();
    }
    if (!host[BUS_KEY]) {
        host[BUS_KEY] = makeLocalBus();
    }
    return host[BUS_KEY];
}
/**
 * Resolves `input` to a request URL string, matching `fetch`'s own coercion:
 * a `Request` uses its `.url`; anything else is stringified.
 */
function urlFromInput(input) {
    if (typeof input === 'string')
        return input;
    if (input instanceof URL)
        return input.toString();
    // A Request (or Request-like) object.
    return input.url;
}
/**
 * Decides whether the bearer token may be attached to a request bound for
 * `resolvedUrl`. Same-origin (which includes relative URLs, since they resolve
 * to the page origin) is always allowed; cross-origin requires an explicit
 * allowlist match. In a non-browser host (no `location`) only an explicit
 * allowlist match qualifies.
 */
function mayAttachToken(urlStr, allowedOrigins) {
    const pageOrigin = typeof location !== 'undefined' ? location.origin : undefined;
    let target;
    try {
        target = new URL(urlStr, pageOrigin);
    }
    catch {
        // Unparseable target: fail closed — do not attach the token.
        return false;
    }
    if (pageOrigin !== undefined && target.origin === pageOrigin)
        return true;
    return allowedOrigins.includes(target.origin);
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
export function createAuthedFetch(session, base = fetch, opts) {
    const allowedOrigins = opts?.allowedOrigins ?? [];
    const authed = async (input, init) => {
        const attach = mayAttachToken(urlFromInput(input), allowedOrigins);
        // Capture the request in a re-constructable form so a 401 retry does not
        // reuse an already-consumed body. A Request body is single-use, so we
        // clone it up front and rebuild a fresh Request for each send.
        const template = input instanceof Request ? input : undefined;
        const send = async () => {
            if (!attach) {
                return template ? base(template.clone()) : base(input, init);
            }
            const token = await session.getToken();
            if (template) {
                const req = template.clone();
                const headers = new Headers(req.headers);
                headers.set('Authorization', `Bearer ${token}`);
                return base(new Request(req, { headers }));
            }
            const headers = new Headers(init?.headers);
            headers.set('Authorization', `Bearer ${token}`);
            return base(input, { ...init, headers });
        };
        const res = await send();
        if (res.status !== 401) {
            return res;
        }
        // 401 → re-authenticate and retry exactly once.
        await session.login();
        return send();
    };
    return authed;
}
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
export class StubSessionProvider {
    constructor(opts = {}) {
        console.warn('[devedge-ufe] StubSessionProvider is for development only and must not be used in production.');
        this.token = opts.token ?? 'dev-stub-token';
        this.claims = opts.claims ?? { sub: 'dev-user' };
        this.bus = createAuthEventBus();
    }
    async getToken() {
        return this.token;
    }
    async getClaims() {
        return this.claims;
    }
    subscribe(fn) {
        return this.bus.subscribe(fn);
    }
    async login() {
        this.bus.publish({ type: 'token_acquired', token: this.token, expiresAt: null });
    }
    async logout() {
        this.bus.publish({ type: 'signed_out' });
    }
}
//# sourceMappingURL=session.js.map