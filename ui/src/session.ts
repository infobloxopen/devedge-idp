/**
 * IdpSessionProvider adapts the dev IdP's OWN server-side SSO session — an
 * HttpOnly cookie the IdP owns — to the devedge-ufe-sdk SessionProvider seam
 * (`@infobloxopen/devedge-ufe-core`). In the ufe model the SHELL owns the
 * session and hands surfaces a read-only view over a window-pinned auth-event
 * bus; the launchpad IS that shell for the dev IdP.
 *
 * No bearer is minted in the browser — the IdP holds tokens server-side — so
 * getToken() returns the empty string in dev. This is deliberately the same
 * seam a production shell binds to via `@infobloxopen/devedge-ufe-oidc`.
 */
import {
  createAuthEventBus,
  type AuthEventBus,
  type Claims,
  type SessionEvent,
  type SessionProvider,
} from '@infobloxopen/devedge-ufe-core';

export interface IdpSessionData {
  authenticated: boolean;
  identity:
    | { subject: string; name: string; email?: string; apps?: string[] }
    | null;
}

export class IdpSessionProvider implements SessionProvider {
  private readonly bus: AuthEventBus;
  private readonly data: IdpSessionData;

  constructor(data: IdpSessionData) {
    this.bus = createAuthEventBus();
    this.data = data;
  }

  async getToken(): Promise<string> {
    // Dev IdP owns tokens server-side; the launchpad never holds a bearer.
    return '';
  }

  async getClaims(): Promise<Claims | null> {
    const id = this.data.identity;
    if (!id) return null;
    return {
      sub: id.subject,
      name: id.name,
      email: id.email,
      apps: id.apps,
    } as Claims;
  }

  subscribe(fn: (e: SessionEvent) => void): () => void {
    return this.bus.subscribe(fn);
  }

  /** Establishing a session = picking an identity on the IdP home. */
  async login(): Promise<void> {
    window.location.assign('/');
  }

  /** Clear the IdP SSO session server-side, then return to the picker. */
  async logout(): Promise<void> {
    this.bus.publish({ type: 'signed_out' });
    window.location.assign('/logout');
  }

  /** Announce the already-established session on the shared bus. */
  announce(): void {
    if (this.data.authenticated) {
      this.bus.publish({ type: 'token_acquired', token: '', expiresAt: null });
    }
  }
}
