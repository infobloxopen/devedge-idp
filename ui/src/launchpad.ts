/**
 * The devedge-idp launchpad frontend, built on the devedge-ufe-sdk core.
 *
 * The server renders the picker/launchpad HTML (so the flow works with no JS
 * and is assertable headlessly); this bundle ENHANCES it. It reads the inline
 * hydration payload, adapts the IdP SSO session to the ufe SessionProvider seam
 * (see IdpSessionProvider), announces it on the window-pinned auth-event bus,
 * and drives log-out / switch-user / tile-launch THROUGH that session contract
 * rather than raw links — the same seam a production shell uses.
 */
import type { SessionEvent } from '@infobloxopen/devedge-ufe-core';
import { IdpSessionProvider, type IdpSessionData } from './session.js';

function readHydrationData(): IdpSessionData {
  const el = document.getElementById('launchpad-data');
  if (!el || !el.textContent) return { authenticated: false, identity: null };
  try {
    const d = JSON.parse(el.textContent) as Partial<IdpSessionData>;
    return { authenticated: !!d.authenticated, identity: d.identity ?? null };
  } catch {
    return { authenticated: false, identity: null };
  }
}

function main(): void {
  const data = readHydrationData();
  const session = new IdpSessionProvider(data);

  // Reflect the session lifecycle onto the document so chrome can react.
  session.subscribe((e: SessionEvent) => {
    document.body.setAttribute('data-session', e.type);
  });
  session.announce();

  // Drive log-out through the SessionProvider seam (not a raw link).
  const logoutEl = document.querySelector('[data-action="logout"]');
  logoutEl?.addEventListener('click', (ev: Event) => {
    ev.preventDefault();
    void session.logout();
  });

  // Switch user = pick another identity.
  const switchEl = document.querySelector('[data-action="switch"]');
  switchEl?.addEventListener('click', (ev: Event) => {
    ev.preventDefault();
    window.location.assign('/switch');
  });

  // Tiles launch their app's launch_url.
  document.querySelectorAll<HTMLElement>('[data-launch]').forEach((tile) => {
    tile.addEventListener('click', (ev: Event) => {
      const url = tile.getAttribute('data-launch');
      if (url) {
        ev.preventDefault();
        window.location.assign(url);
      }
    });
  });
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', main);
  } else {
    main();
  }
}
