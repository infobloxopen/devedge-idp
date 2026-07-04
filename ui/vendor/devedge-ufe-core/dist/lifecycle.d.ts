/**
 * F1 — application-lifecycle contract.
 *
 * The minimal, framework-agnostic shape every devedge micro-frontend implements.
 * A host (shell) drives `bootstrap` → `mount` → `unmount`, always passing the
 * shell-owned session down as a prop. Child uFEs never construct a session; they
 * only consume the read-only {@link SessionProvider} view handed to them.
 */
import type { SessionProvider } from './session.js';
/** Identifies a micro-frontend and where its entry bundle lives. */
export interface MicrofrontendDescriptor {
    id: string;
    entry: string;
}
/**
 * Props the host passes into every lifecycle method. `session` is always
 * present; hosts may pass additional custom props alongside it.
 */
export interface HostProps {
    session: SessionProvider;
    [k: string]: unknown;
}
/** A loadable micro-frontend module implementing the devedge lifecycle. */
export interface MicrofrontendModule {
    descriptor: MicrofrontendDescriptor;
    bootstrap(props: HostProps): Promise<void>;
    mount(props: HostProps): Promise<void>;
    unmount(props: HostProps): Promise<void>;
}
//# sourceMappingURL=lifecycle.d.ts.map