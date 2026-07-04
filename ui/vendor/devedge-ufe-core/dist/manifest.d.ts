/**
 * F5 — deploy-artifact / manifest contract.
 *
 * Generalizes the `metadata.ts` default export from the single-spa-angular
 * boilerplate ({ navItems, routes, exports, searchObjects }) into a small,
 * validated, framework-agnostic shape.
 */
import type { NavContribution } from './nav.js';
/** One exported entry a uFE artifact exposes to the host. */
export interface UfeExport {
    id: string;
    entry: string;
    type: 'ufe-application' | string;
}
/** The manifest a uFE publishes describing what it contributes. */
export interface UfeManifest {
    navItems: NavContribution[];
    routes: string[];
    exports: UfeExport[];
    searchObjects?: unknown[];
}
/** A built uFE described abstractly: its manifest plus (optionally) its files. */
export interface DeployableArtifact {
    manifest: UfeManifest;
    files?: string[];
}
/**
 * Identity function that validates a manifest's shape, throwing a clear error
 * if a required field is missing or the wrong type. Use it as the default
 * export of a uFE's `metadata` module so shape errors fail at build/import
 * time rather than rendering nothing at runtime.
 */
export declare function defineManifest(m: UfeManifest): UfeManifest;
//# sourceMappingURL=manifest.d.ts.map