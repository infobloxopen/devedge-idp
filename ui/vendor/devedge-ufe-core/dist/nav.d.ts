/**
 * F2 — nav contribution + loud validation.
 *
 * This is the headline bug fix. In the reference uFE surface, a nav item's
 * `group` was free text validated against nothing: a wrong value rendered
 * NOTHING, with no error anywhere. This module turns that silent drop into a
 * loud, mechanism-level failure by validating every contribution's `group`
 * against an explicit registry of known groups.
 */
/** The nav-item kinds a contribution may declare. */
export type NavItemType = 'menuItem' | 'tabParent' | 'tab' | 'tabButton' | 'tabLink' | 'headerMenu' | 'dropdownTab';
/** A single navigation entry a uFE contributes to the shell. */
export interface NavContribution {
    name: string;
    path: string;
    /** The nav group this item belongs to. Validated against a {@link GroupRegistry}. */
    group: string;
    type: NavItemType;
    weight?: number;
    /** Opaque, host-interpreted access hint (e.g. an authz expression). */
    access?: unknown;
}
/** The set of nav groups a host recognizes. Unknown groups render nothing. */
export interface GroupRegistry {
    /** All groups this registry recognizes. */
    known(): readonly string[];
    /** Whether `group` is a recognized group. */
    has(group: string): boolean;
}
/**
 * A registry backed by a fixed, explicit list of groups.
 *
 * Note: an EMPTY list means "no known groups configured". By itself an empty
 * registry cannot validate anything — see {@link validateNavContribution} /
 * {@link assertNavContributions} for how permissive-vs-strict is resolved.
 */
export declare function staticGroupRegistry(groups: readonly string[]): GroupRegistry;
/** Options controlling how an empty registry is treated. */
export interface NavValidationOptions {
    /**
     * When the registry is empty ("no known groups configured"), treat a
     * contribution as valid instead of failing. Defaults to `false` (strict).
     * A permissive pass emits a clear `console.warn` so the gap is never silent.
     */
    permissive?: boolean;
}
/** Result of validating a single contribution. */
export interface NavValidationResult {
    ok: boolean;
    error?: string;
}
/**
 * Validates a contribution's `group` against the active registry.
 *
 * Always fails LOUD, never silent:
 *   - unknown group  → `{ ok: false, error }` naming the group + valid groups.
 *   - empty registry → strict: fail; permissive: pass with a `console.warn`.
 */
export declare function validateNavContribution(c: NavContribution, reg: GroupRegistry, opts?: NavValidationOptions): NavValidationResult;
/**
 * Validates every contribution and THROWS a clear error on the first failure,
 * naming the offending contribution, its unknown group, and the valid groups.
 * This is the assertion a host runs at registration time so a bad `group`
 * fails loudly at startup instead of rendering nothing at runtime.
 */
export declare function assertNavContributions(cs: NavContribution[], reg: GroupRegistry, opts?: NavValidationOptions): void;
//# sourceMappingURL=nav.d.ts.map