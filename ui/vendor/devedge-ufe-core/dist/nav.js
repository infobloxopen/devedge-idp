/**
 * F2 — nav contribution + loud validation.
 *
 * This is the headline bug fix. In the reference uFE surface, a nav item's
 * `group` was free text validated against nothing: a wrong value rendered
 * NOTHING, with no error anywhere. This module turns that silent drop into a
 * loud, mechanism-level failure by validating every contribution's `group`
 * against an explicit registry of known groups.
 */
/**
 * A registry backed by a fixed, explicit list of groups.
 *
 * Note: an EMPTY list means "no known groups configured". By itself an empty
 * registry cannot validate anything — see {@link validateNavContribution} /
 * {@link assertNavContributions} for how permissive-vs-strict is resolved.
 */
export function staticGroupRegistry(groups) {
    const set = new Set(groups);
    const frozen = Object.freeze([...groups]);
    return {
        known() {
            return frozen;
        },
        has(group) {
            return set.has(group);
        },
    };
}
function formatGroups(reg) {
    const groups = reg.known();
    return groups.length ? groups.map((g) => `"${g}"`).join(', ') : '(none configured)';
}
/**
 * Validates a contribution's `group` against the active registry.
 *
 * Always fails LOUD, never silent:
 *   - unknown group  → `{ ok: false, error }` naming the group + valid groups.
 *   - empty registry → strict: fail; permissive: pass with a `console.warn`.
 */
export function validateNavContribution(c, reg, opts = {}) {
    const empty = reg.known().length === 0;
    if (empty) {
        if (opts.permissive) {
            // Loud in dev: never a silent pass.
            console.warn(`[devedge-ufe] nav group "${c.group}" for "${c.name}" was not validated: ` +
                `the group registry is empty (no known groups configured). ` +
                `Passing because permissive mode is on — configure a GroupRegistry before production.`);
            return { ok: true };
        }
        return {
            ok: false,
            error: `nav contribution "${c.name}" declares group "${c.group}" but the group registry ` +
                `is empty (no known groups configured). Configure a GroupRegistry, or pass ` +
                `{ permissive: true } to allow this in dev.`,
        };
    }
    if (!reg.has(c.group)) {
        return {
            ok: false,
            error: `nav contribution "${c.name}" declares unknown group "${c.group}". ` +
                `Valid groups are: ${formatGroups(reg)}. ` +
                `(A wrong group renders nothing — this check makes that failure loud.)`,
        };
    }
    return { ok: true };
}
/**
 * Validates every contribution and THROWS a clear error on the first failure,
 * naming the offending contribution, its unknown group, and the valid groups.
 * This is the assertion a host runs at registration time so a bad `group`
 * fails loudly at startup instead of rendering nothing at runtime.
 */
export function assertNavContributions(cs, reg, opts = {}) {
    for (const c of cs) {
        const result = validateNavContribution(c, reg, opts);
        if (!result.ok) {
            throw new Error(`[devedge-ufe] invalid nav contribution: ${result.error}`);
        }
    }
}
//# sourceMappingURL=nav.js.map