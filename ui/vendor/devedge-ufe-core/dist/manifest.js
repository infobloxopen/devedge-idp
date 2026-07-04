/**
 * Identity function that validates a manifest's shape, throwing a clear error
 * if a required field is missing or the wrong type. Use it as the default
 * export of a uFE's `metadata` module so shape errors fail at build/import
 * time rather than rendering nothing at runtime.
 */
export function defineManifest(m) {
    if (m == null || typeof m !== 'object') {
        throw new Error('[devedge-ufe] manifest must be an object');
    }
    if (!Array.isArray(m.navItems)) {
        throw new Error('[devedge-ufe] manifest.navItems must be an array');
    }
    if (!Array.isArray(m.routes)) {
        throw new Error('[devedge-ufe] manifest.routes must be an array');
    }
    if (!Array.isArray(m.exports)) {
        throw new Error('[devedge-ufe] manifest.exports must be an array');
    }
    for (const [i, exp] of m.exports.entries()) {
        if (!exp || typeof exp.id !== 'string' || typeof exp.entry !== 'string') {
            throw new Error(`[devedge-ufe] manifest.exports[${i}] must have string "id" and "entry"`);
        }
    }
    if (m.searchObjects !== undefined && !Array.isArray(m.searchObjects)) {
        throw new Error('[devedge-ufe] manifest.searchObjects, if present, must be an array');
    }
    return m;
}
//# sourceMappingURL=manifest.js.map