# Reviewed development snapshot

This candidate preserves the existing public history and imports only the file contents approved in import-manifest.json. Source labels identify inventory roles, not private Git ancestry. Hashes are file-content SHA-256 checksums.

The additions cover generic GTE MVMVA/SQR arithmetic and R3000A proof analysis with synthetic tests. This is a bounded subset of development work, not the complete first-boot runtime. Title-specific routines, static tables, generated translations, original assets, uncertain fixtures and private research remain excluded. The symbolic BIOS summaries are analysis assumptions, not a BIOS implementation or original BIOS data.

Public licensing, attribution, CI, build configuration and CD backing C++20 fixes are preserved. Build configuration is extended with explicit synthetic test targets and Python 3.

The original GTE vector test is compiled but its execution is SKIPPED: its separately reviewed external fixture is absent. No proprietary input is required by the registered tests. Excluded differential/copy-domain suites are outside this candidate and are not reported as passing.

Validation results are recorded in validation.json. Build products and local audit evidence reside only in Git administrative storage and must never be packaged for publication. Review the manifest exclusions before considering any further import.
