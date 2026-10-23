# Overlay Foundation — tranche 1

This document describes T1. The subsequent static-unit generator and its explicit
T4/T5 limits are documented in [Overlay T3](recomp-overlay-unit.md).

Only metadata, fingerprinting and initial-load recognition are implemented, in
`moyle::detail::recomp::overlay`. No loader hook or runtime execution path is added.
The production `recognize()` accepts only the compiled PAL descriptors (TITLE; since the
LANGUAGE tranche also LANGUAGE, see [Overlay T3](recomp-overlay-unit.md#language-layout-and-first-boot-dispatch));
unknown base, size or digest throws `RecognitionError` with a fatal diagnostic.
There is no dynamic registration or silent fallback. Addresses stay inside the
recomp/compatibility layer.

## PAL identity

| Field | Value |
| --- | --- |
| Overlay | TITLE type-2, PAL SLES_017.26 |
| Canonical base | `0x80010200` |
| Exact size | `0x42B4` |
| Masked SHA-1 | `8039efc0f86388d94659c8fb29cef0f9b67eae84` |
| Runtime word0 | `0x8006B340` |
| Initial patch upper half | `0x1840` at every site |
| Alternate patch upper half | `0x1C40`, runtime only, at every site (uniform) |
| Patch sites | `0x800103A4`, `0x80010460`, `0x80010530`, `0x800105EC`, `0x800106B4`, `0x8001077C` |

Fingerprinting copies the supplied image and zeroes bytes `[0,4)` and each
`[site-base+2,site-base+4)`. All other bytes, including the low halves of the patch
instructions, participate in SHA-1. The caller's input is never modified.
SHA-1 uses the Windows CNG provider, not copied bundle code or a handwritten hash.
It is a compatibility identifier, not authentication of hostile input.
See [Microsoft's CNG hash API documentation](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcrypthash).

`fingerprint()` computes identity only. `validateInitialLoad()` also checks the
six upper halves, even though they are excluded from the hash:

- `InitialImage`: exact base/size, matching masked hash and all six sites at
  `0x1840`. Word0 is not part of identity: an image with word0 zero, as on disk,
  is recognized. `0x8006B340` is never required at this phase.
- `RuntimeLoaded`: exact base/size, matching masked hash, word0 exactly
  `0x8006B340`, and a uniform patch state: all six sites `0x1840` or all six
  `0x1C40`. A mixed state or any other high half is fatal.

- `RuntimeSetterEntry`: as `RuntimeLoaded`, but a per-site mix of `0x1840` and
  `0x1C40` is tolerated because the setter rewrites all six sites. Any other
  high half is still fatal.

Patch execution semantics (T4) are described in [Overlay T3](recomp-overlay-unit.md).
No generic writable-code invalidation or continued monitoring is implemented.
Callers must perform runtime-loaded validation after writing word0; this does not
write it or claim that the current game loader already calls this API.
Physical/KSEG1 aliases are not alternate overlay identities: this descriptor
requires its exact base. Recognition has no registry: `recognize()` accepts only
the compiled PAL descriptor, so duplicate id/hash registration cannot occur.

## Reference/provenance review

Reviewed before implementation from the user-supplied `pm_overlay_support.zip`:
`README.md`, `spec/OVERLAY_SPEC.md`, the identity/patch portions of
`spec/overlay_title_pal.json`, and `tools/ovl_verify_spec.py` to cross-check masks.
Bundle SHA-256:
`B7D4C967DCA441979984510D2ADA6118DFE860FEB84C9EC6B3838B707E29AA1C`.

The bundle describes itself as read-only RE material prepared by Claude on
2026-10-13, not code built/tested in ProjectMoyle. Its archive contains no explicit
license file. No source file, prose, test vector or complete manifest was copied.
Only the factual identity constants and masking requirements were transcribed;
implementation and synthetic tests were written for this repository.
`gte_ref.py` and all other GTE/oracle code were not reused. No overlay image,
disassembly, dump or executable-derived byte sequence is needed by this tranche.

No discrepancy was found between the requested tranche-1 values and the bundle's
JSON, prose or masking procedure. Broader bundle suggestions (GTE ports, tables,
renderer, poll points, oracle execution) are deliberately outside this tranche.
The bundle's claims of tests on a real image are provenance information, not a
claim that this change independently ran that image.

## Synthetic verification

`OverlayRecognitionTest` is wired into Release `build.ps1 -Test` and CTest.
It creates a deterministic byte pattern in memory, using the PAL-sized layout
with synthetic contents and a separate test descriptor. Its expected masked
digest was independently calculated with .NET SHA1. This exercises the same
validator without pretending synthetic bytes match the real PAL digest.

Tests cover metadata constants, matching synthetic fingerprint, word0 masking,
each high-half mask, rejection of every altered initial patch (including `1C40`),
uniform runtime `1840`/`1C40` acceptance, every mixed runtime split in both
directions, equal initial/alternate metadata rejection,
hashed low halves/other bytes, runtime word0, unknown hash/base/size, immutable
input, invalid phase and malformed mask locations. Production recognition rejects
the synthetic image. Tests do not read files and depend on neither the bundle
nor any external game asset.

No overlay recompilation, jump tables, GTE, renderer, RingSpaceWait or GameFrame
is implemented. Recognition does not register host functions or authorize code
execution.

Release validation on 2026-10-13 passed with `build.ps1 -Test` and the existing
optional external SLES regression suites, including 716 pad cases and the unchanged
static-table v1 golden/v2 census. The session used the existing ignored local Zig
adapter via `-Zig` for the known sandbox driver/cache limitation; no tracked source
depends on it. CMake wiring was added but CTest was not run in this environment.
