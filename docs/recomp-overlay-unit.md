# Overlay Foundation — T3 static TITLE unit

T3 extends the existing static C++ generator with a PAL TITLE unit pass. It does
not execute the guest loader, install a T2 hook, or activate overlays automatically.
The reference baseline is `15dff094c9e38141471ef72e04073a12ae45fb94` (T1).

## Architecture and identity

`tools/recomp/overlay_unit.hpp` consumes an external raw image, validates the T1
descriptor, then emits one PC-switch executor. `src/overlay_unit.hpp` contains
internal compatibility metadata and runtime guards. PS1 addresses do not enter
the public runtime API. The existing dynamic dispatcher is unchanged.

All instructions share `Context::r`, HI/LO, pending load, PC, memory and the
instruction budget. Internal JAL/JR and tail transfers remain in that executor;
no helper becomes a native o32 call, and no implicit register save/restore is
invented. Sources are captured before pending-load retirement. Each control
instruction selects the PC after its delay slot; the slot runs once, and a load
in a return slot remains pending for the caller. JAL writes the guest PC+8;
JR/table tail jumps preserve RA. Physical, KSEG0 and KSEG1 execution addresses
use the existing RAM canonicalization, preserving the guest alias in linkage.
HI/LO moves and arithmetic right shift are supported by the overlay pass; ADD
and SUB trap on signed overflow before writing the destination.

Public entries are `80010204`, `80010258`, `8001020C`, `80012AE4`, `80012AB0`.
The setter entry `8001020C` executes the guest cull setter (T4, below).
Public entry validation and live-code validation are separate: internal helpers
are reachable within the unit, but cannot be supplied as public entrypoints.

Only `[80010204,80012B54)` is emitted, excluding `[80010930,80010BA4)` and
`[80012AA4,80012AB0)`. Word0 and all tables/fog data are data, not instructions.
Transfers to data, dead ranges or delay-slot interiors are rejected; a JR or
direct edge into `[80010930,80010BA4)` names the dead range explicitly. BREAK,
including destination `80012AA0` (`break 1`), raises a fatal diagnostic and never
continues into the `j self` at `80012AA4`, which is not emitted. Unsupported
integer instructions trap explicitly; this is not a complete MIPS ISA backend.

## Four table dispatches

| Name | JR site | Table LW | Table base | Words | Guest domain |
| --- | --- | --- | --- | --- | --- |
| JT_A | `80010DEC` | `80010DE4` | `80012B54` | 22 | indices 0..21 (type byte) |
| JT_B | `80011A94` | `80011A54` | `80012BA4` | 8 | byte offsets `08..1C` |
| JT_C | `80010368` | `80010360` | `80012BC4` | 20 | indices 0..19 (type byte) |
| JT_D | `80010928` | `800108FC` | `80012C14` | 8 | byte offsets `08..1C` |

Targets are read from the recognized input, never maintained as a manual list.
The A/B overlap is intentional. Every target must be aligned live code outside
delay slots. The table LW is declared metadata and is verified, not searched:
it must be `LW` of the JR source; every path from it (B/D: it sits in a branch
delay slot and both paths join) stays inside the dispatch region, contains no
call/indirect transfer or redefinition of the source, and retires the load
before the JR; no edge may enter the region except through that LW. At runtime
the load checks, in order and *before* any memory read: table identity,
4-byte alignment (AdEL-equivalent diagnostic), RAM routing, the exact table
extent, then the guest domain (B/D reject byte offsets `00`/`04`). It then
validates the loaded target against the generated slot. Entries that target
`80012AA0` keep their trap behavior.
A per-table ticket authorizes only the matching JR. All four are tail jumps;
they retain the original caller's RA, including dispatch to shared builders.

The generated executor revalidates the T1 fingerprint, runtime word0 and a
uniform patch state (all `1840` or all `1C40`; mixed is fatal) at every public
invocation; the setter entry alone tolerates a per-site mix of those two states,
because it rewrites all six. Unit stores into its code/word0 range fail except
the T4 whitelist below; unaligned stores currently fail explicitly as
unsupported in this pass. This is a single-threaded static-unit guard, not
generic SMC or concurrent writable-code invalidation.

## Build and optional external generation

`scripts/build.ps1 -Configuration Release -Test` builds the generator, generates
and compiles the synthetic unit, runs generator/runtime tests and compares two
independent synthetic outputs. CMake/CTest targets are also wired.

For an optional external image, after building the tools:

```powershell
.\tools\recomp\generate-overlay.ps1 `
  -Image 'C:\external\TITLE_overlay.bin' `
  -Generator '.\build\Release\OverlayUnitGenerator.exe' `
  -Output "$PWD\build\generated\title.cpp"
```

The wrapper requires input outside the repository and output under ignored
`build/generated`. It compares C++ and diagnostic disassembly across two runs.
The CLI accepts only the exact production T1 identity. Unknown images never
gain execution through the synthetic test descriptor facility. Generated real
code/disassembly must remain local, never staged. This is a generator interface,
not a game loader; runtime memory must be supplied separately.

## Reference and verification limits

Reviewed `pm_overlay_support.zip` README, OVERLAY_SPEC, JSON metadata and S10
scenario/expectations, plus `FIRST_REAL_3D_FRAME_closure.md`. The bundle has no
explicit license file. Used only factual addresses, boundaries, counts, identity
and packet semantics. No bundle source, interpreter, GTE code, complete manifest
or derived binary/disassembly was copied. All implementation and test programs
were independently written. The provenance/hash recorded in the T1 document
also applies here.

Synthetic tests assemble invented MIPS programs in memory. They cover all five
public entries, all four tables and aliases,
internal JAL/non-RA JR, unchanged guest state, delay-slot source clobbering,
pending-load retirement/return, taken/untaken branches, ADD/SUB overflow,
identity rejection, table bounds/changed targets, code/data/dead/slot boundaries,
BREAK, code writes, and controlled GTE/poll failures. The S10-shaped case
emits the specified F4/E1 packets and OT links using synthetic instructions.
It proves CPU execution and memory semantics, **not execution of the original
S10 code**. Tests require neither the ZIP nor any proprietary input file.

No identity/count/boundary discrepancy was found against the bundle. Its
real-image/oracle claims have not been independently reproduced: the suggested
external `C:\path\to\TITLE_overlay.bin` was absent. Real table-load
patterns and the actual image's instruction coverage therefore remain to be
validated by the optional generator/oracle run.

T5 now enables the documented [GTE subset](gte-t5.md) and COP2 transfers.
Deferred: other GTE commands; poll/VBlank/CD support (the RingSpaceWait spin); T2 loader
integration, rendering and GameFrame. No game frame/playability claim.
This separate overlay unit does not alter the EXE discovery census.

## T3 hardening

RingSpaceWait (`800129B4`) is emitted and runs normally: prologue, free-space
computation, the `>= 0x800` test and the return. Only `[80012A04,80012A2C)` traps,
i.e. only when the wait branch is really taken. `80012A04` is the future poll
point; no VBlank/poll scheduler is implemented.

BREAK raises `guest BREAK <code>` and, when the last overlay table transfer
targeted the trap, appends the dispatcher name/PC, table index, byte offset and,
for A/C, the element type byte (`index*4`) and element pointer (`$a0`, loaded
from work+8 before the dispatch). The table trace now records the index.

Tests added. Synthetic (committable, no proprietary input): RingSpaceWait
proceed/stop at both sides of `0x800` and for negative space; BREAK direct and
through A/C entries (N1-N3 analogues: C `0x10`/`0x44`, A `0x18`); N4 range,
alignment, RAM routing and B/D domain with proof that no rejected slot is read,
plus domain boundaries accepted; N5 dead-range JR targets and direct edges;
runtime uniform/mixed patch states; declared-LW verification failures
(redefinition on either path, call in region, external edge into region).

LOCAL ONLY (`build.ps1 -TitleImage <external image>`, or CMake
`MOYLE_TITLE_IMAGE`): `OverlayTitleExternalTest` runs the unit generated from the
real image under ignored `build/generated`. E1 (`80010258`, empty model) and E2
(`80010204`, empty model) check the unchanged packet pointer, callee-saved
registers, SP, work+0x60 = `8006B340`, and that no RAM byte outside the stack
frame changed, except in E2 the clip table and count: first clip entry
`{0005,0,-256,256,-120,120}`, terminator `FFFF`, count 1, ctx frame byte 1.
N1/N2 (object renderer, types `0x10`/`0x44`) and N3 (room renderer, `0x18`) end in
the BREAK diagnostic with JT_C/JT_A, index, type and element pointer. The real
RingSpaceWait proceeds with exactly `0x800` free and stops at `80012A04` with
`0x7FF`. The test file contains addresses and expectations only; the image and
generated code are never tracked.

Finding: before this change the production generator rejected the real image
(`Overlay JR lacks verified retired table LW`), because the B/D table LWs are in a
branch delay slot several instructions before their JR. The previous local
backward search could not express that; the declared-LW verification replaces it.
The real image now yields 2484 live words, deterministic across two runs.

## Validation recorded for this change

Release `build.ps1 -Test` plus the optional external SLES suites exited zero on
2026-10-13. New tests: 20 generator checks, 113 runtime checks, byte-identical
synthetic generation across two processes. Existing recognition, memory (90
generated cases), dynamic/guarded dispatch, resources/BZZ/CLI/startup and all
backend suites passed. External regressions include 343366 counter/native cases,
716 pad cases, unchanged v1 table golden, deterministic v2 19-site census and 45
libpad probe cases. `git diff --check` passed.

As in T1, this sandbox used the existing ignored local Zig adapter via the public
`-Zig` option to avoid the known driver/cache issue. No tracked file requires the
adapter. The complete local log is `build/overlay-t3-release.log`; the final
synthetic packet assertions were additionally rebuilt and rerun after changing
them to calculate expectations from test inputs rather than literal packet words.
CMake targets were added but CTest was not run (CMake unavailable here).

## Validation recorded for T3 hardening

This change was implemented from a session whose shell is a Linux VM on the
development machine, so Windows executables could not be run there. With Zig
0.15.2 (the pinned toolchain version, Linux host build):

- every `build.ps1 -Test` target, `OverlayUnitGenerator` and the new external
  test cross-compiled and linked for `x86_64-windows-gnu` with the project flags
  (`-O2 -Wall -Wextra -Wpedantic -Werror`, `-lbcrypt`);
- the same sources were built natively with the same flags and run: overlay
  generator (62 checks, byte-identical output across two runs), overlay runtime
  (200 checks), recognition, memory (90 generated cases), static tables v1/v2
  and GuestBound runtime, dynamic/guarded dispatch, discovery, call-state/global
  state/vector backends, resources and BZZ. The native run used test-only shims
  kept outside the repository: SHA-1 behind the BCrypt calls, and `std::min`
  overloads for an existing LP64-only `uint64_t`/`ULL` deduction difference in
  untouched discovery code;
- LOCAL ONLY: the real image generated 2484 live words deterministically and
  `OverlayTitleExternalTest` passed 61 checks.

Not run in that environment: the Windows Release `build.ps1 -Test` itself,
including `ProjectMoyle.exe` startup and BZZ CLI tests, the optional external
SLES suites, and CTest (CMake requires Windows). These must pass on Windows
before this change is accepted.

## T4 cull patch semantics

Setter `8001020C` is emitted as ordinary guest code and executed by the unit:
six `SH a0` to `site+2`, the sixth in the `JR ra` delay slot. The stores go to
guest RAM; there is no host-side cull variable. PC, RA and all registers follow
the guest code (the real setter leaves the six site addresses in `t0`..`t5`).

Each of the six sites is emitted as a branch whose target comes from the
verified low half, while the high halfword is re-read from guest RAM every time
the branch executes (`overlay::patchedBranch`): `1840` selects BLEZ, `1C40`
selects BGTZ on the captured source register (both encode `rs = v0`, `rt = 0`,
checked by the generator). Any other value is a fatal diagnostic. Nothing is
cached, so a later overlay reload or setter call is observed immediately; the
T1 initial check still requires all `1840`, runtime validation all `1840` or all
`1C40`.

Code-write protection is a whitelist specific to the PAL TITLE descriptor: in
`[80010200,80012B54)` only a halfword store to one of the six `site+2` addresses
(in any RAM alias) is allowed. A store to `site`, `site+1`, `site+3`, a byte or
word store at a site, word0 or any other code is fatal and leaves RAM unchanged.
Tables/data after the code and all other RAM keep normal store semantics. The
store does not validate the value; an unknown value is reported when a site
executes or at the next public entry.

The original T4 validation stopped before real cull sites because they require
`NCLIP`/`MFC2 MAC0`. [T5](gte-t5.md) now executes those paths and adds LOCAL ONLY
S02/S03, including the degenerate (MAC0 = 0) case, against the real TITLE unit.
Synthetic tests drive the sites with a synthetic MAC0 in `v0` instead; no NCLIP
was invented.

Tests added. Synthetic: setter to `1840` and `1C40` from uniform `1840`, uniform
`1C40` and alternating states, checking all six sites (the sixth explicitly),
exactly six ordered code stores, registers, PC/RA and every other image byte;
setter entry with an unknown site value is fatal; BLEZ/BGTZ selection for both
states, all six sites and MAC0 in {0, 1, -1, INT_MIN, INT_MAX}; RAM changed between
dispatches and inside one invocation (setter then site) changes the outcome;
guest-stored unknown value is fatal at the site; whitelist accepts `site+2`
halfword stores in three aliases and rejects `SH site`, `SB site+1/+2/+3`,
`SW site`, other code, word0 and the last code halfword, while data after the
code, normal RAM and scratchpad stay writable. LOCAL ONLY: the real setter on
the unit generated from the real image, from uniform and alternating states:
six ordered halfword stores, the sixth in the delay slot, no other code-image
byte changed, `t0`..`t5` = site addresses, E1 still valid in the `1C40` state,
and `1840` restores the code image byte for byte.

## Validation recorded for T4

The T3 hardening commit `135b85ec` was afterwards run by the maintainer with
Windows Release `build.ps1 -Test -TitleImage`: all suites green.

For T4, from the same Linux VM: all `build.ps1 -Test` targets and the external
test cross-compiled for `x86_64-windows-gnu` with Zig 0.15.2 and `-Werror`; the
native suites passed (overlay generator 78 checks with byte-identical output,
overlay runtime 685 checks, recognition, memory, static tables v1/v2, GuestBound,
dynamic/guarded dispatch, discovery, backends, resources, BZZ), using the
test-only shims described above. LOCAL ONLY: real image 2484 live words,
deterministic; `OverlayTitleExternalTest` 181 checks. Windows execution, BZZ CLI
and startup were not run in this environment.

## LANGUAGE layout and first-boot dispatch

The first-boot run showed that the overlay resident when the EXE first calls `8001020C` is the PAL LANGUAGE
type-2 image, not TITLE. LANGUAGE (`palLanguage`: `0x42B8` bytes, masked SHA-1 `d5ccba9c...`) carries the same
engine code: entries, dead ranges, sites, patch states and every table LW/JR site are identical. One pad word at
`80012B54` moves all tables and data by `palLanguageTableShift` = 4 (JT_A..D at `80012B58`, `80012BA8`,
`80012BC8`, `80012C18`), and the 12 code immediates that address them differ by +4. `build(image, identity,
tableShift, unitName)` accepts exactly TITLE/shift 0 and LANGUAGE/shift 4; the checked table load carries the shift
only when it is non-zero, so TITLE output is byte-identical. `OverlayUnitGenerator` recognizes either image and
emits `executePalTitle` or `executePalLanguage`.

`src/overlay_dispatch.hpp` is the DynamicRegistry backend for the five public entries: it refuses a pending probe
redirect and non-public entries, selects the compiled descriptor whose masked fingerprint matches live RAM (unknown
or ambiguous = fatal) and runs that executor on the shared Context; the executor still validates word0 and the patch
state. EXE code reaches it through `--external-entry ENTRY EVIDENCE` (DirectTitleGenerator, default off): a JAL to a
pinned entry outside the payload is looked up in the registry at the JAL, writes RA = JAL + 8, runs its slot once and
dispatches after the slot (`dispatchDynamic`, which checks the continuation). With the option, a probe redirect in
such a delay slot is a fatal diagnostic. `scripts/first-boot.ps1 -LanguageImage <external file>` generates the
LANGUAGE executor under `build/generated/overlay-language` (never committed) and builds FirstBoot with
`MOYLE_PAL_LANGUAGE_UNIT` whenever the Direct TITLE report lists `external_call_sites`.
Tests (synthetic only): `OverlayDispatchTest`, `ExternalEntryGeneratorTest`/`ExternalEntryRuntimeTest`, and the
LANGUAGE-shaped generator checks in `OverlayUnitGeneratorTest`.
