# Direct TITLE foundation — phase 1 (CD backing, libcd HLE, pump)

Goal: advance the real path `TITLE.BZZ → guest loader path A → hook 0x80041A1C`
without inventing guest infrastructure. Path B (0x80041A64–0x80041CC8) is dead in
the retail game and is not implemented. No T5/GTE, renderer or loader hook here.

## Real container facts (LOCAL runs, nothing tracked)

Container scanner v2 (`pm_container_scan_v2.py`) on the user's `TITLE.BZZ` with
`SLES_017.26` (SHA-1 `b5c54edc…`):

| Item | Value | Confidence |
| --- | --- | --- |
| Level id / size | level 0, 489472 bytes (LBA 10383 from the level table) | CONFIRMED |
| Header | 4 entries, checksum OK, word0 ≠ 0 (ring + BZZ mode) | CONFIRMED |
| Script stream | offset 0x800, decoded 28751 bytes, starts with `-E`, overlay index 0 only | CONFIRMED |
| Overlay stream | offset 0x3000 (sector 6), decoded 0x42B4, raw SHA-1 `4b90fd64…`, masked `8039efc0…`, word0 0 on disk, six sites `1840` | CONFIRMED |
| Main data stream | offset 0x4800 | CONFIRMED |
| Ring config (`-;`) | ring size 0x27100, `0x80069576` = 500, subdivision flag `0x80069578` = 1 (two records, same values) | CONFIRMED (also observed at runtime below) |

A sandbox-only Python execution of the real code (not part of this repository)
ran `0x80015EC0 → 0x80040EF4 → 0x8004447C(0) → Loader(0, 0x80077000)` with a libcd
HLE equivalent to the one added here and on-demand sector delivery:

- `0x80040EF4`: level 0 entry LS id 0, `+6` = 1 (path A), size 489472, LBA 10383.
- Loader returned 0. Hook PC `0x80041A1C` reached once; then word0 `0x8006B340`,
  six sites `1840`, masked SHA-1 `8039efc0…`.
- 239 sectors (the whole container) delivered by ReadN, 239 `CdGetSector` calls.
- Script: 226 `-` command groups; **`,` executed once** (top-level byte at script
  offset 0xB99), but its wait loops `0x80042114`/`0x80042128` were **never
  reached**; **`K` not used** and `0x800422B8` never reached. No `,`/`K` poll point
  is needed for TITLE.
- CD commands used: Setmode `0x0E`, Getstat `0x01`, SeekL `0x15` (CdControlB);
  ReadN `0x06`, Pause `0x09` (CdControl); CdSync; CdReadCallback `0x800410DC`.
- The BZZ helper wait (`0x800448A4–0x800448E8`) needed the pump at **0x800448AC**
  238 times (it calls CdStatus only every 0xFFFF spins): that poll point is required.
- After the loader: ring size `0x27100`, `0x80069576` = 500, subdivision flag 1,
  `0x80069550` = `0x800A270C`, `0x800695E4` = `0x80077624`, `0x80069678` = 0.
- Other services reached on the same path (stubbed in the sandbox run, NOT
  implemented here): BIOS B0 `08/0A/0B/0C` (events), B0 `19`, B0 `5B`, A0 `72`,
  C0 `0A`, syscalls 1/2 (critical sections); a SPU transfer wait on TestEvent
  (`0x8004BB88`); a GPU ready poll (GPUSTAT bit 26) at `0x80053804`; library
  calls from `0x8004447C`/`0x8004440C` (`0x80051888`, `0x8004DB7C`, `0x80051604`,
  `0x80051980`, `0x800518E8`, `0x8004D908`, `0x80051B04`, `0x800546A4`, `0x800521B0`).

## Implemented in this repository

- `src/cd_backing.hpp`: read-only, on-demand sector sources. Whole disc images
  (raw 2352 Mode 2 Form 1 with sync/header/form checks per read, or cooked 2048)
  and one extracted file mapped at its LBA. BCD CdlLOC/MSF with the 150-sector
  lead-in. Nothing is preloaded or cached.
- `src/libcd_hle.hpp`: HLE of the six PAL entries (CdControlB `0x800469D4`,
  CdControl `0x80046764`, CdReadCallback `0x80046750`, CdGetSector `0x80046B40`,
  CdStatus `0x800465B8`, CdSync `0x800466FC`) as dynamic-registry backends that
  return through the guest RA. Drive state: Setmode, Getstat, Setloc, SeekL,
  ReadN, Pause; CdSync = CdlComplete. ReadN arms the drive only.
- Pump: `cdhle::pump` delivers exactly one sector per call (DataReady), read from
  the source at that moment, and runs the registered guest read callback
  interrupt-style through the registry (GPRs, HI/LO, pending load and PC of the
  interrupted code restored; no re-entrancy; an unregistered callback is fatal).
  CdStatus pumps. A sector not fully taken by CdGetSector is counted as overrun.
  The callback's result-pointer argument is passed as 0: TITLE's callback reads
  only the interrupt code.
- Not wired: the poll point `0x800448AC` and any `,`/`K` poll. The guest code that
  would reach them is not recompiled; `cdhle::pump` is the function the future
  poll point calls.

Tests: `CdBackingTest` (40 checks) and `LibcdHleTest` (183 checks; synthetic
source, ring with wrap, Pause at the section limit, register restoration,
re-entrancy, overrun, partial CdGetSector, unregistered/non-returning callbacks,
and a synthetic BZZ archive that survives virtual CD → guest buffer → decoder).
LOCAL ONLY (`build.ps1 -TitleBzz <external TITLE.BZZ>` or CMake
`MOYLE_TITLE_BZZ`): `DirectTitleExternalTest` streams the real container through
the HLE (239 sectors, on demand), decodes it (L0-B), checks `-E` index 0 (L0-C)
and recognizes overlay index 0 as the PAL TITLE overlay. Its consumer callback is
a host stand-in for the guest callback `0x800410DC`, which is not recompiled.

## Checkpoints

| CP | Status |
| --- | --- |
| L0-A TITLE.BZZ identified | reached (scanner, external test) |
| L0-B section decoded | reached host-side through the libcd HLE; guest-side only in the sandbox run |
| L0-C `-E 0` | reached host-side; guest hook PC observed only in the sandbox run |
| L0-D overlay loaded by the guest at 0x80041A1C | **not reached in this repository** |

## Blocker towards L0-D: loader closure is not recompiled

The repository recompiles four manifest regions plus a small discovery set
(35 functions). None of `0x80040EF4`, `0x8004447C`, `0x800415E0` or their callees.
Executed closure in the sandbox run: 37 game functions (the three roots,
`0x80015EC0` and 33 callees: `0x80036158 0x800361F8 0x80036244 0x800362C4
0x80036380 0x800363C8 0x80036520 0x800365C4 0x800368DC 0x8003EB0C 0x8003EB68
0x8003EBA8 0x8003EC5C 0x8003ECF4 0x8003ED18 0x8003ED8C 0x8003F9A4 0x8003F9E4
0x80040100 0x80040DD8 0x80040E1C 0x80040E70 0x80040FB8 0x80041230 0x80041278
0x800412A4 0x800412D8 0x8004157C 0x8004440C 0x800446AC 0x8004489C 0x80044A30
0x80044A4C`), 3415 executed game instructions, plus 73 library entries.

Instruction classes executed on that closure but not supported by the EXE
generator today: SRA (overlay pass only), SLLV/SRLV/SRAV, MULT/MULTU/DIVU,
MFHI/MFLO (overlay pass only), BLTZ, BLEZ/BGTZ, generic JR/JALR (the chunk
switches `0x80042364`, `0x80042400`, `0x8004282C`, `0x8004342C`, `0x80043758`
are already in the v2 GuestBound census), SYSCALL.

Next tranche (recomp foundation for loader path A):
1. EXE generator ISA for the classes above, with synthetic tests.
2. Manifest/discovery seeds for the 37 game functions and their extents.
3. A data-driven library policy: libcd HLE (this change) wired as direct-call
   targets; BIOS vector/syscall HLE (events, critical sections); minimal
   libgpu/libetc/libspu device or stubs for the calls listed above.
4. Data-driven pre-instruction poll point at `0x800448AC` calling `cdhle::pump`.
5. T2 hook at `0x80041A1C` with the T1 assertions → L0-D.
