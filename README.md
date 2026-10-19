# ProjectMoyle

ProjectMoyle is a title-focused native-port project for
**Bugs Bunny: Lost in Time** for the original PlayStation.

The project explores static recompilation, PlayStation runtime behavior,
and native-platform infrastructure with the long-term goal of running the
original game on modern systems while preserving its behavior.

## Current status

ProjectMoyle is under active development.

This public repository contains only reviewed ProjectMoyle-authored
infrastructure considered suitable for redistribution. Development work
that directly depends on reverse-engineered game code, executable-derived
data, or material of uncertain redistribution status is maintained
separately and is not included here.

## Original game data

ProjectMoyle does not distribute the original game, disc images,
executables, extracted assets, BIOS files, or other proprietary game data.

Where original game data is required, users must provide their own
legally obtained copy.

## Development approach

ProjectMoyle develops title-focused recompilation tooling and runtime components
to study and reproduce the behavior required by the target title.

External technical documentation and reference projects consulted during
development are listed in [REFERENCES.md](REFERENCES.md).

Third-party code, when incorporated, must be separately identified and
licensed. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Provenance

The public repository is intentionally separated from the private
development archive used during reverse engineering and research.

See [PROVENANCE.md](PROVENANCE.md).

## License

ProjectMoyle-authored code in this repository is licensed under the
MIT License unless otherwise stated.

This license does not grant rights to Bugs Bunny: Lost in Time,
its assets, trademarks, original executable code, or any other
third-party intellectual property.

## Building

ProjectMoyle currently requires:

- CMake 3.20 or newer
- a C++20-compatible compiler
- a supported build backend such as Ninja

Example:

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

The initial public source set contains only tests that use synthetic or
redistributable data.

Some development tests used by the private research archive require
separately reviewed fixtures or original game data and are intentionally
not included here.
