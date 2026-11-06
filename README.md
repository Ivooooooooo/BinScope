# BinScope

**English** | [Español](README.es.md)

Static binary analyzer for Windows, written in Rust with a Tauri + React interface. It inspects PE/COFF (EXE, DLL, SYS), .NET assemblies, ELF, Mach-O, archives, scripts and unknown files **without executing them or loading their libraries**.

BinScope prioritizes explicit evidence, verifiable resource limits, and separation between detection sources. Every result keeps the engine that produced it, its provenance, and its certainty level.

## Main features

- Content-based format detection, independent of file extension.
- Native PE parser covering headers, sections, directories, imports, delay imports, exports, resources, version info, manifest, PDB, Rich header, TLS, overlay, structural Authenticode and CLR.
- Deterministic PE anomalies (`BS-PE-*`) with severity, typed evidence, offset/RVA/section, expected vs. observed values, and false-positive notes.
- .NET/CLR metadata: COR20, BSJB root, streams, Module/Assembly/AssemblyRef tables, version, flags, strong name and entry point.
- ELF and Mach-O with architecture, entry point, sections/segments, libraries, imports/exports, build-id and runpaths.
- SHA-256, SHA-1 and MD5 hashing in streaming mode.
- ASCII, multibyte UTF-8 and UTF-16LE string extraction with exact offsets, section attribution and evidence-based classification.
- Detection of compilers, linkers, packers, protectors, runtimes and installers through internal signatures, DIE, PE-bear/PEiD, YARA-X and structural heuristics.
- Themida/WinLicense detection using the entry-point patterns and structural conditions ported from `protector_Themida.2.sg`, marked as exact evidence or strong heuristic, never as proof of malware.
- YARA-X with internal rules and external repositories, per-file provenance, rule-set revision, real offsets, metadata and diagnostics for rejected rules.
- Batch Analysis with bounded traversal, configurable concurrency, cooperative cancellation, SHA-256 deduplication and CSV/JSON export.
- Optional per-user integration with the Windows Explorer context menu.
- Optional VirusTotal integration, disabled by default; it sends only the SHA-256 after confirmation.

## Detection sources

Every detection reports its engine and is not mixed with the others:

1. Internal JSON signatures.
2. Real Detect It Easy signatures through the documented `compareEP` subset.
3. PE-bear / PEiD UserDB (`SIG.txt`), downloaded separately because of its license.
4. External YARA-X rules installed by the user.
5. Internal YARA-X rules bundled with the repository.
6. Structural heuristics and bounded DIE heuristics (Themida, VMProtect).

Results include `engine`, `vendor`, `certainty`, `source`, evidence, offsets and compatibility notes when applicable. Detections from different sources are never merged in a way that loses their origin.

## YARA-X

- Real compilation of `.yar` and `.yara` files with the linked YARA-X compiler.
- Recursive discovery, symlink protection, and file-count and size limits.
- One invalid file does not discard valid rules.
- In-process cache keyed by content revision and engine version.
- Explicit separation between internal and external matches.
- Evidence with pattern identifier, real offset, length, bytes and printable representation.
- Visible diagnostics for compilation errors and rejected rules.

## Build and run

Verified requirements:

- Rust 1.99 or newer (`x86_64-pc-windows-msvc`).
- Visual Studio Build Tools 2022 with the C++ workload.
- Node.js 24 and npm 11.
- WebView2 Runtime.

```powershell
npm --prefix frontend install

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

npm --prefix frontend test
npm --prefix frontend run build

npx --prefix frontend tauri dev
npx --prefix frontend tauri build
```

Release binaries are written to `target/release/` and the NSIS installer to `target/release/bundle/nsis/`.

## Portable package

```powershell
powershell -ExecutionPolicy Bypass -File scripts\package-release.ps1
```

It produces:

- `release\portable\` with `BinScope.exe`, `binscope.portable`, rules, signature databases and checksums.
- `release\github\` with the source tree ready to publish.
- `release\BinScope-Portable-0.1.0.zip`.

Settings, rules, history and the WebView2 cache are stored in the user profile (`%APPDATA%\com.binscope.analyzer` and `%LOCALAPPDATA%\com.binscope.analyzer`), not inside the portable folder.

## Structure

```text
src-tauri/                 Tauri shell, commands, settings, Windows integration
frontend/                  React + TypeScript + Vite
crates/common/             Bounds-checked reader, cancellation, deadline, entropy
crates/hashing/            SHA-256/SHA-1/MD5
crates/strings/            Streaming string extraction
crates/file-detect/        Magic-based format detection
crates/pe-parser/          PE parser and fixture generator
crates/elf-mach-parser/    ELF and Mach-O
crates/dotnet/             CLR/BSJB metadata
crates/signatures/         JSON, DIE, PE-bear signatures and heuristics
crates/yara-engine/        YARA-X compilation and scanning
crates/rules/              Inventory, categories, profiles and sources
crates/updates/            Verified downloads and atomic activation
crates/core/               Orchestration, report, export, CLI and benchmark
databases/die/             PE signatures from the official DIE release (MIT)
databases/signatures/      Built-in JSON database
rules/yara/                Internal YARA rules
tests/fixtures/            Synthetic benign binaries
tests/malformed-files/     Synthetic invalid corpus
```

## Interface

The interface is a desktop workbench built for dense analysis: typographic rail, specimen header, ruled sections, technical tables, YARA inspector, and explicit loading, error and empty states. It ships with Light, Dark and System themes using distinct mineral palettes.

## Security and limits

- The analyzed file is never executed, its DLLs are never loaded, and IL is never interpreted.
- All parsers use a bounds-checked `Reader`; first-party code does not use `unsafe`.
- Default limits: 512 MiB for structured parsing, 4 GiB for streaming, 180 s time budget, 100,000 strings / 16 MiB of text, 96 sections and 65,536 entries.
- YARA-X has a timeout, file-count limit and maximum size per rule.
- Module errors are recorded and the rest of the analysis continues when possible.
- VirusTotal is disabled by default; the API key is stored in Windows Credential Manager, never in the report or source code.

Known limitations:

- There is no full DiE-JS interpreter; only the `compareEP` subset and bounded heuristics.
- No real Themida samples or the `diec` executable are included in the repository; Themida coverage is validated with synthetic fixtures.
- The structural Themida heuristic can produce false positives and is marked `strong_heuristic`.
- There is no disassembly or dynamic analysis.
- Authenticode reports structure and trust, but a signature is not a security guarantee.
- PE-bear `SIG.txt` is not redistributed under GPLv2; it is downloaded explicitly from the application.

## License

MIT. Dependencies retain their own licenses. Original rules and fixtures in this repository are distributed under MIT. Third-party databases retain their licenses and attribution in `LICENSE` and their own license files.
