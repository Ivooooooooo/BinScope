# BinScope

[English](README.md) | **Español**

Analizador estático de binarios para Windows, escrito en Rust con interfaz Tauri + React. Inspecciona PE/COFF (EXE, DLL, SYS), ensamblados .NET, ELF, Mach-O, archivos comprimidos, scripts y archivos desconocidos **sin ejecutarlos ni cargar sus bibliotecas**.

BinScope prioriza evidencia explícita, límites de recursos verificables y separación de fuentes de detección. Cada resultado conserva el motor que lo produjo, su procedencia y su nivel de certeza.

## Funciones principales

- Detección de formato por contenido, sin depender de la extensión.
- Parser PE propio con cabeceras, secciones, directorios, imports, delay imports, exports, recursos, versión, manifiesto, PDB, Rich header, TLS, overlay, Authenticode estructural y CLR.
- Anomalías PE deterministas (`BS-PE-*`) con severidad, evidencia tipada, offset/RVA/sección, esperado vs observado y notas de falsos positivos.
- Metadatos .NET/CLR: COR20, raíz BSJB, streams, tablas Module/Assembly/AssemblyRef, versión, flags, strong name y entry point.
- ELF y Mach-O con arquitectura, entry point, secciones/segmentos, bibliotecas, imports/exports, build-id y runpaths.
- Hashes SHA-256, SHA-1 y MD5 en streaming.
- Extracción de strings ASCII, UTF-8 multibyte y UTF-16LE con offsets exactos, sección y clasificación por evidencia.
- Detección de compiladores, linkers, packers, protectores, runtimes e instaladores mediante firmas internas, DIE, PE-bear/PEiD, YARA-X y heurísticas estructurales.
- Detección de Themida/WinLicense mediante los patrones de entry point y las condiciones estructurales portadas de `protector_Themida.2.sg`, marcadas como evidencia exacta o heurística fuerte, nunca como prueba de malware.
- YARA-X con reglas internas y repositorios externos, procedencia por archivo, revisión de conjunto, offsets reales, metadatos y diagnóstico de reglas rechazadas.
- Batch Analysis con recorrido acotado, concurrencia configurable, cancelación cooperativa, deduplicación por SHA-256 y exportación CSV/JSON.
- Integración opcional con el menú contextual del Explorador de Windows por usuario.
- VirusTotal opcional y desactivado por defecto; solo envía el SHA-256 tras confirmación.

## Fuentes de detección

Cada detección indica su motor y no se mezcla con las demás:

1. Firmas internas JSON.
2. Firmas reales de Detect It Easy mediante el subconjunto `compareEP` documentado.
3. PE-bear / PEiD UserDB (`SIG.txt`), descargado aparte por su licencia.
4. YARA-X externo instalado por el usuario.
5. YARA-X interno incluido en el repositorio.
6. Heurísticas estructurales y heurísticas DIE acotadas (Themida, VMProtect).

Los resultados incluyen `engine`, `vendor`, `certainty`, `source`, evidencia, offsets y notas de compatibilidad cuando corresponde. Las detecciones de distinta procedencia no se fusionan perdiendo el origen.

## YARA-X

- Compilación real de `.yar` y `.yara` con el compilador YARA-X enlazado.
- Descubrimiento recursivo, protección contra symlinks, límites de archivos y tamaño.
- Un archivo inválido no descarta las reglas válidas.
- Caché en proceso por revisión de contenido y versión del motor.
- Separación explícita entre coincidencias internas y externas.
- Evidencia con identificador de patrón, offset real, longitud, bytes y representación imprimible.
- Diagnóstico visible de errores de compilación y reglas rechazadas.

## Compilar y ejecutar

Requisitos verificados:

- Rust 1.99 o superior (`x86_64-pc-windows-msvc`).
- Visual Studio Build Tools 2022 con carga de trabajo C++.
- Node.js 24 y npm 11.
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

Los binarios de release quedan en `target/release/` y el instalador NSIS en `target/release/bundle/nsis/`.

## Paquete portable

```powershell
powershell -ExecutionPolicy Bypass -File scripts\package-release.ps1
```

Genera:

- `release\portable\` con `BinScope.exe`, `binscope.portable`, reglas, bases de firmas y checksums.
- `release\github\` con el árbol fuente listo para publicar.
- `release\BinScope-Portable-0.1.0.zip`.

Los ajustes, reglas, historial y caché de WebView2 se guardan en el perfil del usuario (`%APPDATA%\com.binscope.analyzer` y `%LOCALAPPDATA%\com.binscope.analyzer`), no dentro de la carpeta portable.

## Estructura

```text
src-tauri/                 Shell Tauri, comandos, settings, integración Windows
frontend/                  React + TypeScript + Vite
crates/common/             Reader con límites, cancelación, deadline, entropía
crates/hashing/            SHA-256/SHA-1/MD5
crates/strings/            Extracción de strings en streaming
crates/file-detect/        Detección de formato por magic
crates/pe-parser/          Parser PE y generador de fixtures
crates/elf-mach-parser/    ELF y Mach-O
crates/dotnet/             Metadatos CLR/BSJB
crates/signatures/         Firmas JSON, DIE, PE-bear y heurísticas
crates/yara-engine/        Compilación y escaneo YARA-X
crates/rules/              Inventario, categorías, perfiles y fuentes
crates/updates/            Descargas verificadas y activación atómica
crates/core/               Orquestación, informe, exportación, CLI y benchmark
databases/die/             Firmas PE del release oficial de DIE (MIT)
databases/signatures/      Base JSON propia
rules/yara/                Reglas YARA internas
tests/fixtures/            Binarios sintéticos benignos
tests/malformed-files/     Corpus sintético inválido
```

## Interfaz

La interfaz es un workbench de escritorio pensado para análisis denso: rail tipográfico, cabecera de espécimen, secciones con reglas, tablas técnicas, inspector YARA y estados explícitos de carga, error y vacío. Usa temas Light, Dark y System con paletas minerales propias.

## Seguridad y límites

- El archivo analizado nunca se ejecuta, ni se cargan sus DLL, ni se interpreta IL.
- Todos los parsers usan un `Reader` con comprobación de límites; el código propio no usa `unsafe`.
- Límites por defecto: 512 MiB para parseo estructurado, 4 GiB para streaming, 180 s de presupuesto, 100 000 strings / 16 MiB de texto, 96 secciones y 65 536 entradas.
- YARA-X tiene timeout, límite de archivos y tamaño máximo por regla.
- Los errores de un módulo se registran y el resto del análisis continúa cuando es posible.
- VirusTotal está apagado por defecto y la API key se guarda en Windows Credential Manager, nunca en el informe ni en el código.

Limitaciones conocidas:

- No hay intérprete DiE-JS completo; solo el subconjunto `compareEP` y heurísticas acotadas.
- No hay muestras reales de Themida ni el ejecutable `diec` en el repositorio; la cobertura Themida se valida con fixtures sintéticos.
- La heurística Themida estructural puede producir falsos positivos y se marca como `strong_heuristic`.
- No hay desensamblado ni análisis dinámico.
- Authenticode informa estructura y confianza, pero no convierte la firma en una garantía de seguridad.
- PE-bear `SIG.txt` no se redistribuye por GPLv2; se descarga explícitamente desde la aplicación.

## Licencia

MIT. Las dependencias conservan sus licencias. Las reglas y fixtures originales del repositorio se distribuyen bajo MIT. Las bases de terceros mantienen su licencia y atribución en `LICENSE` y en sus propios archivos de licencia.
