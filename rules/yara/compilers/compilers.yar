/*
 * BinScope default compiler/toolchain signatures. Original rules, MIT.
 * YARA-X core syntax only; no modules or includes.
 */

rule binscope_compiler_msvc
{
    meta:
        description = "PE image with MSVC toolchain indicators (Rich header and PDB)"
        author = "BinScope project"
        license = "MIT"
        source = "BinScope original"
        category = "compiler"
    strings:
        $rich = "Rich" ascii
        $rsds = "RSDS" ascii
        $pdb = ".pdb" ascii
    condition:
        uint16(0) == 0x5A4D and $rich and ($rsds or $pdb)
}

rule binscope_compiler_gcc
{
    meta:
        description = "GCC version string embedded by a GNU toolchain"
        author = "BinScope project"
        license = "MIT"
        source = "BinScope original"
        category = "compiler"
    strings:
        $gcc = "GCC: (" ascii
        $gnu = "GCC: (GNU)" ascii
    condition:
        any of them
}

rule binscope_compiler_clang
{
    meta:
        description = "Clang/LLVM version string"
        author = "BinScope project"
        license = "MIT"
        source = "BinScope original"
        category = "compiler"
    strings:
        $a = "clang version " ascii
        $b = "LLVM version " ascii
    condition:
        any of them
}

rule binscope_compiler_rust
{
    meta:
        description = "Rust runtime/panic symbols"
        author = "BinScope project"
        license = "MIT"
        source = "BinScope original"
        category = "compiler"
    strings:
        $a = "rust_begin_unwind" ascii
        $b = "RUST_BACKTRACE" ascii
        $c = "/rustc/" ascii
    condition:
        2 of them
}

rule binscope_compiler_go
{
    meta:
        description = "Go build ID or runtime symbol"
        author = "BinScope project"
        license = "MIT"
        source = "BinScope original"
        category = "compiler"
    strings:
        $a = "Go build ID:" ascii
        $b = "runtime.main" ascii
        $c = "runtime.gopanic" ascii
    condition:
        2 of them
}

rule binscope_compiler_delphi
{
    meta:
        description = "Delphi/Borland runtime or compiler strings"
        author = "BinScope project"
        license = "MIT"
        source = "BinScope original"
        category = "compiler"
    strings:
        $a = "Embarcadero Delphi" ascii
        $b = "Borland Delphi" ascii
        $c = "TApplication" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule binscope_toolchain_mingw
{
    meta:
        description = "MinGW/GCC runtime library names"
        author = "BinScope project"
        license = "MIT"
        source = "BinScope original"
        category = "compiler"
    strings:
        $a = "libgcc_s_dw2-1.dll" ascii
        $b = "libgcc_s_seh-1.dll" ascii
        $c = "libstdc++-6.dll" ascii
        $d = "mingw" nocase ascii
    condition:
        any of them
}
