use binscope_pe::PeBuilder;
use std::fs;
use std::path::{Path, PathBuf};

fn main() -> std::io::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf();
    let fixtures = root.join("tests").join("fixtures");
    let malformed = root.join("tests").join("malformed-files");
    fs::create_dir_all(&fixtures)?;
    fs::create_dir_all(&malformed)?;

    write(
        &fixtures.join("pe32-x86.exe"),
        &PeBuilder::pe32()
            .with_export("FixtureExport")
            .with_pdb(r"C:\build\binscope\pe32-fixture.pdb")
            .build(),
    )?;

    write(&fixtures.join("msvc-rich.exe"), &{
        let mut builder = PeBuilder::pe32().with_pdb(r"C:\build\binscope\msvc-rich.pdb");
        builder.rich = true;
        builder.build()
    })?;

    write(
        &fixtures.join("pe64-x64.dll"),
        &PeBuilder::pe64()
            .dll()
            .with_export("FixtureExport")
            .with_pdb(r"C:\build\binscope\pe64-fixture.pdb")
            .build(),
    )?;

    write(
        &fixtures.join("dotnet-managed.dll"),
        &PeBuilder::pe32()
            .dll()
            .with_clr(0x1 | 0x8)
            .with_version_string("FileDescription", "Synthetic managed assembly")
            .build(),
    )?;

    write(
        &fixtures.join("dotnet-mixed.dll"),
        &PeBuilder::pe32()
            .dll()
            .with_clr(0x2)
            .with_import("mscoree.dll", "_CorExeMain")
            .build(),
    )?;

    write(
        &fixtures.join("upx-like.exe"),
        &PeBuilder::pe32()
            .with_section("UPX0", Vec::new(), 0xE000_0020)
            .with_section("UPX1", vec![0x90; 512], 0xE000_0020)
            .build(),
    )?;

    write(
        &fixtures.join("gcc-like.exe"),
        &PeBuilder::pe32()
            .with_section(".comment", b"GCC: (GNU) 13.2.0\0".to_vec(), 0x4000_0040)
            .build(),
    )?;

    let mut die_fixture = PeBuilder::pe32();
    die_fixture.text_bytes = vec![
        0x60, 0x06, 0xFC, 0x1E, 0x07, 0xBE, 0x11, 0x22, 0x33, 0x44, 0x6A, 0x04, 0x68, 0x55, 0x66,
        0x77, 0x88, 0x68, 0x90, 0x90,
    ];
    write(&fixtures.join("die-32lite.exe"), &die_fixture.build())?;

    let mut strings = Vec::new();
    strings.extend_from_slice(b"\x00ASCII fixture string: BinScope\0");
    strings.extend(
        "Wide fixture string: an\u{00E1}lisis"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes()),
    );
    strings.extend([0u8, 0]);
    strings.extend_from_slice(b"\x00short\x00completely-benign-marker-12345\x00");
    write(&fixtures.join("strings.bin"), &strings)?;

    write(&fixtures.join("elf64-x86_64"), &minimal_elf64())?;
    write(&fixtures.join("macho64-x86_64"), &minimal_macho64())?;
    write(&fixtures.join("empty.bin"), b"")?;

    let pe = PeBuilder::pe32().build();
    write(&malformed.join("truncated-pe.bin"), &pe[..64.min(pe.len())])?;
    write(&malformed.join("mz-truncated.bin"), b"MZ\x90\x00")?;

    let mut bad_lfanew = vec![0u8; 128];
    bad_lfanew[0..2].copy_from_slice(b"MZ");
    bad_lfanew[0x3c..0x40].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
    write(&malformed.join("bad-e-lfanew.exe"), &bad_lfanew)?;

    let mut bad_magic = pe.clone();
    let pe_offset = u32::from_le_bytes(bad_magic[0x3c..0x40].try_into().unwrap()) as usize;
    bad_magic[pe_offset + 24] = 0;
    bad_magic[pe_offset + 25] = 0;
    write(&malformed.join("bad-optional-magic.exe"), &bad_magic)?;

    let mut zero_sections = pe.clone();
    zero_sections[pe_offset + 6] = 0;
    zero_sections[pe_offset + 7] = 0;
    write(&malformed.join("zero-sections.exe"), &zero_sections)?;

    write(&malformed.join("truncated-elf.bin"), b"\x7fELF\x02\x01")?;

    let macho = minimal_macho64();
    write(&malformed.join("truncated-macho.bin"), &macho[..16])?;

    let noise: Vec<u8> = (0..4096u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 11) as u8)
        .collect();
    write(&malformed.join("random.bin"), &noise)?;

    let mut huge_counts = pe.clone();

    huge_counts[pe_offset + 24 + 92..pe_offset + 24 + 96]
        .copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    write(&malformed.join("huge-directory-count.exe"), &huge_counts)?;

    println!("Fixtures written to {}", fixtures.display());
    println!("Malformed samples written to {}", malformed.display());
    Ok(())
}

fn write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    fs::write(path, bytes)?;
    println!("  {} ({} bytes)", path.display(), bytes.len());
    Ok(())
}

fn minimal_elf64() -> Vec<u8> {
    let mut data = vec![0u8; 64];
    data[0..4].copy_from_slice(b"\x7fELF");
    data[4] = 2;
    data[5] = 1;
    data[6] = 1;
    data[7] = 3;
    data[16..18].copy_from_slice(&2u16.to_le_bytes());
    data[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
    data[20..24].copy_from_slice(&1u32.to_le_bytes());
    data[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
    data[52..54].copy_from_slice(&64u16.to_le_bytes());
    data[58..60].copy_from_slice(&64u16.to_le_bytes());
    data
}

fn minimal_macho64() -> Vec<u8> {
    let mut data = vec![0u8; 32];
    data[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    data[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes());
    data[8..12].copy_from_slice(&3u32.to_le_bytes());
    data[12..16].copy_from_slice(&2u32.to_le_bytes());
    data
}
