#![allow(clippy::needless_range_loop)]

use crate::headers::compute_checksum;

#[derive(Clone, Debug)]
pub struct PeBuilder {
    pub is_64: bool,
    pub dll: bool,
    pub subsystem: u16,
    pub timestamp: u32,
    pub linker_version: (u8, u8),

    pub imports: Vec<(String, Vec<String>)>,
    pub exports: Vec<String>,
    pub manifest: Option<String>,
    pub version_strings: Vec<(String, String)>,
    pub pdb_path: Option<String>,
    pub clr: bool,
    pub clr_flags: u32,

    pub extra_sections: Vec<(String, Vec<u8>, u32)>,
    pub overlay: Vec<u8>,
    pub rich: bool,
    pub certificate: bool,
    pub text_bytes: Vec<u8>,
}

impl Default for PeBuilder {
    fn default() -> Self {
        Self {
            is_64: false,
            dll: false,
            subsystem: 3,
            timestamp: 0x6500_0000,
            linker_version: (14, 29),
            imports: vec![(
                "KERNEL32.dll".to_string(),
                vec![
                    "GetProcAddress".to_string(),
                    "ExitProcess".to_string(),
                    "VirtualAlloc".to_string(),
                ],
            )],
            exports: Vec::new(),
            manifest: None,
            version_strings: vec![
                ("CompanyName".into(), "BinScope Test".into()),
                ("FileDescription".into(), "Synthetic PE fixture".into()),
                ("FileVersion".into(), "1.2.3.4".into()),
                ("ProductName".into(), "BinScope Fixtures".into()),
            ],
            pdb_path: None,
            clr: false,
            clr_flags: 0x1 | 0x8,
            extra_sections: Vec::new(),
            overlay: Vec::new(),
            rich: false,
            certificate: false,
            text_bytes: vec![0x90, 0x90, 0x48, 0x31, 0xc0, 0xc3],
        }
    }
}

impl PeBuilder {
    pub fn pe32() -> Self {
        Self::default()
    }

    pub fn pe64() -> Self {
        Self {
            is_64: true,
            ..Self::default()
        }
    }

    pub fn dll(mut self) -> Self {
        self.dll = true;
        self
    }

    pub fn with_import(mut self, dll: &str, function: &str) -> Self {
        if let Some(entry) = self
            .imports
            .iter_mut()
            .find(|(n, _)| n.eq_ignore_ascii_case(dll))
        {
            entry.1.push(function.to_string());
        } else {
            self.imports
                .push((dll.to_string(), vec![function.to_string()]));
        }
        self
    }

    pub fn with_export(mut self, name: &str) -> Self {
        self.exports.push(name.to_string());
        self
    }

    pub fn with_manifest(mut self, manifest: &str) -> Self {
        self.manifest = Some(manifest.to_string());
        self
    }

    pub fn with_pdb(mut self, path: &str) -> Self {
        self.pdb_path = Some(path.to_string());
        self
    }

    pub fn with_section(mut self, name: &str, bytes: Vec<u8>, characteristics: u32) -> Self {
        self.extra_sections
            .push((name.to_string(), bytes, characteristics));
        self
    }

    pub fn with_overlay(mut self, bytes: Vec<u8>) -> Self {
        self.overlay = bytes;
        self
    }

    pub fn with_clr(mut self, flags: u32) -> Self {
        self.clr = true;
        self.clr_flags = flags;
        self
    }

    pub fn with_version_string(mut self, key: &str, value: &str) -> Self {
        if let Some(entry) = self.version_strings.iter_mut().find(|(k, _)| k == key) {
            entry.1 = value.to_string();
        } else {
            self.version_strings
                .push((key.to_string(), value.to_string()));
        }
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let pe_offset = 0x100usize;
        let opt_size = if self.is_64 { 0xF0usize } else { 0xE0usize };
        let nsec = 3 + self.extra_sections.len();
        let headers_end = pe_offset + 4 + 20 + opt_size + nsec * 40;
        let size_headers = align(headers_end, 0x200) as u32;

        let text_rva = 0x1000u32;
        let rdata_rva = 0x2000u32;
        let data_rva = 0x3000u32;
        let extra_rva_base = 0x4000u32;

        let mut text = self.text_bytes.clone();
        text.resize(0x200, 0x90);
        let text_raw_size = align(text.len(), 0x200) as u32;

        let rdata_raw = size_headers + 0x200;
        let (rdata, export_info, import_info, resource_info, debug_rva, clr_dir) =
            self.build_rdata(rdata_rva, text_rva, rdata_raw);

        let mut sections: Vec<(String, Vec<u8>, u32, u32)> = vec![
            (".text".into(), text, 0x6000_0020, text_rva),
            (".rdata".into(), rdata, 0x4000_0040, rdata_rva),
            (".data".into(), vec![0x42; 0x20], 0xC000_0040, data_rva),
        ];
        for (i, (name, bytes, chars)) in self.extra_sections.iter().enumerate() {
            sections.push((
                name.clone(),
                bytes.clone(),
                0x4000_0040 | *chars,
                extra_rva_base + 0x1000 * i as u32,
            ));
        }

        let mut raw_offset = size_headers;
        let mut laid_out: Vec<(String, u32, Vec<u8>, u32, u32, u32)> = Vec::new();
        for (name, bytes, chars, rva) in sections {
            let raw_size = align(bytes.len(), 0x200).max(if bytes.is_empty() { 0 } else { 0x200 });
            let virtual_size = bytes.len().max(1) as u32;
            laid_out.push((name, rva, bytes, raw_size as u32, raw_offset, chars));
            raw_offset += raw_size as u32;
            let _ = virtual_size;
        }
        let sections_end = raw_offset;

        let cert_offset = sections_end + self.overlay.len() as u32;
        let cert_size = if self.certificate { 0x40u32 } else { 0 };

        let last_rva = laid_out
            .iter()
            .map(|(_, rva, bytes, _, _, _)| *rva as u64 + bytes.len().max(1) as u64)
            .max()
            .unwrap_or(0x1000);
        let size_of_image = align(last_rva as usize, 0x1000) as u32;

        let mut image = vec![0u8; sections_end as usize];

        image[0..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
        let stub = b"This program cannot be run in DOS mode.\r\n$";
        image[0x40..0x40 + stub.len()].copy_from_slice(stub);
        if self.rich {
            write_rich_header(&mut image, 0x80, pe_offset);
        }

        image[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
        let fh = pe_offset + 4;
        let machine: u16 = if self.is_64 { 0x8664 } else { 0x014c };
        write_u16(&mut image, fh, machine);
        write_u16(&mut image, fh + 2, laid_out.len() as u16);
        write_u32(&mut image, fh + 4, self.timestamp);
        write_u16(&mut image, fh + 16, opt_size as u16);
        let mut characteristics: u16 = 0x0002;
        if !self.is_64 {
            characteristics |= 0x0100;
        }
        characteristics |= 0x0020;
        if self.dll {
            characteristics |= 0x2000;
        }
        write_u16(&mut image, fh + 18, characteristics);

        let opt = fh + 20;
        write_u16(&mut image, opt, if self.is_64 { 0x20b } else { 0x10b });
        image[opt + 2] = self.linker_version.0;
        image[opt + 3] = self.linker_version.1;
        write_u32(&mut image, opt + 4, text_raw_size);
        write_u32(
            &mut image,
            opt + 8,
            align(laid_out[1].2.len(), 0x200) as u32,
        );
        write_u32(&mut image, opt + 12, 0);
        write_u32(&mut image, opt + 16, text_rva);
        write_u32(&mut image, opt + 20, text_rva);
        if self.is_64 {
            write_u64(&mut image, opt + 24, 0x0000_0001_4000_0000);
        } else {
            write_u32(&mut image, opt + 24, data_rva);
            write_u32(&mut image, opt + 28, 0x0040_0000);
        }
        write_u32(&mut image, opt + 32, 0x1000);
        write_u32(&mut image, opt + 36, 0x200);
        write_u16(&mut image, opt + 40, 6);
        write_u16(&mut image, opt + 48, 6);
        write_u32(&mut image, opt + 56, size_of_image);
        write_u32(&mut image, opt + 60, size_headers);
        write_u32(&mut image, opt + 64, 0);
        write_u16(&mut image, opt + 68, self.subsystem);
        write_u16(&mut image, opt + 70, 0x8160);
        if self.is_64 {
            write_u64(&mut image, opt + 72, 0x10_0000);
            write_u64(&mut image, opt + 80, 0x1000);
            write_u64(&mut image, opt + 88, 0x10_0000);
            write_u64(&mut image, opt + 96, 0x1000);
            write_u32(&mut image, opt + 108, 16);
        } else {
            write_u32(&mut image, opt + 72, 0x10_0000);
            write_u32(&mut image, opt + 76, 0x1000);
            write_u32(&mut image, opt + 80, 0x10_0000);
            write_u32(&mut image, opt + 84, 0x1000);
            write_u32(&mut image, opt + 92, 16);
        }
        let dirs = if self.is_64 { opt + 112 } else { opt + 96 };
        if let Some((rva, size)) = export_info {
            write_u32(&mut image, dirs, rva);
            write_u32(&mut image, dirs + 4, size);
        }
        if let Some((rva, size)) = import_info {
            write_u32(&mut image, dirs + 8, rva);
            write_u32(&mut image, dirs + 12, size);
        }
        if let Some((rva, size)) = resource_info {
            write_u32(&mut image, dirs + 16, rva);
            write_u32(&mut image, dirs + 20, size);
        }
        if let Some(debug_rva) = debug_rva {
            write_u32(&mut image, dirs + 48, debug_rva);
            write_u32(&mut image, dirs + 52, 28);
        }
        if self.certificate {
            write_u32(&mut image, dirs + 32, cert_offset);
            write_u32(&mut image, dirs + 36, cert_size);
        }
        if let Some((rva, size)) = clr_dir {
            write_u32(&mut image, dirs + 112, rva);
            write_u32(&mut image, dirs + 116, size);
        }

        let sth = opt + opt_size;
        for (i, (name, rva, bytes, raw_size, off, chars)) in laid_out.iter().enumerate() {
            let base = sth + i * 40;
            let mut name_bytes = [0u8; 8];
            for (j, b) in name.bytes().take(8).enumerate() {
                name_bytes[j] = b;
            }
            image[base..base + 8].copy_from_slice(&name_bytes);
            write_u32(&mut image, base + 8, bytes.len().max(1) as u32);
            write_u32(&mut image, base + 12, *rva);
            write_u32(&mut image, base + 16, *raw_size);
            write_u32(&mut image, base + 20, *off);
            write_u32(&mut image, base + 36, *chars);
            if *raw_size > 0 {
                let start = *off as usize;
                let end = start + *raw_size as usize;
                let clear_end = end.min(image.len());
                image[start..clear_end].iter_mut().for_each(|b| *b = 0);
                image[start..start + bytes.len()].copy_from_slice(bytes);
            }
        }

        image.extend_from_slice(&self.overlay);
        if self.certificate {
            let cert = build_fake_certificate();
            image.extend_from_slice(&cert);
        }

        let chk = compute_checksum(&image, (opt + 64) as u64);
        write_u32(&mut image, opt + 64, chk);
        image
    }

    #[allow(clippy::type_complexity)]
    fn build_rdata(
        &self,
        base: u32,
        text_rva: u32,
        raw_offset: u32,
    ) -> (
        Vec<u8>,
        Option<(u32, u32)>,
        Option<(u32, u32)>,
        Option<(u32, u32)>,
        Option<u32>,
        Option<(u32, u32)>,
    ) {
        let mut rdata: Vec<u8> = Vec::new();
        let width = if self.is_64 { 8usize } else { 4usize };
        let imports = effective_imports(self);

        let desc_size = 20 * (imports.len() + 1);
        rdata.resize(desc_size, 0);

        #[derive(Clone)]
        struct LibPlan {
            ilt_rva: u32,
            iat_rva: u32,
            function_rvas: Vec<u32>,
        }

        let mut libs: Vec<LibPlan> = Vec::new();
        for (_name, funcs) in &imports {
            let ilt_rva = base + rdata.len() as u32;
            rdata.resize(rdata.len() + (funcs.len() + 1) * width, 0);
            libs.push(LibPlan {
                ilt_rva,
                iat_rva: 0,
                function_rvas: Vec::new(),
            });
        }
        for (i, (_, funcs)) in imports.iter().enumerate() {
            let iat_rva = base + rdata.len() as u32;
            rdata.resize(rdata.len() + (funcs.len() + 1) * width, 0);
            libs[i].iat_rva = iat_rva;
        }

        for (i, (_, funcs)) in imports.iter().enumerate() {
            for func in funcs {
                let rva = base + rdata.len() as u32;
                rdata.extend_from_slice(&0u16.to_le_bytes());
                rdata.extend_from_slice(func.as_bytes());
                rdata.push(0);
                if rdata.len() % 2 != 0 {
                    rdata.push(0);
                }
                libs[i].function_rvas.push(rva);
            }
        }

        let mut name_rvas = Vec::new();
        for (name, _) in &imports {
            let rva = base + rdata.len() as u32;
            rdata.extend_from_slice(name.as_bytes());
            rdata.push(0);
            name_rvas.push(rva);
        }

        for (i, lib) in libs.iter().enumerate() {
            let d = i * 20;
            write_u32(&mut rdata, d, lib.ilt_rva);
            write_u32(&mut rdata, d + 12, name_rvas[i]);
            write_u32(&mut rdata, d + 16, lib.iat_rva);
            for (j, function_rva) in lib.function_rvas.iter().enumerate() {
                let value = *function_rva as u64;
                let ilt_off = (lib.ilt_rva - base) as usize + j * width;
                let iat_off = (lib.iat_rva - base) as usize + j * width;
                write_thunk(&mut rdata, ilt_off, value, width);
                write_thunk(&mut rdata, iat_off, value, width);
            }
            let term_off = (lib.iat_rva - base) as usize + lib.function_rvas.len() * width;
            write_thunk(&mut rdata, term_off, 0, width);
        }
        align_vec(&mut rdata, 4);

        let export_info = if self.exports.is_empty() {
            None
        } else {
            Some(self.build_exports(&mut rdata, base, text_rva))
        };

        align_vec(&mut rdata, 4);
        let resource_info = if self.manifest.is_some() || !self.version_strings.is_empty() {
            let start = rdata.len();
            let version_blob = build_version_resource(&self.version_strings, (1, 2, 3, 4));
            let manifest_blob = self.manifest.clone().unwrap_or_default();
            let blob = build_resource_tree(
                base,
                rdata.len() as u32,
                manifest_blob.as_bytes(),
                &version_blob,
            );
            rdata.extend_from_slice(&blob);
            Some((base + start as u32, blob.len() as u32))
        } else {
            None
        };

        let mut clr_directory = None;
        if self.clr {
            align_vec(&mut rdata, 4);
            let cor20_off = rdata.len();
            rdata.extend_from_slice(&[0u8; 72]);
            let meta_off = rdata.len();
            let meta = build_dotnet_metadata();
            rdata.extend_from_slice(&meta);
            let cor20_rva = base + cor20_off as u32;
            let meta_rva = base + meta_off as u32;
            write_u32(&mut rdata, cor20_off, 72);
            write_u16(&mut rdata, cor20_off + 4, 2);
            write_u16(&mut rdata, cor20_off + 6, 5);
            write_u32(&mut rdata, cor20_off + 8, meta_rva);
            write_u32(&mut rdata, cor20_off + 12, meta.len() as u32);
            write_u32(&mut rdata, cor20_off + 16, self.clr_flags);
            write_u32(&mut rdata, cor20_off + 20, 0x0600_0001);
            if self.clr_flags & 0x8 != 0 {
                let strong_off = rdata.len();
                rdata.extend_from_slice(&[0xAA; 16]);
                write_u32(&mut rdata, cor20_off + 32, base + strong_off as u32);
                write_u32(&mut rdata, cor20_off + 36, 16);
            }
            clr_directory = Some((cor20_rva, 72));
        }

        let mut debug_rva = None;
        if let Some(path) = &self.pdb_path {
            align_vec(&mut rdata, 4);
            let debug_dir_off = rdata.len();
            rdata.extend_from_slice(&[0u8; 28]);
            let mut blob = Vec::new();
            blob.extend_from_slice(b"RSDS");
            blob.extend_from_slice(&[
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
                0xff, 0x00,
            ]);
            blob.extend_from_slice(&1u32.to_le_bytes());
            blob.extend_from_slice(path.as_bytes());
            blob.push(0);
            let blob_off = rdata.len();
            rdata.extend_from_slice(&blob);
            let dbg_rva = base + debug_dir_off as u32;
            write_u32(&mut rdata, debug_dir_off + 12, 2);
            write_u32(&mut rdata, debug_dir_off + 16, blob.len() as u32);
            write_u32(&mut rdata, debug_dir_off + 20, base + blob_off as u32);
            write_u32(&mut rdata, debug_dir_off + 24, raw_offset + blob_off as u32);
            debug_rva = Some(dbg_rva);
        }

        align_vec(&mut rdata, 0x200);
        (
            rdata,
            export_info,
            Some((base, desc_size as u32)),
            resource_info,
            debug_rva,
            clr_directory,
        )
    }

    fn build_exports(&self, rdata: &mut Vec<u8>, base: u32, text_rva: u32) -> (u32, u32) {
        let start = rdata.len();
        rdata.extend_from_slice(&[0u8; 40]);
        let dir_rva = base + start as u32;
        let funcs_start = rdata.len();
        let count = self.exports.len();
        rdata.resize(funcs_start + count * 4, 0);
        for i in 0..count {
            write_u32(rdata, funcs_start + i * 4, text_rva + 0x10 + i as u32);
        }
        let names_start = rdata.len();
        rdata.resize(names_start + count * 4, 0);
        let names_ord_start = rdata.len();
        rdata.resize(names_ord_start + count * 2, 0);
        for i in 0..count {
            write_u16(rdata, names_ord_start + i * 2, i as u16);
        }
        let mut name_rvas = Vec::new();
        for name in &self.exports {
            let rva = base + rdata.len() as u32;
            rdata.extend_from_slice(name.as_bytes());
            rdata.push(0);
            name_rvas.push(rva);
        }
        let dll_name_rva = base + rdata.len() as u32;
        rdata.extend_from_slice(b"binscope-fixture.dll\0");
        for (i, rva) in name_rvas.iter().enumerate() {
            write_u32(rdata, names_start + i * 4, *rva);
        }
        write_u32(rdata, start + 12, dll_name_rva);
        write_u32(rdata, start + 16, 1);
        write_u32(rdata, start + 20, count as u32);
        write_u32(rdata, start + 24, count as u32);
        write_u32(rdata, start + 28, base + funcs_start as u32);
        write_u32(rdata, start + 32, base + names_start as u32);
        write_u32(rdata, start + 36, base + names_ord_start as u32);
        (dir_rva, (rdata.len() - start) as u32)
    }
}

fn effective_imports(builder: &PeBuilder) -> Vec<(String, Vec<String>)> {
    builder
        .imports
        .iter()
        .filter(|(_, funcs)| !funcs.is_empty())
        .cloned()
        .collect()
}

fn build_resource_tree(base: u32, offset: u32, manifest: &[u8], version: &[u8]) -> Vec<u8> {
    let dir_size = 32 + 6 * 24 + 2 * 16;

    let mut out = vec![0u8; dir_size];
    align_vec(&mut out, 4);
    let blob_off = out.len();
    let manifest_off = blob_off;
    out.extend_from_slice(manifest);
    align_vec(&mut out, 4);
    let version_off = out.len();
    out.extend_from_slice(version);
    align_vec(&mut out, 4);

    let m_type = 32u32;
    let m_name = 56u32;
    let m_lang = 80u32;
    let m_data = 104u32;
    let v_type = 120u32;
    let v_name = 144u32;
    let v_lang = 168u32;
    let v_data = 192u32;

    write_u16(&mut out, 12, 0);
    write_u16(&mut out, 14, 2);
    write_resource_entry(&mut out, 16, 24, 0x8000_0000 | m_type);
    write_resource_entry(&mut out, 24, 16, 0x8000_0000 | v_type);

    write_resource_dir(&mut out, m_type as usize, 1);
    write_resource_entry(&mut out, m_type as usize + 16, 1, 0x8000_0000 | m_name);
    write_resource_dir(&mut out, v_type as usize, 1);
    write_resource_entry(&mut out, v_type as usize + 16, 1, 0x8000_0000 | v_name);

    write_resource_dir(&mut out, m_name as usize, 1);
    write_resource_entry(&mut out, m_name as usize + 16, 1033, 0x8000_0000 | m_lang);
    write_resource_dir(&mut out, v_name as usize, 1);
    write_resource_entry(&mut out, v_name as usize + 16, 1033, 0x8000_0000 | v_lang);

    write_resource_dir(&mut out, m_lang as usize, 1);
    write_resource_entry(&mut out, m_lang as usize + 16, 1033, m_data);
    write_resource_dir(&mut out, v_lang as usize, 1);
    write_resource_entry(&mut out, v_lang as usize + 16, 1033, v_data);

    write_u32(
        &mut out,
        m_data as usize,
        base + offset + manifest_off as u32,
    );
    write_u32(&mut out, m_data as usize + 4, manifest.len() as u32);
    write_u32(&mut out, m_data as usize + 8, 1200);
    write_u32(
        &mut out,
        v_data as usize,
        base + offset + version_off as u32,
    );
    write_u32(&mut out, v_data as usize + 4, version.len() as u32);
    write_u32(&mut out, v_data as usize + 8, 1200);
    out
}

fn write_resource_dir(out: &mut [u8], offset: usize, entries: u16) {
    write_u16(out, offset + 12, 0);
    write_u16(out, offset + 14, entries);
}

fn write_resource_entry(out: &mut [u8], offset: usize, id: u32, target: u32) {
    write_u32(out, offset, id);
    write_u32(out, offset + 4, target);
}

pub fn build_version_resource(
    strings: &[(String, String)],
    version: (u16, u16, u16, u16),
) -> Vec<u8> {
    let mut fixed = vec![0u8; 52];
    fixed[0..4].copy_from_slice(&0xFEEF_04BDu32.to_le_bytes());
    fixed[4..8].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    fixed[8..12].copy_from_slice(&((version.0 as u32) << 16 | version.1 as u32).to_le_bytes());
    fixed[12..16].copy_from_slice(&((version.2 as u32) << 16 | version.3 as u32).to_le_bytes());
    fixed[16..20].copy_from_slice(&((version.0 as u32) << 16 | version.1 as u32).to_le_bytes());
    fixed[20..24].copy_from_slice(&((version.2 as u32) << 16 | version.3 as u32).to_le_bytes());

    let mut table_children = Vec::new();
    for (key, value) in strings {
        table_children.extend(version_node(key, 1, &wide(value), &[]));
    }
    let table = version_node("040904B0", 1, &[], &table_children);
    let sfi = version_node("StringFileInfo", 1, &[], &table);
    version_node("VS_VERSION_INFO", 0, &fixed, &sfi)
}

fn version_node(key: &str, w_type: u16, value: &[u8], children: &[u8]) -> Vec<u8> {
    let mut body = wide(key);
    while (6 + body.len()) % 4 != 0 {
        body.push(0);
    }
    body.extend_from_slice(value);
    while (6 + body.len()) % 4 != 0 {
        body.push(0);
    }
    body.extend_from_slice(children);
    let mut out = Vec::new();
    out.extend(((6 + body.len()) as u16).to_le_bytes());
    let value_len = if w_type == 1 {
        (value.len() / 2) as u16
    } else {
        value.len() as u16
    };
    out.extend(value_len.to_le_bytes());
    out.extend(w_type.to_le_bytes());
    out.extend(body);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    let total = out.len() as u16;
    out[0..2].copy_from_slice(&total.to_le_bytes());
    out
}

fn wide(s: &str) -> Vec<u8> {
    let mut out: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    out.extend([0, 0]);
    out
}

pub fn build_dotnet_metadata() -> Vec<u8> {
    let strings: &[u8] = b"\0FixtureAssembly\0FixtureModule\0";
    let string_assembly: u16 = 1;
    let string_module: u16 = 17;

    let mut tables = Vec::new();
    tables.extend_from_slice(&0u32.to_le_bytes());

    tables.push(2);

    tables.push(0);

    tables.push(0);

    tables.push(1);

    let valid: u64 = (1 << 0) | (1 << 32);
    tables.extend_from_slice(&valid.to_le_bytes());
    tables.extend_from_slice(&0u64.to_le_bytes());

    tables.extend_from_slice(&1u32.to_le_bytes());

    tables.extend_from_slice(&1u32.to_le_bytes());

    tables.extend_from_slice(&0u16.to_le_bytes());
    tables.extend_from_slice(&string_module.to_le_bytes());
    tables.extend_from_slice(&1u16.to_le_bytes());
    tables.extend_from_slice(&0u16.to_le_bytes());
    tables.extend_from_slice(&0u16.to_le_bytes());

    tables.extend_from_slice(&0x8004u32.to_le_bytes());
    tables.extend_from_slice(&1u16.to_le_bytes());
    tables.extend_from_slice(&0u16.to_le_bytes());
    tables.extend_from_slice(&0u16.to_le_bytes());
    tables.extend_from_slice(&0u16.to_le_bytes());
    tables.extend_from_slice(&0u32.to_le_bytes());
    tables.extend_from_slice(&0u16.to_le_bytes());

    tables.extend_from_slice(&string_assembly.to_le_bytes());
    tables.extend_from_slice(&0u16.to_le_bytes());

    let streams: [(&str, Vec<u8>); 5] = [
        ("#~", tables),
        ("#Strings", strings.to_vec()),
        ("#US", vec![0]),
        ("#GUID", vec![0; 16]),
        ("#Blob", vec![0]),
    ];
    let version = b"v4.0.30319\0";
    let version_padded = align(version.len(), 4);
    let header_size = 16 + version_padded + 2 + 2 + streams.len() * 8;
    let mut name_sizes = Vec::new();
    for (name, _) in &streams {
        name_sizes.push(align(name.len() + 1, 4));
    }
    let stream_headers_size: usize = name_sizes.iter().sum();
    let data_start = header_size + stream_headers_size;
    let mut out = vec![0u8; data_start];
    out[0..4].copy_from_slice(&0x424A_5342u32.to_le_bytes());
    out[4..6].copy_from_slice(&1u16.to_le_bytes());
    out[6..8].copy_from_slice(&1u16.to_le_bytes());
    out[12..16].copy_from_slice(&(version.len() as u32).to_le_bytes());
    out[16..16 + version.len()].copy_from_slice(version);
    let flags_off = 16 + version_padded;
    out[flags_off..flags_off + 2].copy_from_slice(&0u16.to_le_bytes());
    out[flags_off + 2..flags_off + 4].copy_from_slice(&(streams.len() as u16).to_le_bytes());
    let mut header_off = flags_off + 4;
    let mut data_off = data_start;
    for (i, (name, data)) in streams.iter().enumerate() {
        write_u32(&mut out, header_off, data_off as u32);
        write_u32(&mut out, header_off + 4, data.len() as u32);
        let name_bytes = name.as_bytes();
        out[header_off + 8..header_off + 8 + name_bytes.len()].copy_from_slice(name_bytes);
        header_off += 8 + name_sizes[i];
        data_off += data.len();
        out.extend_from_slice(data);
    }
    out
}

fn build_fake_certificate() -> Vec<u8> {
    let mut cert = vec![0u8; 0x40];
    write_u32(&mut cert, 0, 0x40);
    write_u16(&mut cert, 4, 0x0200);
    write_u16(&mut cert, 6, 0x0002);
    let oid = [
        0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x04, 0x01,
    ];
    cert[8..8 + oid.len()].copy_from_slice(&oid);
    cert
}

fn write_rich_header(image: &mut [u8], offset: usize, pe_offset: usize) {
    let key: u32 = 0x5a5a_1234;
    let mut cursor = offset;
    for i in 0..4 {
        let word = if i == 0 {
            u32::from_le_bytes(*b"DanS")
        } else {
            0
        };
        write_u32(image, cursor, word ^ key);
        cursor += 4;
    }
    let entries = [(0x00C9u32 << 16) | 30319, (0x00FFu32 << 16) | 40999];
    for (i, comp) in entries.iter().enumerate() {
        write_u32(image, cursor, comp ^ key);
        write_u32(image, cursor + 4, (i as u32 + 1) ^ key);
        cursor += 8;
    }
    image[cursor..cursor + 4].copy_from_slice(b"Rich");
    write_u32(image, cursor + 4, key);
    let _ = pe_offset;
}

fn write_thunk(out: &mut [u8], offset: usize, value: u64, width: usize) {
    if width == 8 {
        write_u64(out, offset, value);
    } else {
        write_u32(out, offset, value as u32);
    }
}

fn write_u16(out: &mut [u8], offset: usize, value: u16) {
    if offset + 2 <= out.len() {
        out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
}

fn write_u32(out: &mut [u8], offset: usize, value: u32) {
    if offset + 4 <= out.len() {
        out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}

fn write_u64(out: &mut [u8], offset: usize, value: u64) {
    if offset + 8 <= out.len() {
        out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}

fn align(v: usize, to: usize) -> usize {
    if to == 0 {
        return v;
    }
    (v + to - 1) & !(to - 1)
}

fn align_vec(v: &mut Vec<u8>, to: usize) {
    let target = align(v.len(), to);
    v.resize(target, 0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_default;

    #[test]
    fn generated_pe32_parses() {
        let data = PeBuilder::pe32().with_export("FixtureExport").build();
        let pe = parse_default(&data).expect("parse");
        assert_eq!(pe.machine, 0x014c);
        assert_eq!(pe.architecture, "x86");
        assert!(!pe.is_64);
        assert!(
            pe.checksum_valid,
            "checksum generated by the builder must be valid"
        );
        assert_eq!(pe.imports.len(), 1);
        assert_eq!(pe.imports[0].name, "KERNEL32.dll");
        assert!(pe.imports[0]
            .functions
            .iter()
            .any(|f| f.name.as_deref() == Some("ExitProcess")));
        assert_eq!(pe.exports.len(), 1);
        assert_eq!(pe.exports[0].name.as_deref(), Some("FixtureExport"));
        assert!(pe.version_info.is_some());
        assert_eq!(
            pe.version_info.unwrap().company_name.as_deref(),
            Some("BinScope Test")
        );
        assert!(pe.resources.len() >= 2);
    }

    #[test]
    fn generated_pe64_parses() {
        let data = PeBuilder::pe64().dll().with_export("Fn").build();
        let pe = parse_default(&data).expect("parse");
        assert_eq!(pe.machine, 0x8664);
        assert_eq!(pe.architecture, "x86-64");
        assert!(pe.is_64);
        assert!(pe.is_dll);
        assert_eq!(pe.image_base, 0x0000_0001_4000_0000);
    }

    #[test]
    fn generated_clr_directory_is_detected() {
        let data = PeBuilder::pe32().with_clr(0x1 | 0x8).build();
        let pe = parse_default(&data).expect("parse");
        let clr = pe.clr.expect("CLR directory");
        assert_eq!(clr.metadata_version.as_deref(), Some("v4.0.30319"));
        assert!(clr.flag_names.iter().any(|f| f == "ILONLY"));
        assert!(clr.strong_name_signed);
    }

    #[test]
    fn generated_pdb_is_detected() {
        let data = PeBuilder::pe64().with_pdb(r"C:\build\fixture.pdb").build();
        let pe = parse_default(&data).expect("parse");
        let pdb = pe.pdb.expect("pdb");
        assert_eq!(pdb.path, r"C:\build\fixture.pdb");
        assert_eq!(pdb.signature, "RSDS");
    }

    #[test]
    fn generated_rich_header_is_detected() {
        let mut b = PeBuilder::pe32();
        b.rich = true;
        let pe = parse_default(&b.build()).expect("parse");
        let rich = pe.rich_header.expect("rich");
        assert_eq!(rich.product_ids, vec![0x00C9, 0x00FF]);
    }

    #[test]
    fn generated_certificate_is_detected() {
        let mut b = PeBuilder::pe32();
        b.certificate = true;
        let pe = parse_default(&b.build()).expect("parse");
        assert!(pe.certificate.present);
        assert_eq!(pe.certificate.entries.len(), 1);
    }
}
