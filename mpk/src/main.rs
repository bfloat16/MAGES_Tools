use anyhow::{Result, bail};
use serde::Serialize;
use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        eprintln!("Usage: mpk <input.mpk> <output_dir>");
        std::process::exit(1);
    }

    let input_path = std::fs::canonicalize(&args[0]).unwrap_or_else(|_| PathBuf::from(&args[0]));
    let output_dir = PathBuf::from(&args[1]);

    if !input_path.is_file() {
        bail!("Input file not found: {}", input_path.display());
    }
    if input_path.extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase()).as_deref() != Some("mpk") {
        bail!("Input must be a .mpk file: {}", input_path.display());
    }

    std::fs::create_dir_all(&output_dir)?;

    let mut file = std::fs::File::open(&input_path)?;
    let file_len = file.metadata()?.len();

    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;
    if &magic != b"MPK\0" {
        bail!("Unexpected MPK magic: {:?}", std::str::from_utf8(&magic).unwrap_or("???"));
    }

    let version = read_u32(&mut file)?;
    let entry_count = read_u32(&mut file)?;
    let reserved = read_u32(&mut file)?;

    const HEADER_SIZE: u64 = 0x40;
    const ENTRY_SIZE: u64 = 0x100;

    let mut entries = Vec::new();
    let mut used_paths: HashSet<String> = HashSet::new();

    for index in 0..entry_count {
        let entry_pos = HEADER_SIZE + index as u64 * ENTRY_SIZE;
        file.seek(SeekFrom::Start(entry_pos))?;

        let flags = read_u32(&mut file)?;
        let id = read_u32(&mut file)?;
        let offset = read_u64(&mut file)?;
        let size = read_u64(&mut file)?;
        let unpacked_size = read_u64(&mut file)?;
        let name = read_fixed_ascii(&mut file, 0x20)?;

        let is_empty = name.trim().is_empty() && offset == 0 && size == 0 && unpacked_size == 0;
        if is_empty {
            continue;
        }

        if offset > file_len || size > file_len || offset + size > file_len {
            bail!("Entry {index} points outside archive: offset=0x{offset:X}, size=0x{size:X}, archiveSize=0x{file_len:X}");
        }

        let relative_path = normalize_relative_path(&name, index as usize);
        let output_path = make_unique_output_path(&output_dir, &relative_path, &mut used_paths, index as usize);

        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        extract_entry(&mut file, &output_path, offset, size)?;

        let rel = pathdiff(&output_dir, &output_path);
        entries.push(MpkEntryMetadata {
            index: index as usize,
            flags,
            id,
            offset,
            size,
            unpacked_size,
            name: name.clone(),
            output_path: rel,
        });
    }

    let metadata = ArchiveMetadata {
        archive_path: input_path.to_string_lossy().into_owned(),
        archive_name: input_path.file_name().unwrap_or_default().to_string_lossy().into_owned(),
        version,
        reserved,
        header_entry_count: entry_count,
        extracted_entry_count: entries.len(),
        entries,
    };

    let metadata_path = output_dir.join("metadata.json");
    let json = serde_json::to_string_pretty(&metadata)?;
    std::fs::write(&metadata_path, json)?;

    println!("Extracted {} entries to {}", metadata.extracted_entry_count, output_dir.display());
    println!("Metadata written to {}", metadata_path.display());
    Ok(())
}

fn read_u32(f: &mut std::fs::File) -> Result<u32> {
    let mut buf = [0u8; 4];
    f.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64(f: &mut std::fs::File) -> Result<u64> {
    let mut buf = [0u8; 8];
    f.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

fn read_fixed_ascii(f: &mut std::fs::File, length: usize) -> Result<String> {
    let mut buf = vec![0u8; length];
    f.read_exact(&mut buf)?;
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Ok(String::from_utf8_lossy(&buf[..end]).into_owned())
}

fn normalize_relative_path(name: &str, index: usize) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return format!("entry_{index:06}.bin");
    }
    let normalized: String = trimmed.replace('\\', "/");
    let parts: Vec<&str> = normalized.split('/').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return format!("entry_{index:06}.bin");
    }
    let sanitized: Vec<String> = parts.iter().map(|p| sanitize_path_segment(p, &format!("entry_{index:06}"))).collect();
    sanitized.join("/")
}

fn sanitize_path_segment(segment: &str, fallback: &str) -> String {
    let invalid = ['<', '>', ':', '"', '|', '?', '*', '\0'];
    let result: String = segment.chars().map(|c| if invalid.contains(&c) || c.is_control() { '_' } else { c }).collect();
    let result = result.trim().to_string();
    if result.is_empty() { fallback.to_string() } else { result }
}

fn make_unique_output_path(output_dir: &Path, relative: &str, used: &mut HashSet<String>, index: usize) -> PathBuf {
    let candidate = output_dir.join(relative);
    let key = candidate.to_string_lossy().to_ascii_lowercase();
    if used.insert(key) {
        return candidate;
    }
    let stem = candidate.file_stem().unwrap_or_default().to_string_lossy();
    let ext = candidate.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
    let dir = candidate.parent().unwrap_or(output_dir);
    let unique = dir.join(format!("{stem}__dup_{index:06}{ext}"));
    used.insert(unique.to_string_lossy().to_ascii_lowercase());
    unique
}

fn extract_entry(file: &mut std::fs::File, output_path: &Path, offset: u64, size: u64) -> Result<()> {
    const BUF_SIZE: usize = 1024 * 1024;
    let mut buf = vec![0u8; BUF_SIZE];
    let mut output = std::fs::File::create(output_path)?;
    file.seek(SeekFrom::Start(offset))?;

    let mut remaining = size;
    while remaining > 0 {
        let to_read = (remaining as usize).min(buf.len());
        let read = file.read(&mut buf[..to_read])?;
        if read == 0 {
            bail!("Unexpected end of archive while extracting {}", output_path.display());
        }
        output.write_all(&buf[..read])?;
        remaining -= read as u64;
    }
    Ok(())
}

fn pathdiff(base: &Path, target: &Path) -> String {
    target.strip_prefix(base).map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| target.to_string_lossy().into_owned())
}

#[derive(Serialize)]
struct MpkEntryMetadata {
    index: usize,
    flags: u32,
    id: u32,
    offset: u64,
    size: u64,
    unpacked_size: u64,
    name: String,
    output_path: String,
}

#[derive(Serialize)]
struct ArchiveMetadata {
    archive_path: String,
    archive_name: String,
    version: u32,
    reserved: u32,
    header_entry_count: u32,
    extracted_entry_count: usize,
    entries: Vec<MpkEntryMetadata>,
}
