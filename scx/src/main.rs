use anyhow::{Result, bail};
use std::path::{Path, PathBuf};

fn main() -> Result<()> {
    let opts = parse_args()?;
    export_all(&opts)
}

struct Options {
    input_dir: PathBuf,
    output_dir: PathBuf,
    pattern: String,
}

fn parse_args() -> Result<Options> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut opts = Options {
        input_dir: PathBuf::from(r"F:\SteamLibrary\steamapps\common\MemoriesOff9\data\script"),
        output_dir: PathBuf::from(r"F:\SteamLibrary\steamapps\common\MemoriesOff9\data\script_disasm"),
        pattern: "*.*".into(),
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--input" => {
                i += 1;
                opts.input_dir = PathBuf::from(&args[i]);
            }
            "--output" => {
                i += 1;
                opts.output_dir = PathBuf::from(&args[i]);
            }
            "--pattern" => {
                i += 1;
                opts.pattern = args[i].clone();
            }
            "-h" | "--help" => {
                eprintln!("SC3/.scx and MES/.msb disassembler for MemoOff9 Steam");
                eprintln!("  --input <dir>              Input folder containing .scx or .msb files");
                eprintln!("  --output <dir>             Output folder for .txt disassembly files");
                eprintln!("  --pattern <glob>           Glob pattern inside input folder (default: *.*)");
                std::process::exit(0);
            }
            other => bail!("Unknown argument: {other}"),
        }
        i += 1;
    }
    Ok(opts)
}

fn is_supported(path: &Path) -> bool {
    matches!(path.extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase()).as_deref(), Some("scx") | Some("msb"))
}

fn export_all(opts: &Options) -> Result<()> {
    if !opts.input_dir.is_dir() {
        bail!("Input dir not found: {}", opts.input_dir.display());
    }
    std::fs::create_dir_all(&opts.output_dir)?;

    let mut files: Vec<PathBuf> = std::fs::read_dir(&opts.input_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| is_supported(p) && matches_pattern(p, &opts.pattern))
        .collect();
    files.sort_by(|a, b| a.to_string_lossy().to_ascii_lowercase().cmp(&b.to_string_lossy().to_ascii_lowercase()));

    if files.is_empty() {
        bail!("No supported .scx/.msb files matching {} in {}", opts.pattern, opts.input_dir.display());
    }

    for (index, file) in files.iter().enumerate() {
        match build_document(file) {
            Ok(doc) => {
                let out_name = file.file_stem().unwrap_or_default().to_string_lossy();
                let out_path = opts.output_dir.join(format!("{out_name}.txt"));
                let lines = scx::render_document(&doc);
                std::fs::write(&out_path, lines.join("\n"))?;
                let fname = file.file_name().unwrap_or_default().to_string_lossy();
                let oname = out_path.file_name().unwrap_or_default().to_string_lossy();
                println!("[{:04}/{:04}] OK   {} -> {}", index + 1, files.len(), fname, oname);
            }
            Err(e) => {
                let fname = file.file_name().unwrap_or_default().to_string_lossy();
                println!("[{:04}/{:04}] FAIL {}: {}", index + 1, files.len(), fname, e);
            }
        }
    }
    Ok(())
}

fn build_document(path: &Path) -> Result<scx::IlDocument> {
    let ext = path.extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "scx" => {
            let scx_file = scx::parse_scx(path)?;
            Ok(scx::build_scx_document(&scx_file))
        }
        "msb" => {
            let msb_file = scx::parse_msb(path)?;
            Ok(scx::build_msb_document(&msb_file))
        }
        _ => bail!("Unsupported input file: {}", path.display()),
    }
}

fn matches_pattern(path: &Path, pattern: &str) -> bool {
    if pattern == "*.*" || pattern == "*" {
        return true;
    }
    let fname = path.file_name().unwrap_or_default().to_string_lossy().to_ascii_lowercase();
    let pat = pattern.to_ascii_lowercase();
    if let Some(ext) = pat.strip_prefix("*.") { fname.ends_with(&format!(".{ext}")) } else { true }
}
