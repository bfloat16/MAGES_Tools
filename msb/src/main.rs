mod font;
mod render;

use anyhow::{Result, bail};
use std::path::{Path, PathBuf};

const CANVAS_WIDTH: u32 = 1920;

fn main() -> Result<()> {
    let opts = parse_args()?;
    run(&opts)
}

struct Options {
    inputs: Vec<String>,
    output_dir: PathBuf,
    system_dir: PathBuf,
}

fn parse_args() -> Result<Options> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut opts = Options {
        inputs: Vec::new(),
        output_dir: PathBuf::from(r"F:\SteamLibrary\steamapps\common\MemoriesOff9\data\mes_text_render"),
        system_dir: PathBuf::from(r"F:\SteamLibrary\steamapps\common\MemoriesOff9\data\system_win"),
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--input" => {
                i += 1;
                opts.inputs.push(args[i].clone());
            }
            "--output" => {
                i += 1;
                opts.output_dir = PathBuf::from(&args[i]);
            }
            "--system-dir" => {
                i += 1;
                opts.system_dir = PathBuf::from(&args[i]);
            }
            "-h" | "--help" => {
                eprintln!("Render MemoOff9 .msb text by cutting glyphs from the game font atlas");
                eprintln!("  --input <path>             .msb file or folder containing .msb files (repeatable)");
                eprintln!("  --output <dir>             Output root folder for rendered message images");
                eprintln!("  --system-dir <dir>         Path to system_win folder (contains font1.png, font1bin.bin)");
                std::process::exit(0);
            }
            other => {
                bail!("Unknown argument: {other}");
            }
        }
        i += 1;
    }
    if opts.inputs.is_empty() {
        bail!("--input is required.");
    }
    Ok(opts)
}

fn run(opts: &Options) -> Result<()> {
    let font_png_path = opts.system_dir.join("font1.png");
    let font_bin_path = opts.system_dir.join("font1bin.bin");

    if !font_png_path.is_file() {
        bail!("Font atlas not found: {}", font_png_path.display());
    }
    if !font_bin_path.is_file() {
        bail!("Font metrics not found: {}", font_bin_path.display());
    }

    let inputs = collect_inputs(&opts.inputs)?;
    std::fs::create_dir_all(&opts.output_dir)?;
    let font_atlas = font::FontAtlas::load(&font_png_path, &font_bin_path)?;

    for (index, input) in inputs.iter().enumerate() {
        let summary = render_one_file(input, &opts.output_dir, &font_atlas)?;
        let fname = input.file_name().unwrap_or_default().to_string_lossy();
        println!("[{:04}/{:04}] OK   {} -> {}", index + 1, inputs.len(), fname, summary.output_dir);
    }
    Ok(())
}

fn collect_inputs(inputs: &[String]) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for input in inputs {
        let path = Path::new(input);
        if path.is_dir() {
            let mut dir_files: Vec<PathBuf> = std::fs::read_dir(path)?
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|e| e.to_str()).map(|e| e.eq_ignore_ascii_case("msb")).unwrap_or(false))
                .collect();
            dir_files.sort_by(|a, b| a.to_string_lossy().to_ascii_lowercase().cmp(&b.to_string_lossy().to_ascii_lowercase()));
            files.extend(dir_files);
        } else if path.is_file() {
            files.push(path.to_path_buf());
        } else {
            bail!("Input not found: {input}");
        }
    }
    if files.is_empty() {
        bail!("No .msb files found in: {}", inputs.join(", "));
    }
    files.dedup();
    Ok(files)
}

#[allow(dead_code)]
struct FileRenderSummary {
    output_dir: String,
    results: Vec<MessageRenderResult>,
}

#[allow(dead_code)]
struct MessageRenderResult {
    msg_id: u32,
    output_path: String,
    name_line_count: usize,
    body_line_count: usize,
    ignored_controls: Vec<String>,
}

fn render_one_file(input_path: &Path, output_root: &Path, font_atlas: &font::FontAtlas) -> Result<FileRenderSummary> {
    let msb = scx::parse_msb(input_path)?;
    let stem = input_path.file_stem().unwrap_or_default().to_string_lossy();
    let output_dir = output_root.join(format!("{}__{stem}", msb.source_set));
    std::fs::create_dir_all(&output_dir)?;

    let mut results = Vec::new();
    for entry in &msb.entries {
        let (name_block, body_block, ignored) = render::render_entry(entry, font_atlas, CANVAS_WIDTH);
        let stacked = render::stack_blocks(name_block.as_ref(), body_block.as_ref());
        let output_path = output_dir.join(format!("msg_{:08X}.png", entry.msg_id));
        stacked.save(&output_path)?;

        results.push(MessageRenderResult {
            msg_id: entry.msg_id,
            output_path: output_path.to_string_lossy().into_owned(),
            name_line_count: name_block.as_ref().map(|b| b.line_count).unwrap_or(0),
            body_line_count: body_block.as_ref().map(|b| b.line_count).unwrap_or(0),
            ignored_controls: ignored,
        });
    }

    // write index
    write_index(&output_dir, input_path, &results)?;

    Ok(FileRenderSummary {
        output_dir: output_dir.to_string_lossy().into_owned(),
        results,
    })
}

fn write_index(output_dir: &Path, source_path: &Path, results: &[MessageRenderResult]) -> Result<()> {
    let mut lines = vec![
        format!("; source={}", source_path.display()),
        format!("; output_dir={}", output_dir.display()),
        format!("; entry_count={}", results.len()),
        "; format=msg_id | png | name_lines | body_lines | ignored_controls".into(),
        String::new(),
    ];

    for r in results {
        let ignored = if r.ignored_controls.is_empty() { "-".into() } else { r.ignored_controls.join(", ") };
        let png_name = Path::new(&r.output_path).file_name().unwrap_or_default().to_string_lossy();
        lines.push(format!("msg_{:08X} | {} | name_lines={} | body_lines={} | ignored={}", r.msg_id, png_name, r.name_line_count, r.body_line_count, ignored));
    }

    std::fs::write(output_dir.join("_index.txt"), lines.join("\n"))?;
    Ok(())
}
