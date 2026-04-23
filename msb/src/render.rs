use image::{Rgba, RgbaImage};
use scx::{MsbEntry, MsbToken, decode_entry_tokens};

use crate::font::FontAtlas;

pub struct RenderBlock {
    pub width: u32,
    pub height: u32,
    pub rgba: RgbaImage,
    pub line_count: usize,
    pub unsupported_controls: Vec<String>,
}

struct LogicalItem {
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    rgba: RgbaImage,
}

struct LineLayout {
    items: Vec<LogicalItem>,
    forced_height: Option<u32>,
}

pub fn render_entry(entry: &MsbEntry, font: &FontAtlas, canvas_width: u32) -> (Option<RenderBlock>, Option<RenderBlock>, Vec<String>) {
    let (name_tokens, body_tokens) = split_entry_sections(entry);
    let name_block = render_token_stream(&name_tokens, font, canvas_width);
    let body_block = render_token_stream(&body_tokens, font, canvas_width);
    let mut ignored = Vec::new();
    if let Some(ref nb) = name_block {
        ignored.extend(nb.unsupported_controls.iter().cloned());
    }
    if let Some(ref bb) = body_block {
        ignored.extend(bb.unsupported_controls.iter().cloned());
    }
    (name_block, body_block, ignored)
}

pub fn stack_blocks(name_block: Option<&RenderBlock>, body_block: Option<&RenderBlock>) -> RgbaImage {
    let blocks: Vec<&RenderBlock> = [name_block, body_block].into_iter().flatten().collect();
    if blocks.is_empty() {
        return RgbaImage::new(1, 1);
    }

    let width = blocks.iter().map(|b| b.width).max().unwrap();
    let height: u32 = blocks.iter().map(|b| b.height).sum::<u32>() + 16 * (blocks.len() as u32 - 1);
    let mut canvas = RgbaImage::new(width, height);

    let mut y_cursor = 0u32;
    for block in &blocks {
        blend_image(&mut canvas, &block.rgba, 0, y_cursor as i32);
        y_cursor += block.height + 16;
    }

    canvas
}

fn split_entry_sections(entry: &MsbEntry) -> (Vec<MsbToken>, Vec<MsbToken>) {
    let decoded = decode_entry_tokens(entry);
    let mut name_tokens = Vec::new();
    let mut body_tokens = Vec::new();
    let mut in_name_run = false;

    for token in decoded {
        if token.text == "begin_name_run()" {
            in_name_run = true;
            continue;
        }
        if token.text == "end_name_run()" {
            in_name_run = false;
            continue;
        }
        if token.text == "end()" {
            continue;
        }
        if in_name_run {
            name_tokens.push(token);
        } else {
            body_tokens.push(token);
        }
    }

    (name_tokens, body_tokens)
}

fn render_token_stream(tokens: &[MsbToken], font: &FontAtlas, canvas_width: u32) -> Option<RenderBlock> {
    if tokens.is_empty() {
        return None;
    }

    let mut lines: Vec<LineLayout> = Vec::new();
    let mut current_line: Vec<LogicalItem> = Vec::new();
    let mut current_alignment = "left";
    let mut x_cursor: i32 = 0;
    let mut ignored_controls: Vec<String> = Vec::new();

    for token in tokens {
        if let Some(glyph_index) = try_parse_glyph_index(token) {
            if let Some((glyph_img, metric)) = font.get_glyph_rgba(glyph_index) {
                if metric.width > 0 && metric.height > 0 {
                    current_line.push(LogicalItem {
                        x: x_cursor + metric.x_offset as i32,
                        y: metric.y_offset as i32,
                        width: metric.width as u32,
                        height: metric.height as u32,
                        rgba: glyph_img,
                    });
                }
                let advance = if metric.advance_x > 0 { metric.advance_x as i32 } else { metric.width as i32 };
                x_cursor += advance.max(0);
            }
            continue;
        }

        if token.text == "newline()" {
            flush_line(&mut lines, &mut current_line, current_alignment, canvas_width);
            x_cursor = 0;
            continue;
        }

        if token.text == "align_left()" {
            current_alignment = "left";
            continue;
        }
        if token.text == "align_center()" {
            current_alignment = "center";
            continue;
        }
        if token.text == "align_right()" {
            current_alignment = "right";
            continue;
        }

        if let Some(ax) = try_parse_u16_argument(&token.text, "advance_x(width=0x") {
            x_cursor += ax as i32;
            continue;
        }

        if let Some(ay) = try_parse_u16_argument(&token.text, "advance_y(offset=0x") {
            flush_line(&mut lines, &mut current_line, current_alignment, canvas_width);
            if ay > 0 {
                lines.push(LineLayout {
                    items: Vec::new(),
                    forced_height: Some(ay as u32),
                });
            }
            x_cursor = 0;
            continue;
        }

        ignored_controls.push(token.text.clone());
    }

    flush_line(&mut lines, &mut current_line, current_alignment, canvas_width);
    if lines.is_empty() {
        return None;
    }

    let line_heights: Vec<u32> = lines.iter().map(get_line_height).collect();
    let used_width = lines
        .iter()
        .filter(|l| !l.items.is_empty())
        .map(|l| l.items.iter().map(|item| (item.x + item.width as i32).max(0) as u32).max().unwrap_or(0))
        .max()
        .unwrap_or(0);
    let total_height: u32 = line_heights.iter().sum::<u32>() + 16 * (lines.len() as u32 + 1);
    let img_width = canvas_width.max(used_width) + 32;
    let mut rgba = RgbaImage::new(img_width, total_height);

    let mut y_cursor: i32 = 16;
    for (idx, line) in lines.iter().enumerate() {
        if line.items.is_empty() {
            y_cursor += line_heights[idx] as i32 + 16;
            continue;
        }
        let min_y = line.items.iter().map(|item| item.y).min().unwrap_or(0);
        for item in &line.items {
            blend_image(&mut rgba, &item.rgba, item.x + 16, y_cursor + (item.y - min_y));
        }
        y_cursor += line_heights[idx] as i32 + 16;
    }

    let final_width = used_width.max(1) + 32;
    let final_height = (y_cursor as u32).max(1);
    let cropped = crop_image(&rgba, final_width, final_height);

    let line_count = lines.len();
    let unsupported = build_unsupported_control_list(&ignored_controls);

    Some(RenderBlock {
        width: final_width,
        height: final_height,
        rgba: cropped,
        line_count,
        unsupported_controls: unsupported,
    })
}

fn blend_image(dst: &mut RgbaImage, src: &RgbaImage, x: i32, y: i32) {
    for sy in 0..src.height() {
        for sx in 0..src.width() {
            let dx = x + sx as i32;
            let dy = y + sy as i32;
            if dx < 0 || dy < 0 || dx >= dst.width() as i32 || dy >= dst.height() as i32 {
                continue;
            }
            let sp = src.get_pixel(sx, sy);
            let sa = sp[3] as f32 / 255.0;
            if sa <= 0.0 {
                continue;
            }
            let dp = dst.get_pixel(dx as u32, dy as u32);
            let da = dp[3] as f32 / 255.0;
            let out_a = sa + da * (1.0 - sa);
            if out_a <= 0.0 {
                continue;
            }
            let r = ((sp[0] as f32 * sa + dp[0] as f32 * da * (1.0 - sa)) / out_a).clamp(0.0, 255.0) as u8;
            let g = ((sp[1] as f32 * sa + dp[1] as f32 * da * (1.0 - sa)) / out_a).clamp(0.0, 255.0) as u8;
            let b = ((sp[2] as f32 * sa + dp[2] as f32 * da * (1.0 - sa)) / out_a).clamp(0.0, 255.0) as u8;
            let a = (out_a * 255.0).clamp(0.0, 255.0) as u8;
            dst.put_pixel(dx as u32, dy as u32, Rgba([r, g, b, a]));
        }
    }
}

fn flush_line(lines: &mut Vec<LineLayout>, current_line: &mut Vec<LogicalItem>, alignment: &str, canvas_width: u32) {
    if current_line.is_empty() {
        lines.push(LineLayout { items: Vec::new(), forced_height: None });
        return;
    }

    let line_width = current_line.iter().map(|item| (item.x + item.width as i32).max(0) as u32).max().unwrap_or(0);
    let shift_x = match alignment {
        "center" if line_width < canvas_width => ((canvas_width - line_width) / 2) as i32,
        "right" if line_width < canvas_width => (canvas_width - line_width) as i32,
        _ => 0,
    };

    if shift_x != 0 {
        for item in current_line.iter_mut() {
            item.x += shift_x;
        }
    }

    let items = std::mem::take(current_line);
    lines.push(LineLayout { items, forced_height: None });
}

fn get_line_height(line: &LineLayout) -> u32 {
    if let Some(h) = line.forced_height {
        return h.max(1);
    }
    if line.items.is_empty() {
        return 32;
    }
    let min_y = line.items.iter().map(|i| i.y).min().unwrap_or(0);
    let max_y = line.items.iter().map(|i| i.y + i.height as i32).max().unwrap_or(0);
    (max_y - min_y).max(32) as u32
}

fn try_parse_glyph_index(token: &MsbToken) -> Option<usize> {
    if token.kind != "tok" {
        return None;
    }
    let value = ((token.raw >> 24) & 0x7F) << 24 | (token.raw & 0x00FF_FFFF);
    Some(value as usize)
}

fn try_parse_u16_argument(text: &str, prefix: &str) -> Option<u16> {
    if !text.to_ascii_lowercase().starts_with(&prefix.to_ascii_lowercase()) || !text.ends_with(')') {
        return None;
    }
    let raw = &text[prefix.len()..text.len() - 1];
    u16::from_str_radix(raw, 16).ok()
}

fn build_unsupported_control_list(ignored: &[String]) -> Vec<String> {
    let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for ctrl in ignored {
        *counts.entry(ctrl.as_str()).or_insert(0) += 1;
    }
    counts.into_iter().map(|(k, v)| format!("{k} x{v}")).collect()
}

fn crop_image(img: &RgbaImage, width: u32, height: u32) -> RgbaImage {
    let w = width.min(img.width());
    let h = height.min(img.height());
    let mut cropped = RgbaImage::new(w, h);
    for y in 0..h {
        for x in 0..w {
            cropped.put_pixel(x, y, *img.get_pixel(x, y));
        }
    }
    cropped
}
