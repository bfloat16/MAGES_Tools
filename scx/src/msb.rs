use anyhow::{Result, bail};
use std::collections::BTreeMap;
use std::path::Path;

use crate::format::*;
use crate::il::*;

// ── MsbFile ──

pub struct MsbFile {
    pub path: String,
    pub source_set: String,
    pub data: Vec<u8>,
    pub version: u32,
    pub count_field: u32,
    pub data_offset: u32,
    pub entries: Vec<MsbEntry>,
    pub raw_tail: Vec<u8>,
}

impl MsbFile {
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

pub struct MsbEntry {
    pub msg_id: u32,
    pub rel_start: u32,
    pub rel_end: u32,
    pub abs_start: usize,
    pub abs_end: usize,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct MsbToken {
    pub offset: usize,
    pub end: usize,
    pub kind: String,
    pub raw: u32,
    pub text: String,
}

// ── parsing ──

pub fn parse_msb(path: &Path) -> Result<MsbFile> {
    let data = std::fs::read(path)?;
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    if data.len() < 0x10 || &data[..4] != b"MES\0" {
        bail!("{name}: not a valid MES file");
    }

    let version = read_u32_le(&data, 4);
    let count_field = read_u32_le(&data, 8);
    let data_offset = read_u32_le(&data, 0x0C);
    if version != 1 {
        bail!("{name}: unsupported version {version}");
    }

    let expected = 0x10u32 + count_field * 8;
    if data_offset != expected {
        bail!("{name}: invalid data_offset=0x{data_offset:X}, expected 0x{expected:X}");
    }
    if data_offset as usize > data.len() {
        bail!("{name}: data_offset beyond EOF");
    }

    let entry_count = count_field as usize;
    let mut table = Vec::with_capacity(entry_count);
    let mut prev_rel_start = 0u32;
    for i in 0..entry_count {
        let item_offset = 0x10 + i * 8;
        let msg_id = read_u32_le(&data, item_offset);
        let rel_start = read_u32_le(&data, item_offset + 4);
        if i == 0 && rel_start != 0 {
            bail!("{name}: first rel_start must be 0, got 0x{rel_start:X}");
        }
        if rel_start < prev_rel_start {
            bail!("{name}: non-monotonic rel_start for msg_id={msg_id} 0x{rel_start:X} < 0x{prev_rel_start:X}");
        }
        table.push((msg_id, rel_start));
        prev_rel_start = rel_start;
    }

    let file_rel_end = (data.len() - data_offset as usize) as u32;
    let mut entries = Vec::with_capacity(entry_count);
    for i in 0..table.len() {
        let (msg_id, rel_start) = table[i];
        let rel_end = if i + 1 < table.len() { table[i + 1].1 } else { file_rel_end };
        if rel_end < rel_start {
            bail!("{name}: invalid range for msg_id={msg_id} 0x{rel_start:X}..0x{rel_end:X}");
        }
        let abs_start = (data_offset + rel_start) as usize;
        let abs_end = (data_offset + rel_end) as usize;
        if abs_end > data.len() {
            bail!("{name}: msg_id={msg_id} range exceeds EOF");
        }
        entries.push(MsbEntry {
            msg_id,
            rel_start,
            rel_end,
            abs_start,
            abs_end,
            data: data[abs_start..abs_end].to_vec(),
        });
    }

    let raw_tail = if !entries.is_empty() {
        let last_end = (data_offset + entries.last().unwrap().rel_end) as usize;
        data[last_end..].to_vec()
    } else {
        data[data_offset as usize..].to_vec()
    };

    let source_set = path.parent().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();

    Ok(MsbFile {
        path: path.to_string_lossy().into_owned(),
        source_set,
        data,
        version,
        count_field,
        data_offset,
        entries,
        raw_tail,
    })
}

// ── MSB token decoding ──

pub fn decode_msb_token(data: &[u8], position: usize, base_offset: usize) -> MsbToken {
    if position >= data.len() {
        return MsbToken {
            offset: base_offset + position,
            end: base_offset + position,
            kind: "unterminated".into(),
            raw: 0,
            text: "unterminated()".into(),
        };
    }

    let b0 = data[position];
    if b0 == 0xFF {
        return MsbToken {
            offset: base_offset + position,
            end: base_offset + position + 1,
            kind: "end".into(),
            raw: b0 as u32,
            text: "end()".into(),
        };
    }

    if (b0 & 0x80) != 0 {
        return decode_packed_token(data, position, base_offset);
    }

    decode_control_token(data, position, base_offset)
}

fn decode_packed_token(data: &[u8], position: usize, base_offset: usize) -> MsbToken {
    if position + 4 > data.len() {
        let raw = read_remaining_be(data, position);
        let text = format!("trunc_tok(prefix={}, raw=0x{raw:X})", fmt_u8(data[position]));
        return MsbToken {
            offset: base_offset + position,
            end: base_offset + data.len(),
            kind: "trunc_tok".into(),
            raw,
            text,
        };
    }

    let packed_raw = read_u32_be(data, position);
    let value = ((packed_raw >> 24) & 0x7F) << 24 | (packed_raw & 0x00FF_FFFF);
    let text = format!("tok(prefix={}, value={})", fmt_u8(data[position]), fmt_u32(value));
    MsbToken {
        offset: base_offset + position,
        end: base_offset + position + 4,
        kind: "tok".into(),
        raw: packed_raw,
        text,
    }
}

fn decode_control_token(data: &[u8], position: usize, base_offset: usize) -> MsbToken {
    let b0 = data[position];
    let offset = base_offset + position;

    match b0 {
        0x00 => MsbToken {
            offset,
            end: offset + 1,
            kind: "ctrl".into(),
            raw: b0 as u32,
            text: "newline()".into(),
        },
        0x01 => MsbToken {
            offset,
            end: offset + 1,
            kind: "ctrl".into(),
            raw: b0 as u32,
            text: "begin_name_run()".into(),
        },
        0x02 => MsbToken {
            offset,
            end: offset + 1,
            kind: "ctrl".into(),
            raw: b0 as u32,
            text: "end_name_run()".into(),
        },
        0x03 => MsbToken {
            offset,
            end: offset + 1,
            kind: "ctrl".into(),
            raw: b0 as u32,
            text: "slot_runtime_mode_1()".into(),
        },
        0x04 => decode_inline_expr_control(data, position, base_offset, "set_text_color_expr"),
        0x05 => MsbToken {
            offset,
            end: offset + 1,
            kind: "ctrl".into(),
            raw: b0 as u32,
            text: "slot_runtime_mode_0()".into(),
        },
        0x07 => decode_u8_arg_control(data, position, base_offset, "ctrl_07", "value"),
        0x08 => MsbToken {
            offset,
            end: offset + 1,
            kind: "ctrl".into(),
            raw: b0 as u32,
            text: "slot_runtime_mode_2()".into(),
        },
        0x09 => MsbToken {
            offset,
            end: offset + 1,
            kind: "ctrl".into(),
            raw: b0 as u32,
            text: "name_run_offset_marker()".into(),
        },
        0x0A => MsbToken {
            offset,
            end: offset + 1,
            kind: "ctrl".into(),
            raw: b0 as u32,
            text: "begin_side_run()".into(),
        },
        0x0B => MsbToken {
            offset,
            end: offset + 1,
            kind: "ctrl".into(),
            raw: b0 as u32,
            text: "end_side_run()".into(),
        },
        0x0C => decode_u16_arg_control(data, position, base_offset, "set_glyph_height_scale", "scale"),
        0x0E => MsbToken {
            offset,
            end: offset + 1,
            kind: "ctrl".into(),
            raw: b0 as u32,
            text: "spacing_segment_break()".into(),
        },
        0x0F => MsbToken {
            offset,
            end: offset + 1,
            kind: "ctrl".into(),
            raw: b0 as u32,
            text: "align_center()".into(),
        },
        0x10 => MsbToken {
            offset,
            end: offset + 1,
            kind: "ctrl".into(),
            raw: b0 as u32,
            text: "align_left()".into(),
        },
        0x11 => decode_u16_arg_control(data, position, base_offset, "advance_y", "offset"),
        0x12 => decode_u16_arg_control(data, position, base_offset, "advance_x", "width"),
        0x13 => decode_u16_arg_control(data, position, base_offset, "emit_var_decimal_charset0", "var"),
        0x14 => decode_u16_arg_control(data, position, base_offset, "emit_var_decimal_charset1", "var"),
        0x15 => decode_inline_expr_control(data, position, base_offset, "queue_inline_expr"),
        0x16 => decode_u16_arg_control(data, position, base_offset, "ctrl_16", "value"),
        0x18 => MsbToken {
            offset,
            end: offset + 1,
            kind: "ctrl".into(),
            raw: b0 as u32,
            text: "slot_runtime_mode_3()".into(),
        },
        0x19 => decode_u16_arg_control(data, position, base_offset, "slot_runtime_mode_4", "value"),
        0x1A => decode_u16_arg_control(data, position, base_offset, "slot_runtime_mode_5", "value"),
        0x1B => decode_u8_arg_control(data, position, base_offset, "select_style_set", "index"),
        0x1E => MsbToken {
            offset,
            end: offset + 1,
            kind: "ctrl".into(),
            raw: b0 as u32,
            text: "side_run_use_base_centers()".into(),
        },
        0x20..=0x29 => MsbToken {
            offset,
            end: offset + 1,
            kind: "ctrl".into(),
            raw: b0 as u32,
            text: format!("select_special_slot({})", b0 - 0x20),
        },
        0x31 => MsbToken {
            offset,
            end: offset + 1,
            kind: "ctrl".into(),
            raw: b0 as u32,
            text: "align_right()".into(),
        },
        0x51..=0x57 => MsbToken {
            offset,
            end: offset + 1,
            kind: "ctrl".into(),
            raw: b0 as u32,
            text: format!("emit_special_slot_glyph({})", b0 - 0x50),
        },
        _ => {
            let name = resolve_control_name(b0);
            MsbToken {
                offset,
                end: offset + 1,
                kind: "ctrl".into(),
                raw: b0 as u32,
                text: format!("{name}()"),
            }
        }
    }
}

fn decode_u8_arg_control(data: &[u8], position: usize, base_offset: usize, name: &str, arg_name: &str) -> MsbToken {
    if position + 2 > data.len() {
        return decode_trunc_control(data, position, base_offset, name);
    }
    let offset = base_offset + position;
    let value = data[position + 1];
    let raw = ((data[position] as u32) << 8) | value as u32;
    MsbToken {
        offset,
        end: offset + 2,
        kind: "ctrl".into(),
        raw,
        text: format!("{name}({arg_name}={})", fmt_u8(value)),
    }
}

fn decode_u16_arg_control(data: &[u8], position: usize, base_offset: usize, name: &str, arg_name: &str) -> MsbToken {
    if position + 3 > data.len() {
        return decode_trunc_control(data, position, base_offset, name);
    }
    let offset = base_offset + position;
    let value = read_u16_be(data, position + 1);
    let raw = ((data[position] as u32) << 16) | value as u32;
    MsbToken {
        offset,
        end: offset + 3,
        kind: "ctrl".into(),
        raw,
        text: format!("{name}({arg_name}={})", fmt_u16(value)),
    }
}

fn decode_inline_expr_control(data: &[u8], position: usize, base_offset: usize, name: &str) -> MsbToken {
    let cursor = scan_inline_expr_end(data, position + 1);
    if cursor >= data.len() {
        return decode_trunc_control(data, position, base_offset, name);
    }
    let payload = &data[position + 1..cursor];
    let preview = preview_bytes(payload);
    let offset = base_offset + position;
    MsbToken {
        offset,
        end: base_offset + cursor + 1,
        kind: "ctrl".into(),
        raw: data[position] as u32,
        text: format!("{name}(size={}, raw={preview})", fmt_u16(payload.len() as u16)),
    }
}

fn decode_trunc_control(data: &[u8], position: usize, base_offset: usize, name: &str) -> MsbToken {
    let raw = read_remaining_be(data, position);
    MsbToken {
        offset: base_offset + position,
        end: base_offset + data.len(),
        kind: "trunc_ctrl".into(),
        raw,
        text: format!("trunc_ctrl(name={name}, raw=0x{raw:X})"),
    }
}

fn scan_inline_expr_end(data: &[u8], position: usize) -> usize {
    let mut cursor = position;
    while cursor < data.len() && data[cursor] != 0 {
        let b0 = data[cursor];
        if (b0 & 0x80) == 0 {
            cursor += 2;
            continue;
        }
        cursor += match b0 & 0x60 {
            0x00 => 2,
            0x20 => 3,
            0x40 => 4,
            _ => 6,
        };
    }
    cursor
}

fn read_remaining_be(data: &[u8], position: usize) -> u32 {
    let mut raw = 0u32;
    for &b in &data[position..] {
        raw = (raw << 8) | b as u32;
    }
    raw
}

fn resolve_control_name(value: u8) -> String {
    match value {
        0x24 => "ctrl_24".into(),
        0x27 => "ctrl_27".into(),
        0x2B => "ctrl_2B".into(),
        0x2E => "ctrl_2E".into(),
        0x4E => "ctrl_4E".into(),
        0x56 => "ctrl_56".into(),
        0x68 => "ctrl_68".into(),
        0x6D => "ctrl_6D".into(),
        0x7A => "ctrl_7A".into(),
        _ => format!("ctrl_{value:02X}"),
    }
}

// ── MSB disassembler ──

pub fn build_msb_document(msb: &MsbFile) -> IlDocument {
    let mut instructions = BTreeMap::new();
    for entry in &msb.entries {
        let mut inst = IlInstruction::new(entry.abs_start, entry.abs_end, format!("msg_{:04X}", entry.msg_id));
        let mut position = 0;
        let mut terminated = false;
        while position < entry.data.len() {
            let token = decode_msb_token(&entry.data, position, entry.abs_start);
            inst.operands.push(IlOperand {
                name: None,
                value: IlValue::Text(token.text.clone()),
            });
            position = (token.end - entry.abs_start).max(position + 1);
            if matches!(token.kind.as_str(), "end" | "trunc_tok" | "trunc_ctrl") {
                terminated = token.kind == "end";
                break;
            }
        }
        if !terminated {
            inst.operands.push(IlOperand {
                name: None,
                value: IlValue::Text("unterminated()".into()),
            });
        }
        inst.comments.push(format!("id={}", entry.msg_id));
        inst.comments.push(format!("rel=[0x{:04X},0x{:04X})", entry.rel_start, entry.rel_end));
        inst.comments.push(format!("len=0x{:X}", entry.data.len()));
        instructions.insert(entry.abs_start, inst);
    }

    IlDocument {
        kind: IlDocumentKind::Msb,
        source_path: msb.path.clone(),
        size: msb.data.len(),
        off_table1: 0,
        off_table2: 0,
        code_start: msb.data_offset as usize,
        code_end: msb.data.len(),
        sweep_start: msb.data_offset as usize,
        msb_source_set: Some(msb.source_set.clone()),
        msb_raw_tail: Some(msb.raw_tail.clone()),
        instructions,
    }
}

pub fn decode_entry_tokens(entry: &MsbEntry) -> Vec<MsbToken> {
    let mut tokens = Vec::new();
    let mut position = 0;
    let mut terminated = false;
    while position < entry.data.len() {
        let token = decode_msb_token(&entry.data, position, entry.abs_start);
        position = (token.end - entry.abs_start).max(position + 1);
        let is_end = matches!(token.kind.as_str(), "end" | "trunc_tok" | "trunc_ctrl");
        terminated = token.kind == "end";
        tokens.push(token);
        if is_end {
            break;
        }
    }
    if !terminated {
        tokens.push(MsbToken {
            offset: entry.abs_end,
            end: entry.abs_end,
            kind: "unterminated".into(),
            raw: 0,
            text: "unterminated()".into(),
        });
    }
    tokens
}
