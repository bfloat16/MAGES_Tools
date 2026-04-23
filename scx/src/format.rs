use std::fmt::Write;

// ── binary helpers ──

pub fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

pub fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

pub fn read_u16_be(data: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([data[offset], data[offset + 1]])
}

pub fn read_u32_be(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

pub fn sign_extend(value: i32, bits: u32) -> i32 {
    let unsigned = value as u32 as i64;
    let sign_bit = 1i64 << (bits - 1);
    ((unsigned ^ sign_bit) - sign_bit) as i32
}

// ── formatting ──

pub fn fmt_u8(value: u8) -> String {
    format!("0x{value:02X}")
}

pub fn fmt_u16(value: u16) -> String {
    format!("0x{:04X}", value)
}

pub fn fmt_u32(value: u32) -> String {
    format!("0x{value:08X}")
}

pub fn fmt_l0(index: u16) -> String {
    format!("table0[{}]", fmt_u16(index))
}

pub fn fmt_l2(index: u16) -> String {
    format!("table2[{}]", fmt_u16(index))
}

pub fn hex8(value: u8) -> String {
    format!("0x{value:02X}")
}

pub fn read_cstring(data: &[u8], offset: usize, limit: usize) -> (String, usize) {
    let max = data.len().min(limit);
    let mut end = offset;
    while end < max && data[end] != 0 {
        end += 1;
    }
    let text = String::from_utf8_lossy(&data[offset..end]).into_owned();
    let next = if end < max { end + 1 } else { end };
    (text, next)
}

pub fn decode_u16(data: &[u8], offset: usize, limit: usize) -> (Option<u16>, usize) {
    if offset + 2 > limit.min(data.len()) {
        return (None, offset);
    }
    (Some(read_u16_le(data, offset)), offset + 2)
}

// ── hex dump ──

pub fn preview_bytes(data: &[u8]) -> String {
    let span = if data.len() <= 0x10 { data } else { &data[..0x10] };
    let mut out = String::new();
    for (i, b) in span.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let _ = write!(out, "{b:02x}");
    }
    if data.len() > 0x10 {
        out.push_str(" ...");
    }
    out
}

pub fn format_hex(data: &[u8]) -> String {
    let mut out = String::new();
    for (i, b) in data.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let _ = write!(out, "{b:02x}");
    }
    out
}
