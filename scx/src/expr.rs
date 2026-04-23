use crate::format::*;

// ── expression tokens ──

#[derive(Clone, Debug)]
pub enum ExprToken {
    Immediate(i32),
    Operator { opcode: u8, precedence: Option<u8>, name: Option<&'static str> },
    Marker(String),
}

#[derive(Clone, Debug, Default)]
pub struct ExprValue {
    pub tokens: Vec<ExprToken>,
}

impl ExprValue {
    pub fn has_unknown_tokens(&self) -> bool {
        self.tokens.iter().any(|t| matches!(t, ExprToken::Operator { name: None, .. }))
    }

    pub fn has_value_source(&self) -> bool {
        if self.tokens.is_empty() {
            return true;
        }
        self.tokens.iter().any(|t| match t {
            ExprToken::Immediate(_) => true,
            ExprToken::Operator { name: Some(n), .. } => n.starts_with("LOAD_") || n.starts_with("SPECIAL_") || n.starts_with("RAND_"),
            _ => false,
        })
    }

    pub fn try_get_immediate(&self) -> Option<i32> {
        if self.tokens.len() == 1 {
            if let ExprToken::Immediate(v) = self.tokens[0] {
                return Some(v);
            }
        }
        None
    }
}

// ── expression names ──

pub fn expr_token_name(opcode: u8) -> Option<&'static str> {
    Some(match opcode {
        0x01 => "MUL",
        0x02 => "DIV",
        0x03 => "ADD",
        0x04 => "SUB",
        0x05 => "MOD",
        0x06 => "SHL",
        0x07 => "SHR",
        0x08 => "AND",
        0x09 => "XOR",
        0x0A => "OR",
        0x0B => "UNARY_NOT",
        0x0C => "EQ",
        0x0D => "NE",
        0x0E => "LE",
        0x0F => "GE",
        0x10 => "LT",
        0x11 => "GT",
        0x14 => "ASSIGN",
        0x15 => "ASSIGN_MUL",
        0x16 => "ASSIGN_DIV",
        0x17 => "ASSIGN_ADD",
        0x18 => "ASSIGN_SUB",
        0x19 => "ASSIGN_MOD",
        0x1A => "ASSIGN_SHL",
        0x1B => "ASSIGN_SHR",
        0x1C => "ASSIGN_AND",
        0x1D => "ASSIGN_OR",
        0x1E => "ASSIGN_XOR",
        0x20 => "INC",
        0x21 => "DEC",
        0x28 => "LOAD_TAB_16F8A90",
        0x29 => "LOAD_FLAG_46F450",
        0x2A => "LOAD_SCRIPT_TABLE_DWORD",
        0x2B => "LOAD_CODEOFF_T0",
        0x2C => "LOAD_CODEOFF_T0_BY_EXPR",
        0x2D => "LOAD_CTX_DWORD",
        0x2E => "LOAD_EXTERN_CTX_DWORD",
        0x2F => "LOAD_MASK_579D90",
        0x30 => "LOAD_MASK_579D88",
        0x31 => "SPECIAL_31",
        0x32 => "SPECIAL_32",
        0x33 => "RAND_SCALE",
        _ => return None,
    })
}

// ── ReadValue: try_read_immediate ──

pub fn try_read_immediate(data: &[u8], position: usize, limit: usize) -> Option<(ExprToken, usize)> {
    let max = limit.min(data.len());
    if position >= max {
        return Some((ExprToken::Marker("<TRUNC>".into()), max));
    }

    let b0 = data[position];
    if (b0 & 0x80) == 0 {
        return None;
    }

    let mut p = position + 1;
    let mode = (b0 >> 5) & 0x3;
    let low5 = (b0 & 0x1F) as i32;

    let value = match mode {
        0 => sign_extend(low5, 5),
        1 => {
            if p + 1 > max {
                return Some((ExprToken::Marker("<TRUNC_IMM13>".into()), max));
            }
            let v = (low5 << 8) | data[p] as i32;
            p += 1;
            sign_extend(v, 13)
        }
        2 => {
            if p + 2 > max {
                return Some((ExprToken::Marker("<TRUNC_IMM21>".into()), max));
            }
            let v = (low5 << 16) | (data[p + 1] as i32) << 8 | data[p] as i32;
            p += 2;
            sign_extend(v, 21)
        }
        _ => {
            if p + 4 > max {
                return Some((ExprToken::Marker("<TRUNC_IMM32>".into()), max));
            }
            let v = read_u32_le(data, p) as i32;
            p += 4;
            sign_extend(v, 32)
        }
    };

    if p < max {
        p += 1;
    }

    Some((ExprToken::Immediate(value), p))
}

// ── ReadExprValue ──

pub fn read_expr_value(data: &[u8], position: usize, limit: usize) -> (ExprValue, usize) {
    let mut expr = ExprValue::default();
    let mut p = position;
    let max = data.len().min(limit);

    while p < max {
        let b0 = data[p];
        if b0 == 0 {
            p += 1;
            return (expr, p);
        }

        if let Some((token, next)) = try_read_immediate(data, p, limit) {
            let is_marker = matches!(token, ExprToken::Marker(_));
            expr.tokens.push(token);
            p = next;
            if is_marker {
                return (expr, p);
            }
            continue;
        }

        p += 1;
        if p >= max {
            expr.tokens.push(ExprToken::Operator { opcode: b0, precedence: None, name: None });
            return (expr, p);
        }

        let precedence = data[p];
        p += 1;
        let name = expr_token_name(b0);
        expr.tokens.push(ExprToken::Operator {
            opcode: b0,
            precedence: Some(precedence),
            name,
        });
    }

    if expr.tokens.is_empty() {
        expr.tokens.push(ExprToken::Marker("<TRUNC>".into()));
    }

    (expr, p)
}

// ── expression rendering ──

pub fn render_expr(value: &ExprValue) -> String {
    format!("expr({})", render_expr_body(value))
}

pub fn render_expr_body(value: &ExprValue) -> String {
    if value.tokens.is_empty() {
        return "0".into();
    }
    value.tokens.iter().map(render_token).collect::<Vec<_>>().join(", ")
}

fn render_token(token: &ExprToken) -> String {
    match token {
        ExprToken::Immediate(v) => v.to_string(),
        ExprToken::Marker(t) => t.clone(),
        ExprToken::Operator { opcode, precedence, name } => {
            let n = name.map(|s| s.to_string()).unwrap_or_else(|| format!("OP_{opcode:02X}"));
            match precedence {
                Some(p) => format!("{n}@{p}"),
                None => format!("{n}@?"),
            }
        }
    }
}
