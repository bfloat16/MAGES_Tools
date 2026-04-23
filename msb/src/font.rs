use anyhow::{Result, bail};
use image::{GenericImageView, RgbaImage};
use std::path::Path;

#[derive(Clone, Debug)]
pub struct GlyphMetrics {
    pub x_offset: i16,
    pub y_offset: i16,
    pub atlas_x: i16,
    pub atlas_y: i16,
    pub width: i16,
    pub height: i16,
    pub advance_x: i16,
    pub line_height: i16,
}

pub struct FontAtlas {
    atlas: RgbaImage,
    metrics: Vec<GlyphMetrics>,
}

impl FontAtlas {
    pub fn load(atlas_path: &Path, metrics_path: &Path) -> Result<Self> {
        let atlas_raw = image::open(atlas_path).map_err(|e| anyhow::anyhow!("Failed to load atlas image {}: {e}", atlas_path.display()))?;
        // The font atlas is a Signed Distance Field (SDF) in grayscale.
        // The game engine renders it with a pixel shader that does:
        //   alpha = smoothstep(0.48 - 0.8*fwidth, 0.48 + 0.8*fwidth, dist)
        // where dist = pixel_value / 255.0 and fwidth = abs(dFdx(d)) + abs(dFdy(d)).
        // We replicate this at load time for 1:1 rendering.
        let gray = atlas_raw.to_luma8();
        let w = gray.width();
        let h = gray.height();
        let mut atlas = RgbaImage::new(w, h);
        for y in 0..h {
            for x in 0..w {
                let d = gray.get_pixel(x, y)[0] as f32 / 255.0;
                if d <= 0.0 {
                    continue; // leave transparent
                }
                // Compute fwidth = abs(dFdx) + abs(dFdy) from neighboring pixels
                let left = if x > 0 { gray.get_pixel(x - 1, y)[0] as f32 / 255.0 } else { d };
                let right = if x + 1 < w { gray.get_pixel(x + 1, y)[0] as f32 / 255.0 } else { d };
                let up = if y > 0 { gray.get_pixel(x, y - 1)[0] as f32 / 255.0 } else { d };
                let down = if y + 1 < h { gray.get_pixel(x, y + 1)[0] as f32 / 255.0 } else { d };
                let ddx = (right - left) * 0.5;
                let ddy = (down - up) * 0.5;
                let fw = ddx.abs() + ddy.abs();

                let half_w = fw * 0.8;
                let lower = 0.48 - half_w;
                let upper = 0.48 + half_w;
                let alpha = smoothstep(lower, upper, d);
                let a = (alpha * 255.0).round().clamp(0.0, 255.0) as u8;
                atlas.put_pixel(x, y, image::Rgba([255, 255, 255, a]));
            }
        }

        let metrics_data = std::fs::read(metrics_path).map_err(|e| anyhow::anyhow!("Failed to load atlas metrics {}: {e}", metrics_path.display()))?;
        if metrics_data.len() % 16 != 0 {
            bail!("{}: unexpected size {}", metrics_path.display(), metrics_data.len());
        }

        let mut metrics = Vec::with_capacity(metrics_data.len() / 16);
        for i in 0..metrics_data.len() / 16 {
            let base = i * 16;
            let vals: Vec<i16> = (0..8).map(|j| i16::from_le_bytes([metrics_data[base + j * 2], metrics_data[base + j * 2 + 1]])).collect();
            metrics.push(GlyphMetrics {
                x_offset: vals[0],
                y_offset: vals[1],
                atlas_x: vals[2],
                atlas_y: vals[3],
                width: vals[4],
                height: vals[5],
                advance_x: vals[6],
                line_height: vals[7],
            });
        }

        Ok(Self { atlas, metrics })
    }

    pub fn get_glyph_rgba(&self, glyph_index: usize) -> Option<(RgbaImage, &GlyphMetrics)> {
        let metric = self.metrics.get(glyph_index)?;
        if metric.width <= 0 || metric.height <= 0 {
            return Some((RgbaImage::new(0, 0), metric));
        }

        let x0 = metric.atlas_x as u32;
        let y0 = metric.atlas_y as u32;
        let w = metric.width as u32;
        let h = metric.height as u32;

        if x0 + w > self.atlas.width() || y0 + h > self.atlas.height() {
            return None;
        }

        let sub = self.atlas.view(x0, y0, w, h).to_image();
        Some((sub, metric))
    }
}

fn smoothstep(edge0: f32, edge1: f32, x: f32) -> f32 {
    if edge1 <= edge0 {
        return if x >= edge0 { 1.0 } else { 0.0 };
    }
    let t = ((x - edge0) / (edge1 - edge0)).clamp(0.0, 1.0);
    t * t * (3.0 - 2.0 * t)
}
