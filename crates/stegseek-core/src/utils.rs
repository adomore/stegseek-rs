//! Small helpers ported from `Utils`.

/// Strip the directory part of a path (basename after the last `/` or `\`).
pub fn strip_dir(s: &[u8]) -> Vec<u8> {
    let start = s
        .iter()
        .rposition(|&c| c == b'/' || c == b'\\')
        .map(|p| p + 1)
        .unwrap_or(0);
    s[start..].to_vec()
}

/// Human-readable byte size, matching `Utils::formatHRSize` ("%.1f %s").
pub fn format_hr_size(size: u64) -> String {
    let mut s = size as f32;
    let mut unit = "Byte(s)";
    if s > 1024.0 {
        s /= 1024.0;
        unit = "KB";
    }
    if s > 1024.0 {
        s /= 1024.0;
        unit = "MB";
    }
    if s > 1024.0 {
        s /= 1024.0;
        unit = "GB";
    }
    format!("{s:.1} {unit}")
}
