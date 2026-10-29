//! Time helpers (UTC only; the TUI also shows relative durations).

use crate::{bail, Result};

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() * 1000 + d.subsec_millis() as u64)
        .unwrap_or(0)
}

/// Convert days since 1970-01-01 to (year, month, day). Howard Hinnant's
/// civil_from_days algorithm, valid for the full i64 range we care about.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe as i64 - 719468
}

/// RFC 3339 / ISO 8601 UTC timestamp with millisecond precision.
pub fn format_rfc3339(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let millis = ms % 1000;
    let days = secs.div_euclid(86400);
    let sod = secs.rem_euclid(86400);
    let (y, mo, d) = civil_from_days(days);
    let h = sod / 3600;
    let mi = (sod % 3600) / 60;
    let s = sod % 60;
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
}

/// Compact UTC timestamp for filenames: 20261029T230938Z
pub fn format_compact(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let days = secs.div_euclid(86400);
    let sod = secs.rem_euclid(86400);
    let (y, mo, d) = civil_from_days(days);
    format!(
        "{y:04}{mo:02}{d:02}T{:02}{:02}{:02}Z",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

fn parse_u32(bytes: &[u8]) -> Option<u32> {
    let mut v: u32 = 0;
    if bytes.is_empty() || !bytes.iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    for &b in bytes {
        v = v.checked_mul(10)?.checked_add((b - b'0') as u32)?;
    }
    Some(v)
}

/// Parse an RFC 3339 timestamp (fractional seconds optional, offset optional).
pub fn parse_rfc3339(s: &str) -> Result<u64> {
    let s = s.trim();
    let bytes = s.as_bytes();
    if bytes.len() < 19 {
        bail!("timestamp too short: {s}");
    }
    if bytes[4] != b'-' || bytes[7] != b'-' || (bytes[10] != b'T' && bytes[10] != b' ') {
        bail!("invalid timestamp: {s}");
    }
    let (Some(y), Some(mo), Some(d)) = (
        parse_u32(&bytes[0..4]),
        parse_u32(&bytes[5..7]),
        parse_u32(&bytes[8..10]),
    ) else {
        bail!("invalid date in timestamp: {s}");
    };
    let (Some(h), Some(mi), Some(sec)) = (
        parse_u32(&bytes[11..13]),
        parse_u32(&bytes[14..16]),
        parse_u32(&bytes[17..19]),
    ) else {
        bail!("invalid time in timestamp: {s}");
    };
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        bail!("timestamp out of range: {s}");
    }
    let mut i = 19;
    let mut sub_ms = 0u64;
    if i < bytes.len() && bytes[i] == b'.' {
        i += 1;
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        let frac = &s[start..i];
        let mut padded = String::from(frac);
        while padded.len() < 3 {
            padded.push('0');
        }
        padded.truncate(3);
        sub_ms = padded.parse().unwrap_or(0);
    }
    let mut offset_min: i64 = 0;
    if i < bytes.len() {
        match bytes[i] {
            b'Z' | b'z' => i += 1,
            b'+' | b'-' => {
                let sign: i64 = if bytes[i] == b'-' { -1 } else { 1 };
                if i + 6 > bytes.len() {
                    bail!("truncated offset: {s}");
                }
                let Some(oh) = parse_u32(&bytes[i + 1..i + 3]) else {
                    bail!("invalid offset: {s}");
                };
                let Some(om) = parse_u32(&bytes[i + 4..i + 6]) else {
                    bail!("invalid offset: {s}");
                };
                offset_min = sign * (oh as i64 * 60 + om as i64);
                i += 6;
            }
            _ => bail!("unexpected trailing data: {s}"),
        }
    }
    if i != bytes.len() {
        bail!("unexpected trailing data: {s}");
    }
    let days = days_from_civil(y as i64, mo, d);
    let secs = days * 86400 + h as i64 * 3600 + mi as i64 * 60 + sec as i64 - offset_min * 60;
    if secs < 0 {
        bail!("timestamp before epoch: {s}");
    }
    Ok(secs as u64 * 1000 + sub_ms)
}

/// Human duration: 850ms, 3.2s, 2m05s, 1h02m.
pub fn fmt_duration_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else if ms < 10_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else if ms < 60_000 {
        format!("{}s", ms / 1000)
    } else if ms < 3_600_000 {
        let m = ms / 60_000;
        let s = (ms % 60_000) / 1000;
        format!("{m}m{s:02}s")
    } else {
        let h = ms / 3_600_000;
        let m = (ms % 3_600_000) / 60_000;
        format!("{h}h{m:02}m")
    }
}

/// Human local-ish clock time (UTC, no timezone database needed).
pub fn fmt_clock(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let sod = secs.rem_euclid(86400);
    format!("{:02}:{:02}:{:02}", sod / 3600, (sod % 3600) / 60, sod % 60)
}

pub fn sleep_ms(ms: u64) {
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_epoch_and_known_dates() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00.000Z");
        // 2024-02-29T12:34:56.789Z
        let ms = parse_rfc3339("2024-02-29T12:34:56.789Z").unwrap();
        assert_eq!(format_rfc3339(ms), "2024-02-29T12:34:56.789Z");
        assert_eq!(ms, 1709210096789);
    }

    #[test]
    fn parses_offsets() {
        let a = parse_rfc3339("2024-01-01T00:00:00Z").unwrap();
        let b = parse_rfc3339("2024-01-01T08:00:00+08:00").unwrap();
        assert_eq!(a, b);
        assert!(parse_rfc3339("not a date").is_err());
        assert!(parse_rfc3339("2024-13-01T00:00:00Z").is_err());
    }

    #[test]
    fn durations_are_readable() {
        assert_eq!(fmt_duration_ms(500), "500ms");
        assert_eq!(fmt_duration_ms(3200), "3.2s");
        assert_eq!(fmt_duration_ms(65_000), "1m05s");
        assert_eq!(fmt_duration_ms(3_930_000), "1h05m");
    }

    #[test]
    fn compact_is_filename_safe() {
        let s = format_compact(parse_rfc3339("2026-10-29T23:09:38Z").unwrap());
        assert_eq!(s, "20261029T230938Z");
    }
}
