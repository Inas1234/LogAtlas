const WINDOWS_TO_UNIX_EPOCH_SECS: u64 = 11_644_473_600;
const FILETIME_TICKS_PER_SEC: u64 = 10_000_000;

pub fn unix_seconds_to_utc_string(unix: u64) -> Option<String> {
    let dt = time::OffsetDateTime::from_unix_timestamp(unix as i64).ok()?;
    Some(format!(
        "{:04}:{:02}:{:02} {:02}:{:02}:{:02} UTC",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    ))
}

/// Convert a Windows FILETIME (100ns ticks since 1601-01-01 UTC) to unix seconds.
pub fn filetime_to_unix_seconds(filetime: u64) -> Option<u64> {
    if filetime == 0 {
        return None;
    }
    let secs = filetime / FILETIME_TICKS_PER_SEC;
    secs.checked_sub(WINDOWS_TO_UNIX_EPOCH_SECS)
}

