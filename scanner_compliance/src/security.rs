/// Maximum JSON nesting depth allowed in any manifest string.
pub const MAX_JSON_DEPTH: usize = 64;

/// Checks that a JSON string does not exceed [`MAX_JSON_DEPTH`] levels of nesting.
///
/// Walks the raw bytes counting `{`/`[` (open) and `}`/`]` (close),
/// skipping characters inside string literals to avoid false positives.
/// Returns `Err` with a message if the depth limit is exceeded.
pub fn check_json_depth(s: &str) -> Result<(), String> {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;

    for b in s.bytes() {
        if escaped {
            escaped = false;
            continue;
        }
        match b {
            b'\\' if in_string => escaped = true,
            b'"' => in_string = !in_string,
            b'{' | b'[' if !in_string => {
                depth += 1;
                if depth > MAX_JSON_DEPTH {
                    return Err(format!(
                        "manifest_raw JSON nesting depth exceeds limit of {}",
                        MAX_JSON_DEPTH
                    ));
                }
            }
            b'}' | b']' if !in_string => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    Ok(())
}
