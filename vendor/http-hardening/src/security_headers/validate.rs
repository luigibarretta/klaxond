//! Dependency-free header syntax checks (RFC 9110 field names and values).

/// Longest accepted header name.
const MAX_NAME_LEN: usize = 128;
/// Longest accepted header value.
const MAX_VALUE_LEN: usize = 8192;

/// True for an RFC 9110 `token`: one or more `tchar`, bounded length.
pub fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_NAME_LEN && name.bytes().all(is_tchar)
}

/// True for a value made only of visible ASCII, spaces and tabs, without
/// leading or trailing whitespace. Stricter than `http::HeaderValue`, which
/// also accepts obsolete non-ASCII bytes.
pub fn is_valid_header_value(value: &str) -> bool {
    let trimmed = value.trim_matches(|c| c == ' ' || c == '\t');
    trimmed.len() == value.len()
        && value.len() <= MAX_VALUE_LEN
        && value
            .bytes()
            .all(|b| b == b'\t' || (b' '..=b'~').contains(&b))
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}
