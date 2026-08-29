pub fn interpolate_bind_dn(template: &str, username: &str) -> String {
    let escaped = escape_dn_value(username);
    if template.contains("{username}") {
        return template.replace("{username}", &escaped);
    }
    if template.contains("%s") {
        return template.replacen("%s", &escaped, 1);
    }
    template.to_string()
}

pub fn escape_filter_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'*' => out.push_str("\\2a"),
            b'(' => out.push_str("\\28"),
            b')' => out.push_str("\\29"),
            b'\\' => out.push_str("\\5c"),
            0 => out.push_str("\\00"),
            _ => out.push(byte as char),
        }
    }
    out
}

pub fn escape_dn_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    for (idx, byte) in bytes.iter().copied().enumerate() {
        let leading_space_or_hash = idx == 0 && matches!(byte, b' ' | b'#');
        let trailing_space = idx == bytes.len().saturating_sub(1) && byte == b' ';
        match byte {
            0 => out.push_str("\\00"),
            b',' | b'+' | b'"' | b'\\' | b'<' | b'>' | b';' | b'=' => {
                out.push('\\');
                out.push(byte as char);
            }
            _ if leading_space_or_hash || trailing_space => {
                out.push('\\');
                out.push(byte as char);
            }
            _ => out.push(byte as char),
        }
    }
    out
}
