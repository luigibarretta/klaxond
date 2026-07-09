pub(in crate::state) fn metric_key(name: &str, labels: &[(&str, &str)]) -> String {
    let mut labels = labels
        .iter()
        .map(|(key, value)| format!("{key}={}", esc_label(value)))
        .collect::<Vec<_>>();
    labels.sort();
    format!("{name}|{}", labels.join(","))
}

pub fn esc_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
