use super::*;

#[test]
fn registry_contains_expected_magic_link_code() {
    assert!(is_gold_auth_error_code(MAGIC_LINK_UNAVAILABLE));
    assert_eq!(describe(MAGIC_LINK_UNAVAILABLE).http_status, 503);
    assert!(describe(MAGIC_LINK_UNAVAILABLE).retryable);
}

#[test]
fn unknown_codes_collapse_to_internal_error() {
    let descriptor = describe("unknown");

    assert_eq!(descriptor.code, INTERNAL_ERROR);
    assert_eq!(descriptor.http_status, 500);
}
