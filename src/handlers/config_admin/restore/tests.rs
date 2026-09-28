use super::*;
use crate::auth::test_support::temp_paths;
use crate::config::{AuthConfig, save_auth};
use tempfile::TempDir;

#[test]
fn staged_partial_restore_preserves_unmentioned_sidecars() {
    let _env_guard = crate::config::TEST_ENV_LOCK.lock().unwrap();
    let tmp = TempDir::new().unwrap();
    let paths = temp_paths(&tmp);
    let mut auth = AuthConfig {
        mode: "basic".to_string(),
        ..AuthConfig::default()
    };
    auth.basic.username = "staged-user".to_string();
    save_auth(&paths, &auth).unwrap();
    let state = AppState::new(paths).unwrap();
    let input = parse_restore_input(&Bytes::from_static(
        b"[delivery]\nseverity_floor = \"warning\"\n",
    ))
    .unwrap();

    let staged = prepare_runtime_config(&state, &input).unwrap();

    assert_eq!(staged.auth.mode, "basic");
    assert_eq!(staged.auth.basic.username, "staged-user");
}
