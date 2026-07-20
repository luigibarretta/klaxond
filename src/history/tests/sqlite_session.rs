use super::*;

#[test]
fn sqlite_auth_sessions_enforce_idle_expiry_and_global_concurrency() {
    let tmp = TempDir::new().unwrap();
    let store = HistoryStore::open(&sqlite_cfg(tmp.path().join("history.db"), 0)).unwrap();
    for (index, mode) in ["basic", "oidc", "magic_link", "ldap"].iter().enumerate() {
        let now = 1_000 + index as i64;
        store
            .create_auth_session(
                &auth_session(&format!("session-{index}"), mode, now),
                None,
                3,
                now,
            )
            .unwrap();
    }

    assert!(
        store
            .auth_session("session-0", 1_010, 1_000)
            .unwrap()
            .is_none(),
        "the oldest session must be revoked regardless of auth mode"
    );
    for index in 1..4 {
        assert!(
            store
                .auth_session(&format!("session-{index}"), 1_010, 1_000)
                .unwrap()
                .is_some()
        );
    }

    let idle = auth_session("idle", "basic", 2_000);
    store.create_auth_session(&idle, None, 3, 2_000).unwrap();
    assert!(store.auth_session("idle", 2_100, 100).unwrap().is_none());
}

#[test]
fn sqlite_auth_sessions_enforce_gold_absolute_lifetime() {
    let tmp = TempDir::new().unwrap();
    let store = HistoryStore::open(&sqlite_cfg(tmp.path().join("history.db"), 0)).unwrap();
    let mut session = auth_session("absolute-lifetime", "basic", 1_000);
    session.expires_at = 101_000;
    store.create_auth_session(&session, None, 3, 1_000).unwrap();

    assert!(
        store
            .auth_session("absolute-lifetime", 1_000 + (8 * 60 * 60), 100_000)
            .unwrap()
            .is_none()
    );
}

#[test]
fn sqlite_rotation_requires_active_family_and_family_logout_uses_revoked_row() {
    let tmp = TempDir::new().unwrap();
    let cfg = sqlite_cfg(tmp.path().join("history.db"), 0);
    let store = HistoryStore::open(&cfg).unwrap();
    let mut original = auth_session("rotation-original", "basic", 1_000);
    original.family_hash = "shared-rotation-family".to_string();
    store
        .create_auth_session(&original, None, 3, 1_000)
        .unwrap();

    let mut replacement = auth_session("rotation-replacement", "basic", 1_100);
    replacement.family_hash = original.family_hash.clone();
    replacement.created_at = original.created_at;
    store
        .create_auth_session(&replacement, Some(&original.id_hash), 3, 1_100)
        .unwrap();

    let invalid = auth_session("rotation-invalid", "basic", 1_200);
    assert!(
        store
            .create_auth_session(&invalid, Some(&replacement.id_hash), 3, 1_200)
            .unwrap_err()
            .to_string()
            .contains("same family")
    );

    let mut conn = rusqlite::Connection::open(&cfg.sqlite_path).unwrap();
    assert_eq!(
        crate::history::sqlite::session::revoke_family_by_id(&mut conn, &original.id_hash, 1_300,)
            .unwrap(),
        1,
        "the revoked predecessor must still identify the active family"
    );
    assert!(
        store
            .auth_session(&replacement.id_hash, 1_301, 10_000)
            .unwrap()
            .is_none()
    );
}

#[test]
fn sqlite_oidc_logout_is_atomic_replay_safe_and_revokes_session() {
    let tmp = TempDir::new().unwrap();
    let store = HistoryStore::open(&sqlite_cfg(tmp.path().join("history.db"), 0)).unwrap();
    store
        .create_auth_session(&auth_session("oidc-session", "oidc", 1_000), None, 3, 1_000)
        .unwrap();
    let token = logout_token("logout-jti-hash", 1_100);

    let first = store
        .consume_oidc_logout(&token, Some("provider-session"), Some("same-user"), 1_100)
        .unwrap();
    assert_eq!(
        first,
        OidcLogoutResult {
            replayed: false,
            revoked_sessions: 1,
        }
    );
    assert!(
        store
            .auth_session("oidc-session", 1_101, 1_000)
            .unwrap()
            .is_none()
    );

    let replay = store
        .consume_oidc_logout(&token, Some("provider-session"), Some("same-user"), 1_101)
        .unwrap();
    assert_eq!(
        replay,
        OidcLogoutResult {
            replayed: true,
            revoked_sessions: 0,
        }
    );
}

#[test]
fn sqlite_history_migration_copies_sessions_and_logout_replay_state() {
    let tmp = TempDir::new().unwrap();
    let src = sqlite_cfg(tmp.path().join("src.db"), 0);
    let dst = sqlite_cfg(tmp.path().join("dst.db"), 0);
    let src_store = HistoryStore::open(&src).unwrap();
    src_store
        .create_auth_session(
            &auth_session("migrated-session", "basic", 1_000),
            None,
            3,
            1_000,
        )
        .unwrap();
    let token = logout_token("migrated-jti-hash", 1_100);
    src_store
        .consume_oidc_logout(&token, None, Some("nobody"), 1_100)
        .unwrap();

    migrate_between(&src, &dst).unwrap();

    let dst_store = HistoryStore::open(&dst).unwrap();
    assert!(
        dst_store
            .auth_session("migrated-session", 1_101, 1_000)
            .unwrap()
            .is_some()
    );
    assert!(
        dst_store
            .consume_oidc_logout(&token, None, Some("nobody"), 1_101)
            .unwrap()
            .replayed
    );
}

#[test]
fn sqlite_auth_state_imports_are_monotonic_and_idempotent() {
    let tmp = TempDir::new().unwrap();
    let src = sqlite_cfg(tmp.path().join("src.db"), 0);
    let dst = sqlite_cfg(tmp.path().join("dst.db"), 0);
    let src_store = HistoryStore::open(&src).unwrap();
    let dst_store = HistoryStore::open(&dst).unwrap();

    let mut incoming = auth_session("monotonic-session", "oidc", 1_000);
    incoming.family_hash = "monotonic-family".to_string();
    incoming.last_seen_at = 1_400;
    incoming.last_rotated_at = 1_350;
    incoming.expires_at = 10_000;
    src_store
        .create_auth_session(&incoming, None, 3, 1_000)
        .unwrap();

    let mut existing = incoming.clone();
    existing.created_at = 900;
    existing.last_seen_at = 1_100;
    existing.last_rotated_at = 1_200;
    existing.expires_at = 5_000;
    existing.revoked_at = Some(1_300);
    dst_store
        .create_auth_session(&existing, None, 3, 900)
        .unwrap();

    let incoming_token = OidcLogoutTokenRecord {
        consumed_at: 1_100,
        expires_at: 3_000,
        ..logout_token("monotonic-jti", 1_100)
    };
    let existing_token = OidcLogoutTokenRecord {
        consumed_at: 1_000,
        expires_at: 5_000,
        ..incoming_token.clone()
    };
    import_logout_token(&src_store, incoming_token.clone());
    import_logout_token(&dst_store, existing_token);

    migrate_between(&src, &dst).unwrap();
    migrate_between(&src, &dst).unwrap();

    let conn = rusqlite::Connection::open(&dst.sqlite_path).unwrap();
    let sessions = crate::history::sqlite::session::export_sessions(&conn).unwrap();
    let merged = sessions
        .iter()
        .find(|record| record.id_hash == incoming.id_hash)
        .unwrap();
    assert_eq!(merged.created_at, 900);
    assert_eq!(merged.last_seen_at, 1_400);
    assert_eq!(merged.last_rotated_at, 1_350);
    assert_eq!(merged.expires_at, 5_000);
    assert_eq!(merged.revoked_at, Some(1_300));

    let tokens = crate::history::sqlite::session::export_logout_tokens(&conn).unwrap();
    let merged = tokens
        .iter()
        .find(|token| token.token_id_hash == incoming_token.token_id_hash)
        .unwrap();
    assert_eq!(merged.consumed_at, 1_000);
    assert_eq!(merged.expires_at, 5_000);
}
