use super::*;

fn postgres_cfg(url: String) -> HistoryConfig {
    HistoryConfig {
        backend: "postgres".to_string(),
        sqlite_path: PathBuf::from("/tmp/klaxond-unused.db"),
        postgres_url: url,
        retention: 0,
        default_limit: 500,
    }
}

#[test]
#[ignore = "requires KLAXOND_TEST_POSTGRES_URL"]
fn postgres_oidc_logout_is_atomic_across_workers() {
    let _guard = postgres_test_guard();
    let url = std::env::var("KLAXOND_TEST_POSTGRES_URL")
        .expect("KLAXOND_TEST_POSTGRES_URL is required for this ignored test");
    let cfg = postgres_cfg(url);
    let first = HistoryStore::open(&cfg).unwrap();
    let second = HistoryStore::open(&cfg).unwrap();
    let unique = crate::util::token_urlsafe(12);
    let subject = format!("postgres-user-{unique}");
    let provider_session_id = format!("postgres-session-{unique}");
    let mut session = auth_session(&format!("postgres-id-{unique}"), "oidc", 1_000);
    session.user_sub = subject.clone();
    session.provider_session_id = Some(provider_session_id.clone());
    first.create_auth_session(&session, None, 3, 1_000).unwrap();
    let token = OidcLogoutTokenRecord {
        token_id_hash: format!("postgres-jti-{unique}"),
        ..logout_token("unused", 1_100)
    };
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let first_barrier = barrier.clone();
    let first_token = token.clone();
    let first_subject = subject.clone();
    let first_sid = provider_session_id.clone();
    let first_thread = std::thread::spawn(move || {
        first_barrier.wait();
        first.consume_oidc_logout(&first_token, Some(&first_sid), Some(&first_subject), 1_100)
    });
    let second_barrier = barrier.clone();
    let second_thread = std::thread::spawn(move || {
        second_barrier.wait();
        second.consume_oidc_logout(&token, Some(&provider_session_id), Some(&subject), 1_100)
    });

    barrier.wait();
    let outcomes = [
        first_thread.join().unwrap().unwrap(),
        second_thread.join().unwrap().unwrap(),
    ];
    assert_eq!(
        outcomes.iter().filter(|outcome| !outcome.replayed).count(),
        1
    );
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.replayed).count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .map(|outcome| outcome.revoked_sessions)
            .sum::<usize>(),
        1
    );
}

#[test]
#[ignore = "requires KLAXOND_TEST_POSTGRES_URL"]
fn postgres_concurrent_session_creation_enforces_global_limit() {
    const SESSION_COUNT: usize = 8;
    const MAX_CONCURRENT: usize = 3;

    let _guard = postgres_test_guard();
    let url = std::env::var("KLAXOND_TEST_POSTGRES_URL")
        .expect("KLAXOND_TEST_POSTGRES_URL is required for this ignored test");
    let cfg = postgres_cfg(url);
    let unique = crate::util::token_urlsafe(12);
    let subject = format!("postgres-concurrent-user-{unique}");
    let ids = (0..SESSION_COUNT)
        .map(|index| format!("postgres-concurrent-{unique}-{index}"))
        .collect::<Vec<_>>();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(SESSION_COUNT + 1));
    let threads = ids
        .iter()
        .map(|id| {
            let store = HistoryStore::open(&cfg).unwrap();
            let barrier = barrier.clone();
            let mut session = auth_session(id, "basic", 1_000);
            session.user_sub = subject.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store.create_auth_session(&session, None, MAX_CONCURRENT, session.created_at)
            })
        })
        .collect::<Vec<_>>();

    barrier.wait();
    for thread in threads {
        thread.join().unwrap().unwrap();
    }

    let verifier = HistoryStore::open(&cfg).unwrap();
    let active = ids
        .iter()
        .filter(|id| verifier.auth_session(id, 1_001, 10_000).unwrap().is_some())
        .count();
    assert_eq!(active, MAX_CONCURRENT);
}

#[test]
#[ignore = "requires KLAXOND_TEST_POSTGRES_URL"]
fn postgres_oidc_logout_serializes_with_session_rotation() {
    let _guard = postgres_test_guard();
    let url = std::env::var("KLAXOND_TEST_POSTGRES_URL")
        .expect("KLAXOND_TEST_POSTGRES_URL is required for this ignored test");
    for (selector, include_sid, include_subject) in [
        ("sid-and-sub", true, true),
        ("sid-only", true, false),
        ("sub-only", false, true),
    ] {
        assert_logout_serializes_with_rotation(&url, selector, include_sid, include_subject);
    }
}

fn assert_logout_serializes_with_rotation(
    url: &str,
    selector: &str,
    include_sid: bool,
    include_subject: bool,
) {
    let cfg = postgres_cfg(url.to_string());
    let setup = HistoryStore::open(&cfg).unwrap();
    let rotate_store = HistoryStore::open(&cfg).unwrap();
    let logout_store = HistoryStore::open(&cfg).unwrap();
    let unique = crate::util::token_urlsafe(12);
    let subject = format!("postgres-rotation-user-{selector}-{unique}");
    let provider_session_id = format!("postgres-rotation-sid-{selector}-{unique}");
    let old_id = format!("postgres-rotation-old-{unique}");
    let new_id = format!("postgres-rotation-new-{unique}");
    let mut old_session = auth_session(&old_id, "oidc", 1_000);
    old_session.user_sub = subject.clone();
    old_session.provider_session_id = Some(provider_session_id.clone());
    setup
        .create_auth_session(&old_session, None, 3, 1_000)
        .unwrap();

    let mut new_session = old_session.clone();
    new_session.id_hash = new_id.clone();
    new_session.last_rotated_at = 1_100;
    let token = OidcLogoutTokenRecord {
        token_id_hash: format!("postgres-rotation-jti-{unique}"),
        ..logout_token("unused", 1_100)
    };
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let rotate_barrier = barrier.clone();
    let rotate_thread = std::thread::spawn(move || {
        rotate_barrier.wait();
        rotate_store.create_auth_session(&new_session, Some(&old_id), 3, 1_100)
    });
    let logout_barrier = barrier.clone();
    let logout_sid = include_sid.then_some(provider_session_id);
    let logout_subject = include_subject.then_some(subject);
    let logout_thread = std::thread::spawn(move || {
        logout_barrier.wait();
        logout_store.consume_oidc_logout(
            &token,
            logout_sid.as_deref(),
            logout_subject.as_deref(),
            1_100,
        )
    });

    barrier.wait();
    let rotation = rotate_thread.join().unwrap();
    let logout = logout_thread.join().unwrap().unwrap();
    assert!(!logout.replayed);
    assert!(logout.revoked_sessions >= 1);
    assert!(
        setup
            .auth_session(&new_id, 1_101, 10_000)
            .unwrap()
            .is_none()
    );
    if rotation.is_err() {
        assert!(
            setup
                .auth_session(&format!("postgres-rotation-old-{unique}"), 1_101, 10_000)
                .unwrap()
                .is_none()
        );
    }
}

#[test]
#[ignore = "requires KLAXOND_TEST_POSTGRES_URL"]
fn postgres_session_and_logout_imports_are_monotonic() {
    let _guard = postgres_test_guard();
    let url = std::env::var("KLAXOND_TEST_POSTGRES_URL")
        .expect("KLAXOND_TEST_POSTGRES_URL is required for this ignored test");
    let store = HistoryStore::open(&postgres_cfg(url)).unwrap();
    let unique = crate::util::token_urlsafe(12);
    let id = format!("postgres-monotonic-{unique}");
    let mut existing = auth_session(&id, "oidc", 900);
    existing.last_seen_at = 1_100;
    existing.last_rotated_at = 1_200;
    existing.expires_at = 5_000;
    existing.revoked_at = Some(1_300);
    import_auth_session(&store, existing.clone());

    let mut stale = existing.clone();
    stale.created_at = 1_000;
    stale.last_seen_at = 1_400;
    stale.last_rotated_at = 1_350;
    stale.expires_at = 10_000;
    stale.revoked_at = None;
    import_auth_session(&store, stale.clone());
    import_auth_session(&store, stale);

    let merged = store
        .export_auth_sessions()
        .unwrap()
        .into_iter()
        .find(|record| record.id_hash == id)
        .unwrap();
    assert_eq!(merged.created_at, 900);
    assert_eq!(merged.last_seen_at, 1_400);
    assert_eq!(merged.last_rotated_at, 1_350);
    assert_eq!(merged.expires_at, 5_000);
    assert_eq!(merged.revoked_at, Some(1_300));

    let token_id = format!("postgres-monotonic-jti-{unique}");
    let stronger = OidcLogoutTokenRecord {
        issuer: "https://idp.example/".to_string(),
        token_id_hash: token_id.clone(),
        consumed_at: 1_000,
        expires_at: 5_000,
    };
    let weaker = OidcLogoutTokenRecord {
        consumed_at: 1_100,
        expires_at: 3_000,
        ..stronger.clone()
    };
    import_logout_token(&store, stronger);
    import_logout_token(&store, weaker);
    let merged = store
        .export_oidc_logout_tokens()
        .unwrap()
        .into_iter()
        .find(|token| token.token_id_hash == token_id)
        .unwrap();
    assert_eq!(merged.consumed_at, 1_000);
    assert_eq!(merged.expires_at, 5_000);
}
