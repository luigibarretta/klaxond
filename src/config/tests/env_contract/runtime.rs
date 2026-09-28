use super::*;
#[test]
fn reference_compose_and_env_example_cover_runtime_env_vars() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let compose = fs::read_to_string(root.join("docker-compose.yml")).unwrap();
    let split_compose = fs::read_to_string(root.join("docker-compose.split.yml")).unwrap();
    let env_example = fs::read_to_string(root.join(".env.example")).unwrap();
    assert_compose_runtime_contract(&compose, &split_compose, &env_example);
    assert_split_runtime_contract(&split_compose, &env_example);
}

fn assert_compose_runtime_contract(compose: &str, split_compose: &str, env_example: &str) {
    let compose_keys = compose_env_keys(compose);
    let split_compose_keys = compose_env_keys(split_compose);
    assert!(
        !compose_keys.is_empty(),
        "docker-compose.yml has no env keys"
    );
    assert!(
        !split_compose_keys.is_empty(),
        "docker-compose.split.yml has no env keys"
    );
    for key in &compose_keys {
        assert!(
            RUNTIME_COMPOSE_ENV_KEYS.contains(&key.as_str()),
            "RUNTIME_COMPOSE_ENV_KEYS missing compose env {key}"
        );
    }
    for key in RUNTIME_COMPOSE_ENV_KEYS {
        assert!(
            compose.contains(&format!("{key}: ${{{key}")),
            "docker-compose.yml missing {key}"
        );
        assert!(
            env_example
                .lines()
                .any(|line| line.starts_with(&format!("{key}="))
                    || line.starts_with(&format!("# {key}="))),
            ".env.example missing {key}"
        );
    }
}

fn assert_split_runtime_contract(split_compose: &str, env_example: &str) {
    for key in RUNTIME_COMPOSE_ENV_KEYS {
        assert!(
            split_compose.contains(&format!("{key}: ${{{key}")),
            "docker-compose.split.yml missing backend runtime env {key}"
        );
    }
    for key in SPLIT_COMPOSE_ENV_KEYS {
        assert!(
            split_compose.contains(&format!("${{{key}")),
            "docker-compose.split.yml missing split env {key}"
        );
        assert!(
            env_example
                .lines()
                .any(|line| line.starts_with(&format!("{key}="))
                    || line.starts_with(&format!("# {key}="))),
            ".env.example missing split env {key}"
        );
    }
    assert!(
        split_compose.contains(r#"profiles: ["backend", "all"]"#),
        "split compose must allow backend-only startup"
    );
    assert!(
        split_compose.contains(r#"profiles: ["frontend", "all"]"#),
        "split compose must allow frontend-only startup"
    );
    assert!(
        split_compose.contains(r#"profiles: ["db", "state", "all"]"#),
        "split compose must allow db/state-only startup"
    );
}
