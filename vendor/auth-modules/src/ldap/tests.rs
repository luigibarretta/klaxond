use ldap3::Scope;

use super::*;

#[test]
fn escapes_ldap_filter_values() {
    assert_eq!(
        escape_filter_value(r#"luigi*(admin)\x"#),
        r#"luigi\2a\28admin\29\5cx"#
    );
}

#[test]
fn interpolates_bind_dn_with_escaped_username() {
    assert_eq!(
        interpolate_bind_dn("cn=%s,ou=users,dc=example", "alice"),
        "cn=alice,ou=users,dc=example"
    );
    assert_eq!(
        interpolate_bind_dn(
            "uid={username},ou=users,dc=example",
            r#" #a,b+c\d=e;f<g>h" "#
        ),
        r#"uid=\ #a\,b\+c\\d\=e\;f\<g\>h\"\ ,ou=users,dc=example"#
    );
    assert_eq!(escape_dn_value("trailing "), r#"trailing\ "#);
}

#[test]
fn parses_scope_aliases() {
    assert_eq!(ldap_scope_from_name("subtree"), Some(Scope::Subtree));
    assert_eq!(ldap_scope_from_name("one-level"), Some(Scope::OneLevel));
    assert_eq!(ldap_scope_from_name("base"), Some(Scope::Base));
    assert_eq!(ldap_scope_from_name("unknown"), None);
}

#[test]
fn ldap_config_debug_redacts_service_password() {
    let config = LdapAuthConfig {
        url: "ldaps://directory.example".to_string(),
        bind_dn_template: None,
        service_bind_dn: Some("cn=service,dc=example,dc=com".to_string()),
        service_bind_password: Some("directory-secret".to_string()),
        base_dn: Some("dc=example,dc=com".to_string()),
        user_filter: default_ldap_user_filter(),
        scope: default_ldap_scope(),
        username_attr: default_ldap_username_attr(),
        email_attr: default_ldap_email_attr(),
        name_attr: default_ldap_name_attr(),
        groups_attr: default_ldap_groups_attr(),
        timeout_secs: DEFAULT_TIMEOUT_SECS,
    };

    let debug = format!("{config:?}");
    assert!(debug.contains("ldaps://directory.example"));
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("directory-secret"));
}

#[test]
fn ldap_configuration_requires_tls_and_a_single_direct_bind_placeholder() {
    let mut config = LdapAuthConfig {
        url: "ldaps://directory.example.test".to_string(),
        bind_dn_template: Some("uid=static,dc=example,dc=test".to_string()),
        service_bind_dn: None,
        service_bind_password: None,
        base_dn: None,
        user_filter: "(uid={username})".to_string(),
        scope: Scope::Subtree,
        username_attr: "uid".to_string(),
        email_attr: "mail".to_string(),
        name_attr: "displayName".to_string(),
        groups_attr: "memberOf".to_string(),
        timeout_secs: 5,
    };

    assert!(matches!(
        config.validate(),
        Err(LdapError::InvalidConfiguration(_))
    ));
    config.bind_dn_template = Some("uid={username},dc=example,dc=test".to_string());
    assert!(config.validate().is_ok());

    config.url = "ldap://directory.example.test".to_string();
    assert!(matches!(
        config.validate(),
        Err(LdapError::InsecureTransport)
    ));
}
