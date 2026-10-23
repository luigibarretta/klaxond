//! Regression test for the LDAP TLS crypto provider.
//!
//! ldap3 builds its rustls client config from the process-default crypto
//! provider. rustls can only infer that default when exactly one provider
//! feature is active in the build; with both ring and aws-lc-rs enabled every
//! `ldaps://` connection panicked inside ldap3, which surfaced as a failed
//! authentication worker instead of an LDAP error.

use auth_modules::ldap::{
    LdapAuthConfig, LdapError, default_ldap_email_attr, default_ldap_groups_attr,
    default_ldap_name_attr, default_ldap_scope, default_ldap_user_filter,
    default_ldap_username_attr,
};
use std::io::Read;
use std::net::TcpListener;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::thread;

#[test]
fn ldaps_connection_reaches_the_tls_handshake_without_panicking() {
    // A peer that accepts TCP and closes before speaking TLS: the client must
    // build its rustls config, start the handshake and fail with an error.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut hello = [0_u8; 512];
            let _ = stream.read(&mut hello);
        }
    });

    let config = LdapAuthConfig {
        url: format!("ldaps://127.0.0.1:{port}"),
        bind_dn_template: Some("uid={username},ou=users,dc=example,dc=test".into()),
        service_bind_dn: None,
        service_bind_password: None,
        base_dn: None,
        user_filter: default_ldap_user_filter(),
        scope: default_ldap_scope(),
        username_attr: default_ldap_username_attr(),
        email_attr: default_ldap_email_attr(),
        name_attr: default_ldap_name_attr(),
        groups_attr: default_ldap_groups_attr(),
        timeout_secs: 5,
    };

    let outcome = catch_unwind(AssertUnwindSafe(|| config.authenticate("alice", "secret")));
    // Unblock the accept loop even if the client never connected.
    let _ = std::net::TcpStream::connect(("127.0.0.1", port));
    server.join().unwrap();

    let result = outcome.expect("ldaps:// connect panicked: no unambiguous rustls provider");
    assert!(
        matches!(result, Err(LdapError::Connect(_))),
        "expected a TLS connect error, got {:?}",
        result.map(|identity| identity.username)
    );
}
