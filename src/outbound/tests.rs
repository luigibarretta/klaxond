use super::preflight::target_verdict;
use super::{OutboundClients, guard_refusal, outbound_guard};
use http_hardening::net_guard::NetGuardError;
use std::fmt;

#[test]
fn allowlist_accepts_networks_and_rejects_malformed_or_wide_entries() {
    assert!(outbound_guard("").is_ok());
    assert!(outbound_guard("192.168.50.100/32, 192.168.50.110/32").is_ok());
    assert!(outbound_guard("192.168.50.0/24 fd00::/48").is_ok());
    assert!(outbound_guard("192.168.50.1/24").is_err(), "host bits set");
    assert!(outbound_guard("10.0.0.0/4").is_err(), "wider than /8");
    assert!(outbound_guard("not-a-cidr").is_err());
}

#[tokio::test]
async fn literal_targets_follow_the_allowlist() {
    let open = outbound_guard("").unwrap();
    let lan = outbound_guard("192.168.50.100/32").unwrap();
    assert!(
        target_verdict(&open, "https://192.168.50.100")
            .await
            .is_err()
    );
    assert!(target_verdict(&lan, "https://192.168.50.100").await.is_ok());
    assert!(
        target_verdict(&lan, "http://192.168.50.110:3000")
            .await
            .is_err()
    );
    assert!(
        target_verdict(&open, "https://149.154.166.110")
            .await
            .is_ok()
    );
    assert!(
        target_verdict(&open, "http://localhost:8080")
            .await
            .is_err()
    );
    assert!(target_verdict(&open, "http://[::1]:8080").await.is_err());
    assert!(
        target_verdict(&open, "http://169.254.169.254/")
            .await
            .is_err()
    );
    assert!(
        target_verdict(&open, "http://user:pw@149.154.166.110/")
            .await
            .is_err()
    );
    assert!(target_verdict(&open, "ftp://example.com/").await.is_err());
}

#[derive(Debug)]
struct Wrapper(NetGuardError);

impl fmt::Display for Wrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("connect failed")
    }
}

impl std::error::Error for Wrapper {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

#[test]
fn guard_errors_nested_in_transport_errors_are_refusals() {
    let nested = Wrapper(NetGuardError::NoAddresses("ntfy.example".into()));
    let reason = guard_refusal(&nested).expect("nested guard error");
    assert!(reason.contains("ntfy.example"));
    let plain = std::io::Error::other("connection refused");
    assert!(guard_refusal(&plain).is_none());
}

#[test]
fn clients_are_rebuilt_when_the_allowlist_changes() {
    let clients = OutboundClients::default();
    assert!(clients.client("192.168.50.100/32").is_ok());
    assert!(clients.client("192.168.50.100/32").is_ok());
    let invalid = clients.client("nonsense").unwrap_err();
    assert!(invalid.is_refusal());
    assert!(invalid.to_string().contains("invalid allowlist"));
}
