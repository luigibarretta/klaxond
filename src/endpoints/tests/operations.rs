use super::openapi_operation_block;

const OPERATIONS: &[(&str, &str)] = &[
    ("get", "/openapi.yaml"),
    ("get", "/api/openapi.yaml"),
    ("get", "/swagger"),
    ("get", "/api/docs"),
    ("get", "/api/swagger"),
    ("get", "/api/swagger-ui"),
    ("get", "/legal"),
    ("get", "/legal/privacy"),
    ("get", "/legal/accessibility"),
    ("get", "/legal/terms"),
    ("get", "/legal/cookies"),
    ("get", "/legal/notice"),
    ("get", "/healthz"),
    ("get", "/metrics"),
    ("post", "/webhook/{severity}"),
    ("post", "/beszel/{severity}"),
    ("post", "/healthchecks/{severity}"),
    ("post", "/uptime-kuma/{severity}"),
    ("post", "/wud/{severity}"),
    ("post", "/authentik/{severity}"),
    ("post", "/shelfmark/{severity}"),
    ("post", "/prowlarr/{severity}"),
    ("post", "/decypharr/{severity}"),
    ("post", "/pve/{severity}"),
    ("post", "/blackstart/{severity}"),
    ("post", "/github/{severity}"),
    ("post", "/revaulter/{severity}"),
    ("get", "/api/auth/login"),
    ("get", "/api/auth/methods"),
    ("post", "/api/auth/local/login"),
    ("post", "/api/auth/magic/request"),
    ("get", "/api/auth/magic/callback/{token}"),
    ("get", "/api/auth/callback"),
    ("post", "/api/auth/backchannel-logout"),
    ("post", "/api/auth/logout"),
    ("get", "/api/auth/me"),
    ("get", "/api/auth/password-policy"),
    ("post", "/api/auth/reauth"),
    ("get", "/api/auth/passkey/login"),
    ("post", "/api/auth/passkey/login/options"),
    ("post", "/api/auth/passkey/login/verify"),
    ("get", "/api/auth/step-up"),
    ("get", "/api/auth/step-up/status"),
    ("post", "/api/auth/step-up/passkey/register/options"),
    ("post", "/api/auth/step-up/passkey/register/verify"),
    ("post", "/api/auth/step-up/totp/setup/start"),
    ("post", "/api/auth/step-up/totp/setup/confirm"),
    ("post", "/api/auth/step-up/totp/verify"),
    ("get", "/api/status"),
    ("get", "/api/status/activity"),
    ("get", "/api/setup-status"),
    ("get", "/api/channel-test-matrix"),
    ("get", "/api/logs"),
    ("get", "/api/audit"),
    ("post", "/api/client-log"),
    ("get", "/api/deliveries"),
    ("get", "/api/emergency-config"),
    ("post", "/api/emergency-config"),
    ("get", "/api/history-config"),
    ("post", "/api/history-config"),
    ("get", "/api/emergencies"),
    ("get", "/api/emergencies/{id}"),
    ("post", "/api/emergencies/{id}/{action}"),
    ("get", "/emergency/{token}"),
    ("post", "/emergency/{token}"),
    ("post", "/api/emergency/{id}/ack"),
    ("get", "/api/auth/config"),
    ("post", "/api/auth/config"),
    ("get", "/api/auth/tokens"),
    ("post", "/api/auth/tokens"),
    ("delete", "/api/auth/tokens/{id}"),
    ("post", "/api/auth/totp/setup/start"),
    ("post", "/api/auth/totp/setup/confirm"),
    ("post", "/api/auth/totp/disable"),
    ("get", "/api/auth/passkey/credentials"),
    ("post", "/api/auth/passkey/register/options"),
    ("post", "/api/auth/passkey/register/verify"),
    ("delete", "/api/auth/passkey/credentials/{id}"),
    ("get", "/api/config/backup"),
    ("get", "/api/config/export"),
    ("get", "/api/config/backups"),
    ("post", "/api/config/import-preview"),
    ("post", "/api/config/restore"),
    ("get", "/api/channel-config"),
    ("post", "/api/channel-config"),
    ("get", "/api/ntfy-topics"),
    ("post", "/api/ntfy-topics"),
    ("get", "/api/ingest-auth"),
    ("post", "/api/ingest-auth"),
    ("get", "/api/delivery-config"),
    ("post", "/api/delivery-config"),
    ("get", "/api/cascade-config"),
    ("post", "/api/cascade-config"),
    ("post", "/api/cascade/toggle"),
    ("get", "/api/dedup-config"),
    ("post", "/api/dedup-config"),
    ("get", "/inhibitions"),
    ("get", "/api/inhibitions"),
    ("get", "/api/inhibition-rules"),
    ("post", "/api/inhibition-rules"),
    ("post", "/api/inhibition-rules/test"),
    ("post", "/api/inhibition-rules/validate-regex"),
    ("post", "/api/inhibitions/clear"),
    ("get", "/api/schedules"),
    ("post", "/api/schedules"),
    ("get", "/api/acks"),
    ("post", "/api/acks/clear"),
    ("get", "/api/ack/{token}"),
    ("post", "/api/policy-simulate"),
    ("get", "/api/render-config"),
    ("post", "/api/render-config"),
    ("post", "/api/render-preview"),
    ("post", "/api/test/{severity}"),
    ("post", "/ingest/{source}/{severity}"),
];

#[test]
fn all_runtime_operations_are_documented_in_openapi() {
    let openapi = include_str!("../../../docs/openapi.yaml");

    for (method, path) in OPERATIONS {
        let block = openapi_operation_block(openapi, path, method)
            .unwrap_or_else(|| panic!("OpenAPI missing operation {method} {path}"));
        for required in ["operationId:", "summary:", "security:", "responses:"] {
            assert!(
                block.contains(required),
                "OpenAPI operation {method} {path} missing {required}"
            );
        }
    }
}

#[test]
fn delivery_config_components_are_bound_only_to_delivery_operations() {
    let openapi = include_str!("../../../docs/openapi.yaml");
    let get_delivery = openapi_operation_block(openapi, "/api/delivery-config", "get")
        .expect("delivery config GET operation");
    let update_delivery = openapi_operation_block(openapi, "/api/delivery-config", "post")
        .expect("delivery config POST operation");

    assert!(get_delivery.contains("#/components/schemas/DeliveryConfigResponse"));
    assert!(update_delivery.contains("#/components/schemas/DeliveryConfigUpdate"));
    assert!(update_delivery.contains("#/components/responses/BadRequest"));

    for (method, path) in [
        ("get", "/api/auth/methods"),
        ("post", "/api/auth/magic/request"),
        ("post", "/api/auth/passkey/register/verify"),
    ] {
        let block = openapi_operation_block(openapi, path, method)
            .unwrap_or_else(|| panic!("OpenAPI missing operation {method} {path}"));
        assert!(
            !block.contains("DeliveryConfig"),
            "OpenAPI operation {method} {path} must not use delivery schemas"
        );
    }
}
