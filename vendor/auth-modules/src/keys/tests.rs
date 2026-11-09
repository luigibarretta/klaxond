use super::hkdf::hkdf_sha256;
use super::*;

const SESSION: KeyLabel = KeyLabel::new("klaxond/session-cookie/v1");
const ACK: KeyLabel = KeyLabel::new("klaxond/alert-ack/v1");

fn hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("hex"))
        .collect()
}

fn master(byte: u8) -> MasterKey {
    let bytes: Vec<u8> = (0..32).map(|index| byte.wrapping_add(index)).collect();
    MasterKey::from_bytes(bytes).expect("valid master key")
}

#[test]
fn hkdf_matches_rfc5869_test_case_1() {
    let mut okm = [0_u8; 42];
    hkdf_sha256(
        &hex("000102030405060708090a0b0c"),
        &[0x0b; 22],
        &hex("f0f1f2f3f4f5f6f7f8f9"),
        &mut okm,
    );
    assert_eq!(
        okm.to_vec(),
        hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    );
}

#[test]
fn hkdf_matches_rfc5869_test_case_2() {
    let ikm: Vec<u8> = (0x00..=0x4f).collect();
    let salt: Vec<u8> = (0x60..=0xaf).collect();
    let info: Vec<u8> = (0xb0..=0xff).collect();
    let mut okm = [0_u8; 82];
    hkdf_sha256(&salt, &ikm, &info, &mut okm);
    assert_eq!(
        okm.to_vec(),
        hex(concat!(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c",
            "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71",
            "cc30c58179ec3e87c14c01d5c1f3434f1d87"
        ))
    );
}

#[test]
fn hkdf_matches_rfc5869_test_case_3() {
    let mut okm = [0_u8; 42];
    hkdf_sha256(&[], &[0x0b; 22], &[], &mut okm);
    assert_eq!(
        okm.to_vec(),
        hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
    );
}

#[test]
fn master_key_requires_enough_non_trivial_material() {
    assert!(MasterKey::from_bytes(vec![7_u8; 31]).is_err());
    assert!(MasterKey::from_bytes(vec![0_u8; 64]).is_err());
    assert!(MasterKey::from_bytes(Vec::new()).is_err());
    assert!(MasterKey::from_bytes((0..32).collect::<Vec<u8>>()).is_ok());
}

#[test]
fn labels_must_be_namespaced_and_versioned() {
    for valid in ["app/purpose/v1", "coveyos/session.cookie/v12", "a/b/c/v3"] {
        assert!(KeyLabel::try_new(valid).is_ok(), "{valid}");
    }
    for invalid in [
        "",
        "purpose",
        "app/v1",
        "app/purpose",
        "app/purpose/1",
        "app/purpose/v",
        "app//v1",
        "/app/purpose/v1",
        "app/purpose/v1/",
        "App/purpose/v1",
        "app/pur pose/v1",
        "app/purpose/v1x",
    ] {
        assert!(KeyLabel::try_new(invalid).is_err(), "{invalid:?}");
    }
    assert_eq!(SESSION.as_str(), "klaxond/session-cookie/v1");
}

#[test]
#[should_panic(expected = "invalid key label")]
fn const_label_constructor_panics_on_invalid_labels() {
    let _ = KeyLabel::new("not-namespaced");
}

#[test]
fn derivation_is_deterministic_and_domain_separated() {
    let key = master(1);
    assert_eq!(
        key.derive(SESSION).expose_secret(),
        key.derive(SESSION).expose_secret()
    );
    assert_ne!(
        key.derive(SESSION).expose_secret(),
        key.derive(ACK).expose_secret()
    );
    assert_ne!(
        key.derive(SESSION).expose_secret(),
        master(2).derive(SESSION).expose_secret()
    );
    assert_eq!(key.derive(SESSION).expose_secret().len(), SUBKEY_BYTES);
}

#[test]
fn key_debug_output_is_redacted() {
    let key = master(1);
    let sub = key.derive(SESSION);
    assert_eq!(format!("{key:?}"), "MasterKey([REDACTED])");
    assert!(format!("{sub:?}").contains("[REDACTED]"));
    assert!(format!("{sub:?}").contains("klaxond/session-cookie/v1"));
    let ring = KeyRing::new(key).with_legacy_raw(b"legacy-secret".to_vec(), &[SESSION]);
    let ring = ring.expect("raw legacy key");
    assert!(!format!("{ring:?}").contains("legacy-secret"));
}

#[test]
fn subkey_hmac_verifies_in_constant_time_shape() {
    let sub = master(3).derive(ACK);
    let tag = sub.hmac_sha256(b"alert-17");
    assert!(sub.verify_hmac_sha256(b"alert-17", &tag));
    assert!(!sub.verify_hmac_sha256(b"alert-18", &tag));
    assert!(!sub.verify_hmac_sha256(b"alert-17", &tag[..31]));
}

#[test]
fn key_ring_signs_with_current_and_verifies_legacy_generations() {
    let old_master = master(9);
    let old_tag = old_master.derive(ACK).hmac_sha256(b"msg");
    let raw_legacy = b"short-legacy-secret".to_vec();
    let raw_tag = legacy_hmac_sha256(&raw_legacy, b"msg");

    let ring = KeyRing::new(master(4))
        .with_legacy_master(old_master)
        .with_legacy_raw(raw_legacy, &[ACK])
        .expect("non-empty raw key");
    let current_tag = ring.sign(ACK, b"msg");

    assert_eq!(current_tag, ring.current(ACK).hmac_sha256(b"msg"));
    assert_eq!(
        ring.verify(ACK, b"msg", &current_tag),
        Some(KeyGeneration::Current)
    );
    assert_eq!(
        ring.verify(ACK, b"msg", &old_tag),
        Some(KeyGeneration::Legacy(0))
    );
    assert_eq!(
        ring.verify(ACK, b"msg", &raw_tag),
        Some(KeyGeneration::Legacy(1))
    );
    assert_eq!(ring.verify(SESSION, b"msg", &current_tag), None);
    assert_eq!(ring.verify(ACK, b"other", &current_tag), None);
    assert!(KeyRing::new(master(4))
        .with_legacy_raw(Vec::new(), &[ACK])
        .is_err());
    assert!(KeyRing::new(master(4))
        .with_legacy_raw(b"secret".to_vec(), &[])
        .is_err());
}

#[test]
fn raw_legacy_tags_verify_only_under_their_scoped_labels() {
    let raw = b"shared-legacy-session-key".to_vec();
    let raw_tag = legacy_hmac_sha256(&raw, b"payload");
    let ring = KeyRing::new(master(5))
        .with_legacy_raw(raw, &[ACK])
        .expect("scoped raw key");

    assert_eq!(
        ring.verify(ACK, b"payload", &raw_tag),
        Some(KeyGeneration::Legacy(0))
    );
    // A legacy alert-ack tag must not be accepted as a session cookie.
    assert_eq!(ring.verify(SESSION, b"payload", &raw_tag), None);
}
