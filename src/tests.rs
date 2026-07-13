use super::{
    Error, Gcm256Key, GcmNonce, Salt, decrypt_with_key, decrypt_with_password,
    encrypt_with_password, encrypt_with_random_key,
};

const PLAINTEXT: &[u8] = b"the treaty of westphalia was signed in 1648";
const PASSWORD: &str = "correct horse battery staple";

/// `Error` is deliberately opaque and implements no `Debug`, so `Result::unwrap` is unavailable.
fn expect<T>(result: Result<T, Error>, msg: &str) -> T {
    result.unwrap_or_else(|_| panic!("{msg}"))
}

fn kek_of(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn wrap(key: &Gcm256Key, kek: &[u8; 32]) -> ([u8; 48], GcmNonce) {
    let (wrapped, nonce) = expect(key.expose_with_kek(kek), "wrapping failed");
    let wrapped = wrapped.try_into().expect("wrapped DEK should be 48 bytes");
    (wrapped, nonce)
}

#[test]
fn random_key_roundtrip() {
    let (encrypted, key) = expect(encrypt_with_random_key(PLAINTEXT), "encryption failed");
    let decrypted = expect(
        decrypt_with_key(&encrypted.bytes, &key, &encrypted.nonce),
        "decryption failed",
    );
    assert_eq!(decrypted, PLAINTEXT);
}

#[test]
fn random_key_ciphertext_hides_plaintext_and_carries_a_tag() {
    let (encrypted, _) = expect(encrypt_with_random_key(PLAINTEXT), "encryption failed");
    assert_ne!(encrypted.bytes.as_slice(), PLAINTEXT);
    assert_eq!(encrypted.bytes.len(), PLAINTEXT.len() + 16);
}

#[test]
fn random_key_encryption_is_randomized() {
    let (first, first_key) = expect(encrypt_with_random_key(PLAINTEXT), "encryption failed");
    let (second, second_key) = expect(encrypt_with_random_key(PLAINTEXT), "encryption failed");
    assert_ne!(first.bytes, second.bytes);
    assert_ne!(first.nonce.as_slice(), second.nonce.as_slice());
    assert_ne!(first_key.as_slice(), second_key.as_slice());
}

#[test]
fn random_key_roundtrip_empty_input() {
    let (encrypted, key) = expect(encrypt_with_random_key(b""), "encryption failed");
    let decrypted = expect(
        decrypt_with_key(&encrypted.bytes, &key, &encrypted.nonce),
        "decryption failed",
    );
    assert!(decrypted.is_empty());
}

#[test]
fn decrypt_with_wrong_key_fails() {
    let (encrypted, _) = expect(encrypt_with_random_key(PLAINTEXT), "encryption failed");
    let (_, other_key) = expect(encrypt_with_random_key(PLAINTEXT), "encryption failed");
    assert!(decrypt_with_key(&encrypted.bytes, &other_key, &encrypted.nonce).is_err());
}

#[test]
fn decrypt_with_wrong_nonce_fails() {
    let (encrypted, key) = expect(encrypt_with_random_key(PLAINTEXT), "encryption failed");
    let wrong_nonce = GcmNonce::from_slice(&[0u8; 12]);
    assert!(decrypt_with_key(&encrypted.bytes, &key, &wrong_nonce).is_err());
}

#[test]
fn tampered_ciphertext_fails_authentication() {
    let (mut encrypted, key) = expect(encrypt_with_random_key(PLAINTEXT), "encryption failed");
    encrypted.bytes[0] ^= 0x01;
    assert!(decrypt_with_key(&encrypted.bytes, &key, &encrypted.nonce).is_err());
}

#[test]
fn tampered_auth_tag_fails_authentication() {
    let (mut encrypted, key) = expect(encrypt_with_random_key(PLAINTEXT), "encryption failed");
    let last = encrypted.bytes.len() - 1;
    encrypted.bytes[last] ^= 0x01;
    assert!(decrypt_with_key(&encrypted.bytes, &key, &encrypted.nonce).is_err());
}

#[test]
fn password_roundtrip() {
    let (encrypted, salt) = expect(
        encrypt_with_password(PLAINTEXT, PASSWORD),
        "encryption failed",
    );
    let decrypted = expect(
        decrypt_with_password(&encrypted.bytes, PASSWORD, &salt, &encrypted.nonce),
        "decryption failed",
    );
    assert_eq!(decrypted, PLAINTEXT);
}

#[test]
fn password_encryption_uses_fresh_salt_and_nonce() {
    let (first, first_salt) = expect(
        encrypt_with_password(PLAINTEXT, PASSWORD),
        "encryption failed",
    );
    let (second, second_salt) = expect(
        encrypt_with_password(PLAINTEXT, PASSWORD),
        "encryption failed",
    );
    assert_ne!(first_salt.as_slice(), second_salt.as_slice());
    assert_ne!(first.nonce.as_slice(), second.nonce.as_slice());
    assert_ne!(first.bytes, second.bytes);
}

#[test]
fn decrypt_with_wrong_password_fails() {
    let (encrypted, salt) = expect(
        encrypt_with_password(PLAINTEXT, PASSWORD),
        "encryption failed",
    );
    assert!(
        decrypt_with_password(&encrypted.bytes, "wrong password", &salt, &encrypted.nonce).is_err()
    );
}

#[test]
fn decrypt_with_wrong_salt_fails() {
    let (encrypted, _) = expect(
        encrypt_with_password(PLAINTEXT, PASSWORD),
        "encryption failed",
    );
    let wrong_salt = Salt::from_slice(&[0u8; 16]);
    assert!(
        decrypt_with_password(&encrypted.bytes, PASSWORD, &wrong_salt, &encrypted.nonce).is_err()
    );
}

#[test]
fn password_roundtrip_with_empty_password() {
    let (encrypted, salt) = expect(encrypt_with_password(PLAINTEXT, ""), "encryption failed");
    let decrypted = expect(
        decrypt_with_password(&encrypted.bytes, "", &salt, &encrypted.nonce),
        "decryption failed",
    );
    assert_eq!(decrypted, PLAINTEXT);
}

#[test]
fn password_roundtrip_with_non_ascii_password() {
    let password = "パスワード🔐ünïcode";
    let (encrypted, salt) = expect(
        encrypt_with_password(PLAINTEXT, password),
        "encryption failed",
    );
    let decrypted = expect(
        decrypt_with_password(&encrypted.bytes, password, &salt, &encrypted.nonce),
        "decryption failed",
    );
    assert_eq!(decrypted, PLAINTEXT);
}

#[test]
fn kek_roundtrip_recovers_the_same_key_bytes() {
    let kek = kek_of(0xAB);
    let (_, key) = expect(encrypt_with_random_key(PLAINTEXT), "encryption failed");
    let original = *key.as_slice();

    let (wrapped, nonce) = wrap(&key, &kek);
    let recovered = expect(
        Gcm256Key::recover_with_kek(&wrapped, &kek, &nonce),
        "unwrapping failed",
    );
    assert_eq!(recovered.as_slice(), &original);
}

#[test]
fn kek_wrapped_key_still_decrypts_the_original_ciphertext() {
    let kek = kek_of(0x11);
    let (encrypted, key) = expect(encrypt_with_random_key(PLAINTEXT), "encryption failed");
    let (wrapped, wrap_nonce) = wrap(&key, &kek);
    drop(key);

    let recovered = expect(
        Gcm256Key::recover_with_kek(&wrapped, &kek, &wrap_nonce),
        "unwrapping failed",
    );
    let decrypted = expect(
        decrypt_with_key(&encrypted.bytes, &recovered, &encrypted.nonce),
        "decryption failed",
    );
    assert_eq!(decrypted, PLAINTEXT);
}

#[test]
fn kek_wrapping_never_exposes_the_raw_key_and_is_randomized() {
    let kek = kek_of(0x22);
    let (_, key) = expect(encrypt_with_random_key(PLAINTEXT), "encryption failed");
    let (first, first_nonce) = wrap(&key, &kek);
    let (second, second_nonce) = wrap(&key, &kek);

    assert_ne!(first_nonce.as_slice(), second_nonce.as_slice());
    assert_ne!(first, second);
    assert!(!first.windows(32).any(|w| w == key.as_slice()));
}

#[test]
fn recover_with_wrong_kek_fails() {
    let (_, key) = expect(encrypt_with_random_key(PLAINTEXT), "encryption failed");
    let (wrapped, nonce) = wrap(&key, &kek_of(0x33));
    assert!(Gcm256Key::recover_with_kek(&wrapped, &kek_of(0x44), &nonce).is_err());
}

#[test]
fn recover_with_wrong_nonce_fails() {
    let kek = kek_of(0x55);
    let (_, key) = expect(encrypt_with_random_key(PLAINTEXT), "encryption failed");
    let (wrapped, _) = wrap(&key, &kek);
    let wrong_nonce = GcmNonce::from_slice(&[0u8; 12]);
    assert!(Gcm256Key::recover_with_kek(&wrapped, &kek, &wrong_nonce).is_err());
}

#[test]
fn recover_with_tampered_wrapped_key_fails() {
    let kek = kek_of(0x66);
    let (_, key) = expect(encrypt_with_random_key(PLAINTEXT), "encryption failed");
    let (mut wrapped, nonce) = wrap(&key, &kek);
    wrapped[0] ^= 0x01;
    assert!(Gcm256Key::recover_with_kek(&wrapped, &kek, &nonce).is_err());
}

#[test]
fn nonce_and_salt_slices_round_trip() {
    let nonce_bytes = [9u8; 12];
    assert_eq!(GcmNonce::from_slice(&nonce_bytes).as_slice(), &nonce_bytes);
    let salt_bytes = [4u8; 16];
    assert_eq!(Salt::from_slice(&salt_bytes).as_slice(), &salt_bytes);
}
