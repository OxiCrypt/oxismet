use super::{
    DEFAULT_CHUNK_SIZE, Error, Gcm256Key, GcmNonce, MAX_CHUNK_SIZE, Salt, decrypt_stream,
    decrypt_with_key, decrypt_with_password, derive_key_from_password, encrypt_stream,
    encrypt_with_password, encrypt_with_random_key,
};
use std::io::Cursor;

const PLAINTEXT: &[u8] = b"the treaty of westphalia was signed in 1648";
const PASSWORD: &str = "correct horse battery staple";

/// Deterministic pseudo-plaintext of a given length.
fn plaintext_of(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).expect("i % 251 always fits in u8"))
        .collect()
}

/// Encrypts `plaintext` into an in-memory chunk stream, returning the ciphertext and the
/// key/root-nonce needed to decrypt it.
fn encrypt_stream_to_vec(plaintext: &[u8], chunk_size: u32) -> (Vec<u8>, Gcm256Key, GcmNonce) {
    let key = Gcm256Key::random();
    let root = GcmNonce::random();
    let mut ciphertext = Vec::new();
    encrypt_stream(
        &mut Cursor::new(plaintext),
        &mut ciphertext,
        &key,
        &root,
        chunk_size,
    )
    .expect("stream encryption failed");
    (ciphertext, key, root)
}

fn kek_of(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn wrap(key: &Gcm256Key, kek: &[u8; 32]) -> ([u8; 48], GcmNonce) {
    let (wrapped, nonce) = key.expose_with_kek(kek).expect("wrapping failed");
    let wrapped = wrapped.try_into().expect("wrapped DEK should be 48 bytes");
    (wrapped, nonce)
}

#[test]
fn random_key_roundtrip() {
    let (encrypted, key) = encrypt_with_random_key(PLAINTEXT).expect("encryption failed");
    let decrypted =
        decrypt_with_key(&encrypted.bytes, &key, &encrypted.nonce).expect("decryption failed");
    assert_eq!(decrypted, PLAINTEXT);
}

#[test]
fn random_key_ciphertext_hides_plaintext_and_carries_a_tag() {
    let (encrypted, _) = encrypt_with_random_key(PLAINTEXT).expect("encryption failed");
    assert_ne!(encrypted.bytes.as_slice(), PLAINTEXT);
    assert_eq!(encrypted.bytes.len(), PLAINTEXT.len() + 16);
}

#[test]
fn random_key_encryption_is_randomized() {
    let (first, first_key) = encrypt_with_random_key(PLAINTEXT).expect("encryption failed");
    let (second, second_key) = encrypt_with_random_key(PLAINTEXT).expect("encryption failed");
    assert_ne!(first.bytes, second.bytes);
    assert_ne!(first.nonce.as_slice(), second.nonce.as_slice());
    assert_ne!(first_key.as_slice(), second_key.as_slice());
}

#[test]
fn random_key_roundtrip_empty_input() {
    let (encrypted, key) = encrypt_with_random_key(b"").expect("encryption failed");
    let decrypted =
        decrypt_with_key(&encrypted.bytes, &key, &encrypted.nonce).expect("decryption failed");
    assert!(decrypted.is_empty());
}

#[test]
fn decrypt_with_wrong_key_fails() {
    let (encrypted, _) = encrypt_with_random_key(PLAINTEXT).expect("encryption failed");
    let (_, other_key) = encrypt_with_random_key(PLAINTEXT).expect("encryption failed");
    assert!(decrypt_with_key(&encrypted.bytes, &other_key, &encrypted.nonce).is_err());
}

#[test]
fn decrypt_with_wrong_nonce_fails() {
    let (encrypted, key) = encrypt_with_random_key(PLAINTEXT).expect("encryption failed");
    let wrong_nonce = GcmNonce::from_slice(&[0u8; 12]);
    assert!(decrypt_with_key(&encrypted.bytes, &key, &wrong_nonce).is_err());
}

#[test]
fn tampered_ciphertext_fails_authentication() {
    let (mut encrypted, key) = encrypt_with_random_key(PLAINTEXT).expect("encryption failed");
    encrypted.bytes[0] ^= 0x01;
    assert!(decrypt_with_key(&encrypted.bytes, &key, &encrypted.nonce).is_err());
}

#[test]
fn tampered_auth_tag_fails_authentication() {
    let (mut encrypted, key) = encrypt_with_random_key(PLAINTEXT).expect("encryption failed");
    let last = encrypted.bytes.len() - 1;
    encrypted.bytes[last] ^= 0x01;
    assert!(decrypt_with_key(&encrypted.bytes, &key, &encrypted.nonce).is_err());
}

#[test]
fn password_roundtrip() {
    let (encrypted, salt) = encrypt_with_password(PLAINTEXT, PASSWORD).expect("encryption failed");
    let decrypted = decrypt_with_password(&encrypted.bytes, PASSWORD, &salt, &encrypted.nonce)
        .expect("decryption failed");
    assert_eq!(decrypted, PLAINTEXT);
}

#[test]
fn password_encryption_uses_fresh_salt_and_nonce() {
    let (first, first_salt) = encrypt_with_password(PLAINTEXT, PASSWORD).expect("encryption failed");
    let (second, second_salt) =
        encrypt_with_password(PLAINTEXT, PASSWORD).expect("encryption failed");
    assert_ne!(first_salt.as_slice(), second_salt.as_slice());
    assert_ne!(first.nonce.as_slice(), second.nonce.as_slice());
    assert_ne!(first.bytes, second.bytes);
}

#[test]
fn decrypt_with_wrong_password_fails() {
    let (encrypted, salt) = encrypt_with_password(PLAINTEXT, PASSWORD).expect("encryption failed");
    assert!(
        decrypt_with_password(&encrypted.bytes, "wrong password", &salt, &encrypted.nonce).is_err()
    );
}

#[test]
fn decrypt_with_wrong_salt_fails() {
    let (encrypted, _) = encrypt_with_password(PLAINTEXT, PASSWORD).expect("encryption failed");
    let wrong_salt = Salt::from_slice(&[0u8; 16]);
    assert!(
        decrypt_with_password(&encrypted.bytes, PASSWORD, &wrong_salt, &encrypted.nonce).is_err()
    );
}

#[test]
fn password_roundtrip_with_empty_password() {
    let (encrypted, salt) = encrypt_with_password(PLAINTEXT, "").expect("encryption failed");
    let decrypted = decrypt_with_password(&encrypted.bytes, "", &salt, &encrypted.nonce)
        .expect("decryption failed");
    assert_eq!(decrypted, PLAINTEXT);
}

#[test]
fn password_roundtrip_with_non_ascii_password() {
    let password = "パスワード🔐ünïcode";
    let (encrypted, salt) = encrypt_with_password(PLAINTEXT, password).expect("encryption failed");
    let decrypted = decrypt_with_password(&encrypted.bytes, password, &salt, &encrypted.nonce)
        .expect("decryption failed");
    assert_eq!(decrypted, PLAINTEXT);
}

#[test]
fn kek_roundtrip_recovers_the_same_key_bytes() {
    let kek = kek_of(0xAB);
    let (_, key) = encrypt_with_random_key(PLAINTEXT).expect("encryption failed");
    let original = *key.as_slice();

    let (wrapped, nonce) = wrap(&key, &kek);
    let recovered = Gcm256Key::recover_with_kek(&wrapped, &kek, &nonce).expect("unwrapping failed");
    assert_eq!(recovered.as_slice(), &original);
}

#[test]
fn kek_wrapped_key_still_decrypts_the_original_ciphertext() {
    let kek = kek_of(0x11);
    let (encrypted, key) = encrypt_with_random_key(PLAINTEXT).expect("encryption failed");
    let (wrapped, wrap_nonce) = wrap(&key, &kek);
    drop(key);

    let recovered =
        Gcm256Key::recover_with_kek(&wrapped, &kek, &wrap_nonce).expect("unwrapping failed");
    let decrypted =
        decrypt_with_key(&encrypted.bytes, &recovered, &encrypted.nonce).expect("decryption failed");
    assert_eq!(decrypted, PLAINTEXT);
}

#[test]
fn kek_wrapping_never_exposes_the_raw_key_and_is_randomized() {
    let kek = kek_of(0x22);
    let (_, key) = encrypt_with_random_key(PLAINTEXT).expect("encryption failed");
    let (first, first_nonce) = wrap(&key, &kek);
    let (second, second_nonce) = wrap(&key, &kek);

    assert_ne!(first_nonce.as_slice(), second_nonce.as_slice());
    assert_ne!(first, second);
    assert!(!first.windows(32).any(|w| w == key.as_slice()));
}

#[test]
fn recover_with_wrong_kek_fails() {
    let (_, key) = encrypt_with_random_key(PLAINTEXT).expect("encryption failed");
    let (wrapped, nonce) = wrap(&key, &kek_of(0x33));
    assert!(Gcm256Key::recover_with_kek(&wrapped, &kek_of(0x44), &nonce).is_err());
}

#[test]
fn recover_with_wrong_nonce_fails() {
    let kek = kek_of(0x55);
    let (_, key) = encrypt_with_random_key(PLAINTEXT).expect("encryption failed");
    let (wrapped, _) = wrap(&key, &kek);
    let wrong_nonce = GcmNonce::from_slice(&[0u8; 12]);
    assert!(Gcm256Key::recover_with_kek(&wrapped, &kek, &wrong_nonce).is_err());
}

#[test]
fn recover_with_tampered_wrapped_key_fails() {
    let kek = kek_of(0x66);
    let (_, key) = encrypt_with_random_key(PLAINTEXT).expect("encryption failed");
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

const TEST_CHUNK: u32 = 64;
/// On-disk size of a full chunk: plaintext chunk + 16-byte GCM tag.
const FULL_CHUNK_ON_DISK: usize = TEST_CHUNK as usize + 16;

#[test]
fn stream_roundtrip_various_sizes() {
    // empty, sub-chunk, exactly one chunk, one-past-a-chunk, several full chunks, and a
    // multiple-plus-partial case.
    for len in [
        0,
        1,
        TEST_CHUNK as usize - 1,
        TEST_CHUNK as usize,
        TEST_CHUNK as usize + 1,
        4 * TEST_CHUNK as usize,
        4 * TEST_CHUNK as usize + 7,
    ] {
        let plaintext = plaintext_of(len);
        let (ciphertext, key, root) = encrypt_stream_to_vec(&plaintext, TEST_CHUNK);
        let mut decrypted = Vec::new();
        decrypt_stream(
            &mut Cursor::new(ciphertext),
            &mut decrypted,
            &key,
            &root,
            TEST_CHUNK,
        )
        .expect("stream decryption failed");
        assert_eq!(decrypted, plaintext, "roundtrip mismatch at len {len}");
    }
}

#[test]
fn stream_empty_input_produces_a_single_final_chunk() {
    let (ciphertext, _, _) = encrypt_stream_to_vec(b"", TEST_CHUNK);
    // One empty plaintext chunk sealed => exactly one 16-byte tag on disk.
    assert_eq!(ciphertext.len(), 16);
}

#[test]
fn stream_ciphertext_differs_from_plaintext() {
    let plaintext = plaintext_of(200);
    let (ciphertext, _, _) = encrypt_stream_to_vec(&plaintext, TEST_CHUNK);
    assert!(!ciphertext.windows(plaintext.len()).any(|w| w == plaintext));
}

#[test]
fn stream_tampered_middle_chunk_fails() {
    let plaintext = plaintext_of(4 * TEST_CHUNK as usize);
    let (mut ciphertext, key, root) = encrypt_stream_to_vec(&plaintext, TEST_CHUNK);
    // Flip a byte inside the second on-disk chunk.
    ciphertext[FULL_CHUNK_ON_DISK + 5] ^= 0x01;
    let mut sink = Vec::new();
    assert!(
        decrypt_stream(&mut Cursor::new(ciphertext), &mut sink, &key, &root, TEST_CHUNK).is_err()
    );
}

#[test]
fn stream_truncated_final_chunk_fails() {
    // Exactly four full chunks; drop the last on-disk chunk entirely.
    let plaintext = plaintext_of(4 * TEST_CHUNK as usize);
    let (mut ciphertext, key, root) = encrypt_stream_to_vec(&plaintext, TEST_CHUNK);
    ciphertext.truncate(ciphertext.len() - FULL_CHUNK_ON_DISK);
    let mut sink = Vec::new();
    // The new last chunk was sealed with is_final=false, so opening it with is_final=true fails.
    assert!(
        decrypt_stream(&mut Cursor::new(ciphertext), &mut sink, &key, &root, TEST_CHUNK).is_err()
    );
}

#[test]
fn stream_swapped_chunks_fail() {
    let plaintext = plaintext_of(4 * TEST_CHUNK as usize);
    let (mut ciphertext, key, root) = encrypt_stream_to_vec(&plaintext, TEST_CHUNK);
    // Swap the first two on-disk chunks; their bound counters no longer match position.
    let (first, rest) = ciphertext.split_at_mut(FULL_CHUNK_ON_DISK);
    first.swap_with_slice(&mut rest[..FULL_CHUNK_ON_DISK]);
    let mut sink = Vec::new();
    assert!(
        decrypt_stream(&mut Cursor::new(ciphertext), &mut sink, &key, &root, TEST_CHUNK).is_err()
    );
}

#[test]
fn stream_wrong_key_fails() {
    let plaintext = plaintext_of(200);
    let (ciphertext, _, root) = encrypt_stream_to_vec(&plaintext, TEST_CHUNK);
    let wrong_key = Gcm256Key::random();
    let mut sink = Vec::new();
    assert!(
        decrypt_stream(
            &mut Cursor::new(ciphertext),
            &mut sink,
            &wrong_key,
            &root,
            TEST_CHUNK
        )
        .is_err()
    );
}

#[test]
fn decrypt_stream_rejects_invalid_chunk_size() {
    let key = Gcm256Key::random();
    let root = GcmNonce::random();
    for bad in [0, MAX_CHUNK_SIZE + 1] {
        let mut sink = Vec::new();
        let err = decrypt_stream(&mut Cursor::new(vec![0u8; 16]), &mut sink, &key, &root, bad)
            .expect_err("should reject invalid chunk size");
        assert!(matches!(err, Error::InvalidChunkSize));
    }
}

#[test]
fn stream_roundtrip_at_default_chunk_size() {
    // A payload larger than one 32 MiB chunk exercises the real default multi-chunk path.
    let plaintext = plaintext_of(DEFAULT_CHUNK_SIZE as usize + 1024);
    let (ciphertext, key, root) = encrypt_stream_to_vec(&plaintext, DEFAULT_CHUNK_SIZE);
    let mut decrypted = Vec::new();
    decrypt_stream(
        &mut Cursor::new(ciphertext),
        &mut decrypted,
        &key,
        &root,
        DEFAULT_CHUNK_SIZE,
    )
    .expect("stream decryption failed");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn derive_key_from_password_is_deterministic_and_salt_dependent() {
    let salt = Salt::from_slice(&[7u8; 16]);
    let a = derive_key_from_password(PASSWORD, &salt).expect("derive failed");
    let b = derive_key_from_password(PASSWORD, &salt).expect("derive failed");
    assert_eq!(a.as_slice(), b.as_slice());

    let other_salt = Salt::from_slice(&[8u8; 16]);
    let c = derive_key_from_password(PASSWORD, &other_salt).expect("derive failed");
    assert_ne!(a.as_slice(), c.as_slice());
}

#[test]
fn random_constructors_produce_distinct_values() {
    assert_ne!(Gcm256Key::random().as_slice(), Gcm256Key::random().as_slice());
    assert_ne!(GcmNonce::random().as_slice(), GcmNonce::random().as_slice());
    assert_ne!(Salt::random().as_slice(), Salt::random().as_slice());
}
