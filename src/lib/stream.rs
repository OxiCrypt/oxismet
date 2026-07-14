use aes_gcm::{
    Aes256Gcm, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use std::io::{Read, Write};

use crate::{Error, Gcm256Key, GcmNonce, MAX_CHUNK_SIZE, TAG_LEN};

/// Encodes a block counter into the low 8 bytes of a 12-byte array (big-endian).
/// Used both as the per-chunk nonce offset (XOR-ed into the root nonce) and as the
/// leading 12 bytes of the per-chunk associated data.
fn counter_to_bytes(counter: u64) -> [u8; 12] {
    let mut bytes = [0u8; 12];
    bytes[4..].copy_from_slice(&counter.to_be_bytes());
    bytes
}
/// Per-chunk nonce = root nonce XOR the counter bytes. XOR is a bijection, so distinct
/// counters yield distinct nonces within a file.
fn chunk_nonce(root: &GcmNonce, counter: u64) -> GcmNonce {
    let offset = counter_to_bytes(counter);
    let mut bytes = *root.as_slice();
    bytes
        .iter_mut()
        .zip(offset.iter())
        .for_each(|(b, o)| *b ^= *o);
    GcmNonce::from_slice(&bytes)
}
/// Per-chunk associated data = counter bytes (12) followed by the `is_final` flag (1).
/// Binding both into the tag prevents chunk reordering/swapping and, via `is_final`,
/// silent truncation of trailing chunks (the STREAM construction).
fn chunk_aad(counter: u64, is_final: bool) -> [u8; 13] {
    let mut aad = [0u8; 13];
    aad[..12].copy_from_slice(&counter_to_bytes(counter));
    aad[12] = u8::from(is_final);
    aad
}
/// Reads up to `buf.len()` bytes, looping until the buffer is full or EOF is reached,
/// then truncates to what was actually read. A returned length shorter than the buffer
/// therefore reliably signals EOF, which the streaming loops use to detect the last chunk.
fn fill_chunk<R: Read>(reader: &mut R, mut buf: Vec<u8>) -> Result<Vec<u8>, Error> {
    let capacity = buf.len();
    let mut filled = 0;
    while filled < capacity {
        let n = reader.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    buf.truncate(filled);
    Ok(buf)
}
/// Encrypts `reader` to `writer` as a sequence of independently sealed chunks.
///
/// Each chunk of at most `chunk_size` plaintext bytes is sealed with AES-256-GCM under
/// `key`, using a per-chunk nonce derived from `root_nonce` and the block counter, with
/// the counter and an `is_final` flag bound into the associated data. There is always at
/// least one chunk (empty input produces a single empty final chunk), so the final chunk
/// is unambiguous on decryption.
///
/// The caller is responsible for writing the file header (version, `chunk_size`,
/// `root_nonce`, and any salt) before calling this. `root_nonce` must be unique per file.
/// # Errors
/// Returns `Error::Io` on a read/write failure or `Error::Aes` if sealing fails.
pub fn encrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    key: &Gcm256Key,
    root_nonce: &GcmNonce,
    chunk_size: u32,
) -> Result<(), Error> {
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key.as_slice()));
    let size = chunk_size as usize;
    let mut counter: u64 = 0;
    let mut current = fill_chunk(reader, vec![0u8; size])?;
    loop {
        let next = fill_chunk(reader, vec![0u8; size])?;
        let is_final = next.is_empty();
        let nonce = chunk_nonce(root_nonce, counter);
        let aad = chunk_aad(counter, is_final);
        let sealed = cipher.encrypt(
            &Nonce::from(*nonce.as_slice()),
            Payload {
                msg: &current,
                aad: &aad,
            },
        )?;
        writer.write_all(&sealed)?;
        counter += 1;
        if is_final {
            break;
        }
        current = next;
    }
    Ok(())
}
/// Decrypts a chunk stream produced by `encrypt_stream` from `reader` to `writer`.
///
/// `chunk_size` is the plaintext chunk size read from the file header; each on-disk chunk
/// is therefore at most `chunk_size + TAG_LEN` bytes. The final chunk is detected by EOF
/// and verified with `is_final = true`, so truncation of trailing chunks fails the tag.
/// # Errors
/// Returns `Error::InvalidChunkSize` if `chunk_size` is zero or exceeds `MAX_CHUNK_SIZE`,
/// `Error::Io` on a read/write failure, or `Error::Aes` if any chunk fails authentication
/// (wrong key, tampering, reordering, or truncation).
pub fn decrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    key: &Gcm256Key,
    root_nonce: &GcmNonce,
    chunk_size: u32,
) -> Result<(), Error> {
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return Err(Error::InvalidChunkSize);
    }
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key.as_slice()));
    let size = chunk_size as usize + TAG_LEN;
    let mut counter: u64 = 0;
    let mut current = fill_chunk(reader, vec![0u8; size])?;
    loop {
        let next = fill_chunk(reader, vec![0u8; size])?;
        let is_final = next.is_empty();
        let nonce = chunk_nonce(root_nonce, counter);
        let aad = chunk_aad(counter, is_final);
        let plaintext = cipher.decrypt(
            &Nonce::from(*nonce.as_slice()),
            Payload {
                msg: &current,
                aad: &aad,
            },
        )?;
        writer.write_all(&plaintext)?;
        counter += 1;
        if is_final {
            break;
        }
        current = next;
    }
    Ok(())
}
