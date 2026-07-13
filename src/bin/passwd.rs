use std::io::{Read, Write};
use std::process::ExitCode;

use smet::{DEFAULT_CHUNK_SIZE, GcmNonce, Salt};

use crate::VERSION;
use crate::header::{read_field, report_stream_error, write_field};

pub fn encrypt_with_password<R: Read, W: Write>(
    password: &str,
    reader: &mut R,
    writer: &mut W,
) -> Result<(), ExitCode> {
    let salt = Salt::random();
    let key = smet::derive_key_from_password(password, &salt).map_err(|_| {
        eprintln!("Error deriving key from password. No further info available.");
        ExitCode::FAILURE
    })?;
    let root_nonce = GcmNonce::random();

    write_field(writer, &VERSION.to_be_bytes(), "version")?;
    write_field(writer, &DEFAULT_CHUNK_SIZE.to_be_bytes(), "chunk size")?;
    write_field(writer, root_nonce.as_slice(), "root nonce")?;
    write_field(writer, salt.as_slice(), "salt")?;

    smet::encrypt_stream(reader, writer, &key, &root_nonce, DEFAULT_CHUNK_SIZE)
        .map_err(|e| report_stream_error(e, "encryption"))
}
pub fn decrypt_with_password<R: Read, W: Write>(
    password: &str,
    reader: &mut R,
    writer: &mut W,
) -> Result<(), ExitCode> {
    let version = u64::from_be_bytes(read_field::<8, _>(reader, "version header")?);
    match version {
        1 => {
            let chunk_size = u32::from_be_bytes(read_field::<4, _>(reader, "chunk size")?);
            let root_nonce = GcmNonce::from_slice(&read_field::<12, _>(reader, "root nonce")?);
            let salt = Salt::from_slice(&read_field::<16, _>(reader, "salt")?);
            let key = smet::derive_key_from_password(password, &salt).map_err(|_| {
                eprintln!("Error deriving key from password. No further info available.");
                ExitCode::FAILURE
            })?;
            smet::decrypt_stream(reader, writer, &key, &root_nonce, chunk_size)
                .map_err(|e| report_stream_error(e, "decryption"))
        }
        0 => decrypt_v0(password, reader, writer),
        other => {
            eprintln!("Error: Unsupported File Version: {other}.");
            Err(ExitCode::FAILURE)
        }
    }
}

/// Decrypts a legacy version-0 (single-blob) password file: 12-byte nonce, 16-byte salt,
/// then the whole ciphertext. Kept so files written by pre-streaming releases still decrypt.
fn decrypt_v0<R: Read, W: Write>(
    password: &str,
    reader: &mut R,
    writer: &mut W,
) -> Result<(), ExitCode> {
    let nonce = GcmNonce::from_slice(&read_field::<12, _>(reader, "nonce")?);
    let salt = Salt::from_slice(&read_field::<16, _>(reader, "salt")?);
    let mut ciphertext = Vec::new();
    reader.read_to_end(&mut ciphertext).map_err(|e| {
        eprintln!("Error: Failed to read ciphertext: {e}");
        ExitCode::FAILURE
    })?;
    let plaintext =
        smet::decrypt_with_password(&ciphertext, password, &salt, &nonce).map_err(|_| {
            eprintln!("Error in Decryption. No further info available.");
            ExitCode::FAILURE
        })?;
    write_field(writer, &plaintext, "plaintext")
}
