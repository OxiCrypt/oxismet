use std::{fs::File, io::Write, process::ExitCode};

use smet::{GcmNonce, Salt};

use crate::VERSION;

pub fn encrypt_with_password(
    password: &str,
    bytes: &[u8],
    buffer: &mut File,
) -> Result<(), ExitCode> {
    let (encrypted_data, salt) =
        smet::encrypt_with_password(bytes, password).map_err(|_| ExitCode::FAILURE)?;
    buffer
        .write_all(&VERSION.to_be_bytes())
        .map_err(|_| ExitCode::FAILURE)?;
    buffer
        .write_all(encrypted_data.nonce.as_slice())
        .map_err(|_| ExitCode::FAILURE)?;
    buffer
        .write_all(salt.as_slice())
        .map_err(|_| ExitCode::FAILURE)?;
    buffer
        .write_all(&encrypted_data.bytes)
        .map_err(|_| ExitCode::FAILURE)?;
    Ok(())
}
pub fn decrypt_with_password(
    password: &str,
    bytes: &[u8],
    buffer: &mut File,
) -> Result<(), ExitCode> {
    let Some((version_bytes, rest)) = bytes.split_first_chunk::<8>() else {
        eprintln!("Error: Input file too short to contain a version header.");
        return Err(ExitCode::FAILURE);
    };
    let version = u64::from_be_bytes(*version_bytes);
    if version != VERSION {
        eprintln!("Error: Unsupported File Version: {version}.");
        return Err(ExitCode::FAILURE);
    }
    let Some((nonce_bytes, rest)) = rest.split_first_chunk::<12>() else {
        eprintln!("Error: Input file too short to contain a nonce.");
        return Err(ExitCode::FAILURE);
    };
    let Some((salt_bytes, ciphertext)) = rest.split_first_chunk::<16>() else {
        eprintln!("Error: Input file too short to contain a salt.");
        return Err(ExitCode::FAILURE);
    };
    let plaintext = smet::decrypt_with_password(
        ciphertext,
        password,
        &Salt::from_slice(salt_bytes),
        &GcmNonce::from_slice(nonce_bytes),
    )
    .map_err(|_| ExitCode::FAILURE)?;
    buffer
        .write_all(plaintext.as_slice())
        .map_err(|_| ExitCode::FAILURE)?;
    Ok(())
}
