use std::{fs::File, io::Write, process::ExitCode};

use smet::{GcmNonce, Salt};

pub fn encrypt_with_password(
    password: &str,
    bytes: &[u8],
    buffer: &mut File,
) -> Result<(), ExitCode> {
    let (encrypted_data, salt) =
        smet::encrypt_with_password(bytes, password).map_err(|_| ExitCode::FAILURE)?;
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
    let nonce = &bytes[0..12];
    let salt = &bytes[12..28];
    let plaintext = smet::decrypt_with_password(
        bytes,
        password,
        &Salt::from_slice(
            salt.try_into().map_err(|_| ExitCode::FAILURE)?, /* This Error is impossible, 16 = 16 */
        ),
        &GcmNonce::from_slice(
            nonce.try_into().map_err(|_| ExitCode::FAILURE)?, /* This Error is impossible 12 = 12 */
        ),
    )
    .map_err(|_| ExitCode::FAILURE)?;
    buffer
        .write_all(plaintext.as_slice())
        .map_err(|_| ExitCode::FAILURE)?;
    Ok(())
}
