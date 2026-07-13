use crate::VERSION;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    process::ExitCode,
};
pub fn read_kek_bytes(path: &Path) -> Result<[u8; 32], ExitCode> {
    let mut kek_bytes = [0u8; 32];
    let mut file = File::open(path).map_err(|e| {
        eprintln!("Failed to open KEK file.");
        eprintln!("Detailed Error: {e}");
        ExitCode::FAILURE
    })?;
    file.seek(SeekFrom::Start(0)).map_err(|e| {
        eprintln!("Failed to seek to start of KEK File. Error: {e}");
        ExitCode::FAILURE
    })?;
    file.read_exact(&mut kek_bytes).map_err(|e| {
        eprintln!("Error: Failed To Read File: {e}");
        ExitCode::FAILURE
    })?;
    Ok(kek_bytes)
}
pub fn encrypt_with_kek(
    bytes: &[u8],
    kek_bytes: &[u8; 32],
    input_path: &Path,
    outfile: &mut File,
) -> Result<(), ExitCode> {
    let (encrypted_data, dek) = smet::encrypt_with_random_key(bytes).map_err(|_| {
        eprintln!("Error in Encryption. No further info available.");
        ExitCode::FAILURE
    })?;
    let wrapped_dek = dek.expose_with_kek(kek_bytes).map_err(|_| {
        eprintln!("Failure while encrypting DEK with KEK. No further info available.");
        ExitCode::FAILURE
    })?;

    let mut keyout = File::create(input_path.with_added_extension("oxky")).map_err(|e| {
        eprintln!("Error creating output file for wrapped DEK: {e}");
        ExitCode::FAILURE
    })?;
    keyout.seek(SeekFrom::Start(0)).map_err(|e| {
        eprintln!("Error seeking to beginning of wrapped DEK output file: {e}");
        ExitCode::FAILURE
    })?;
    keyout.write_all(&wrapped_dek.0).map_err(|e| {
        eprintln!("Error: Failed to write Wrapped DEK to output file: {e}");
        ExitCode::FAILURE
    })?;
    keyout.write_all(wrapped_dek.1.as_slice()).map_err(|e| {
        eprintln!("Error: Failed to write Nonce of Wrapped DEK to output file: {e}");
        ExitCode::FAILURE
    })?;

    outfile.write_all(&VERSION.to_be_bytes()).map_err(|e| {
        eprintln!("Error: Failed to write version to output file: {e}");
        ExitCode::FAILURE
    })?;
    outfile
        .write_all(encrypted_data.nonce.as_slice())
        .map_err(|e| {
            eprintln!("Error: Failed to write nonce to output file: {e}");
            ExitCode::FAILURE
        })?;
    outfile.write_all(&encrypted_data.bytes).map_err(|e| {
        eprintln!("Error: Failed to write ciphertext to output file: {e}");
        ExitCode::FAILURE
    })?;
    Ok(())
}
