use crate::VERSION;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
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
fn read_wrapped_dek(path: &Path) -> Result<([u8; 48], [u8; 12]), ExitCode> {
    let mut wrapped_dek = [0u8; 48];
    let mut dek_nonce = [0u8; 12];
    let mut keyfile = File::open(path).map_err(|e| {
        eprintln!("Error: Failed to open encrypted DEK file: {e}");
        ExitCode::FAILURE
    })?;
    keyfile.seek(SeekFrom::Start(0)).map_err(|e| {
        eprintln!("Error: Failed to seek to beginning of encrypted DEK file: {e}");
        ExitCode::FAILURE
    })?;
    keyfile.read_exact(&mut wrapped_dek).map_err(|e| {
        eprintln!("Error: Failed to read wrapped DEK: {e}");
        ExitCode::FAILURE
    })?;
    keyfile.read_exact(&mut dek_nonce).map_err(|e| {
        eprintln!("Error: Failed to read nonce of wrapped DEK: {e}");
        ExitCode::FAILURE
    })?;
    Ok((wrapped_dek, dek_nonce))
}

pub fn decrypt_with_kek(
    bytes: &[u8],
    kek_bytes: &[u8; 32],
    dek_encrypted: Option<PathBuf>,
    outfile: &mut File,
) -> Result<(), ExitCode> {
    let Some(dek_path) = dek_encrypted else {
        // Already validated before reading the input file; kept so this match arm is total.
        eprintln!("Error: dek_encrypted must be provided when using a KEK for decryption.");
        return Err(ExitCode::FAILURE);
    };
    let (wrapped_dek, dek_nonce) = read_wrapped_dek(&dek_path)?;

    let dek = smet::Gcm256Key::recover_with_kek(
        &wrapped_dek,
        kek_bytes,
        &smet::GcmNonce::from_slice(&dek_nonce),
    )
    .map_err(|_| {
        eprintln!("Error: Failed to unwrap DEK with KEK. No further info available.");
        ExitCode::FAILURE
    })?;

    let Some((version_bytes, rest)) = bytes.split_first_chunk::<8>() else {
        eprintln!("Error: Input file too short to contain a version header.");
        return Err(ExitCode::FAILURE);
    };
    if *version_bytes != VERSION.to_be_bytes() {
        eprintln!(
            "Error: Unsupported file version {}. This build supports version {VERSION}.",
            u64::from_be_bytes(*version_bytes)
        );
        return Err(ExitCode::FAILURE);
    }
    let Some((nonce_bytes, ciphertext)) = rest.split_first_chunk::<12>() else {
        eprintln!("Error: Input file too short to contain a nonce.");
        return Err(ExitCode::FAILURE);
    };
    let plaintext =
        smet::decrypt_with_key(ciphertext, &dek, &smet::GcmNonce::from_slice(nonce_bytes))
            .map_err(|_| {
                eprintln!("Error in Decryption. No further info available.");
                ExitCode::FAILURE
            })?;
    outfile.write_all(&plaintext).map_err(|e| {
        eprintln!("Error: Failed to write plaintext to output file: {e}");
        ExitCode::FAILURE
    })?;
    Ok(())
}
