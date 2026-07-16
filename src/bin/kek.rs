use crate::VERSION;
use crate::header::{read_field, report_stream_error, write_field};
use smetlib::{DEFAULT_CHUNK_SIZE, GcmNonce};
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
pub fn encrypt_with_kek<R: Read, W: Write>(
    reader: &mut R,
    kek_bytes: &[u8; 32],
    output_path: &Path,
    writer: &mut W,
) -> Result<(), ExitCode> {
    let dek = smetlib::Gcm256Key::random();
    let wrapped_dek = dek.expose_with_kek(kek_bytes).map_err(|_| {
        eprintln!("Failure while encrypting DEK with KEK. No further info available.");
        ExitCode::FAILURE
    })?;

    let mut keyout = File::create(output_path.with_extension("oxky")).map_err(|e| {
        eprintln!("Error creating output file for wrapped DEK: {e}");
        ExitCode::FAILURE
    })?;
    write_field(&mut keyout, &wrapped_dek.0, "wrapped DEK")?;
    write_field(&mut keyout, wrapped_dek.1.as_slice(), "nonce of wrapped DEK")?;

    let root_nonce = GcmNonce::random();
    write_field(writer, &VERSION.to_be_bytes(), "version")?;
    write_field(writer, &DEFAULT_CHUNK_SIZE.to_be_bytes(), "chunk size")?;
    write_field(writer, root_nonce.as_slice(), "root nonce")?;

    smetlib::encrypt_stream(reader, writer, &dek, &root_nonce, DEFAULT_CHUNK_SIZE)
        .map_err(|e| report_stream_error(e, "encryption"))
}
fn read_wrapped_dek(path: &Path) -> Result<([u8; 48], [u8; 12]), ExitCode> {
    let mut keyfile = File::open(path).map_err(|e| {
        eprintln!("Error: Failed to open encrypted DEK file: {e}");
        ExitCode::FAILURE
    })?;
    let wrapped_dek = read_field::<48, _>(&mut keyfile, "wrapped DEK")?;
    let dek_nonce = read_field::<12, _>(&mut keyfile, "nonce of wrapped DEK")?;
    Ok((wrapped_dek, dek_nonce))
}

pub fn decrypt_with_kek<R: Read, W: Write>(
    reader: &mut R,
    kek_bytes: &[u8; 32],
    dek_encrypted: Option<PathBuf>,
    writer: &mut W,
) -> Result<(), ExitCode> {
    let Some(dek_path) = dek_encrypted else {
        // Already validated before opening the input file; kept so this match arm is total.
        eprintln!("Error: dek_encrypted must be provided when using a KEK for decryption.");
        return Err(ExitCode::FAILURE);
    };
    let (wrapped_dek, dek_nonce) = read_wrapped_dek(&dek_path)?;

    let dek = smetlib::Gcm256Key::recover_with_kek(
        &wrapped_dek,
        kek_bytes,
        &GcmNonce::from_slice(&dek_nonce),
    )
    .map_err(|_| {
        eprintln!("Error: Failed to unwrap DEK with KEK. No further info available.");
        ExitCode::FAILURE
    })?;

    let version = u64::from_be_bytes(read_field::<8, _>(reader, "version header")?);
    match version {
        1 => {
            let chunk_size = u32::from_be_bytes(read_field::<4, _>(reader, "chunk size")?);
            let root_nonce = GcmNonce::from_slice(&read_field::<12, _>(reader, "root nonce")?);
            smetlib::decrypt_stream(reader, writer, &dek, &root_nonce, chunk_size)
                .map_err(|e| report_stream_error(e, "decryption"))
        }
        0 => decrypt_v0(reader, writer, &dek),
        other => {
            eprintln!("Error: Unsupported file version {other}. This build supports version {VERSION}.");
            Err(ExitCode::FAILURE)
        }
    }
}

/// Decrypts a legacy version-0 (single-blob) KEK file: 12-byte nonce followed by the
/// whole ciphertext. Kept so files written by pre-streaming releases still decrypt.
fn decrypt_v0<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    dek: &smetlib::Gcm256Key,
) -> Result<(), ExitCode> {
    let nonce = GcmNonce::from_slice(&read_field::<12, _>(reader, "nonce")?);
    let mut ciphertext = Vec::new();
    reader.read_to_end(&mut ciphertext).map_err(|e| {
        eprintln!("Error: Failed to read ciphertext: {e}");
        ExitCode::FAILURE
    })?;
    let plaintext = smetlib::decrypt_with_key(&ciphertext, dek, &nonce).map_err(|_| {
        eprintln!("Error in Decryption. No further info available.");
        ExitCode::FAILURE
    })?;
    write_field(writer, &plaintext, "plaintext")
}
