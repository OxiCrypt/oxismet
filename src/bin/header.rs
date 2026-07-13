use std::io::{Read, Write};
use std::process::ExitCode;

/// Reads exactly `N` bytes into an array, mapping any failure to a labelled CLI error.
pub fn read_field<const N: usize, R: Read>(
    reader: &mut R,
    what: &str,
) -> Result<[u8; N], ExitCode> {
    let mut buf = [0u8; N];
    reader.read_exact(&mut buf).map_err(|e| {
        eprintln!("Error: Failed to read {what}: {e}");
        ExitCode::FAILURE
    })?;
    Ok(buf)
}

/// Writes all bytes, mapping any failure to a labelled CLI error.
pub fn write_field<W: Write>(writer: &mut W, bytes: &[u8], what: &str) -> Result<(), ExitCode> {
    writer.write_all(bytes).map_err(|e| {
        eprintln!("Error: Failed to write {what} to output file: {e}");
        ExitCode::FAILURE
    })
}

/// Maps a `smet::Error` from a streaming call to a CLI error with a contextual message.
/// `context` is a noun phrase such as "encryption" or "decryption".
pub fn report_stream_error(e: smet::Error, context: &str) -> ExitCode {
    match e {
        smet::Error::InvalidChunkSize => {
            eprintln!("Error: File header declares an invalid or unsupported chunk size.");
        }
        smet::Error::Io(io) => eprintln!("Error: I/O failure during {context}: {io}"),
        _ => eprintln!("Error during {context}. No further info available."),
    }
    ExitCode::FAILURE
}
