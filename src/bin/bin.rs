#![warn(clippy::pedantic)]
mod kek;
mod passwd;
use clap::Parser;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    process::ExitCode,
};

const VERSION: u64 = 0;
#[derive(Parser)]
#[command(name = "oxismet", about = "A Headless Encryption Tool for Servers.")]
#[command(author, version)]
struct OxiSmet {
    #[arg(short, long, help = "Password to be used for encryption/decryption.")]
    password: Option<String>,
    #[arg(
        short,
        long,
        help = "Path to Key Encryption Key to be used for encryption/decryption."
    )]
    kek: Option<PathBuf>,
    #[arg(short, long, help = "Path to the file to be encrypted/decrypted.")]
    file: PathBuf,
    #[arg(short, long, help = "Path to the output file.")]
    output: Option<PathBuf>,
    #[clap(subcommand)]
    command: EncOrDec,
}

#[derive(Parser)]
enum EncOrDec {
    Encrypt,
    Decrypt {
        /// Path to the encrypted DEK to be used for decryption. Ignored in password mode.
        dek_encrypted: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    match run(OxiSmet::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

fn run(args: OxiSmet) -> Result<(), ExitCode> {
    if let EncOrDec::Decrypt { dek_encrypted } = &args.command
        && args.kek.is_some()
        && dek_encrypted.is_none()
    {
        eprintln!("Error: dek_encrypted must be provided when using a KEK for decryption.");
        return Err(ExitCode::FAILURE);
    }

    // Both paths need the bytes of the input file
    let bytes = read_input_file(&args.file)?;

    // Both paths need a file to output to
    let mut outfile = create_output_file(
        args.output
            .unwrap_or_else(|| args.file.with_added_extension("smet")),
    )?;

    if let Some(kek) = args.kek {
        if args.password.is_some() {
            eprintln!("Fatal: Password and KEK provided");
            return Err(ExitCode::FAILURE);
        }
        let kek_bytes = kek::read_kek_bytes(&kek)?;

        match args.command {
            EncOrDec::Encrypt => {
                kek::encrypt_with_kek(&bytes, &kek_bytes, &args.file, &mut outfile)
            }
            EncOrDec::Decrypt { dek_encrypted } => {
                kek::decrypt_with_kek(&bytes, &kek_bytes, dek_encrypted, &mut outfile)
            }
        }
    } else if let Some(password) = args.password {
        match args.command {
            EncOrDec::Encrypt => {
                passwd::encrypt_with_password(&password, bytes.as_slice(), &mut outfile)
            }
            EncOrDec::Decrypt { dek_encrypted: _ } => {
                passwd::decrypt_with_password(&password, bytes.as_slice(), &mut outfile)
            }
        }
    } else {
        eprintln!("Must provide Password or KEK to proceed.");
        Err(ExitCode::FAILURE)
    }
}

fn read_input_file(path: &Path) -> Result<Vec<u8>, ExitCode> {
    let mut bytes: Vec<u8> = Vec::new();
    let mut file = File::open(path).map_err(|e| {
        eprintln!("Error: Failed to read input File: {e}");
        ExitCode::FAILURE
    })?;
    file.seek(SeekFrom::Start(0)).map_err(|e| {
        eprintln!("Error: Failed to seek to beginning of input file: {e}");
        ExitCode::FAILURE
    })?;
    file.read_to_end(&mut bytes).map_err(|e| {
        eprintln!("Error: Failed to read input file: {e}");
        ExitCode::FAILURE
    })?;
    Ok(bytes)
}

fn create_output_file(path: PathBuf) -> Result<File, ExitCode> {
    let mut outfile = File::create(path).map_err(|e| {
        eprintln!("Error creating output file for ciphertext: {e}");
        ExitCode::FAILURE
    })?;
    outfile.seek(SeekFrom::Start(0)).map_err(|e| {
        eprintln!("Error seeking to beginning of output file: {e}");
        ExitCode::FAILURE
    })?;
    Ok(outfile)
}
