#![warn(clippy::pedantic)]
mod header;
mod kek;
mod passwd;
use clap::Parser;
use std::{
    fs::File,
    path::{Path, PathBuf},
    process::ExitCode,
};

/// On-disk format version this build writes. Decryption also accepts version 0
/// (the legacy single-blob format) for backward compatibility.
const VERSION: u64 = 1;
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

fn output_file_generator(command: &EncOrDec, input_path: &Path) -> Result<PathBuf, ExitCode> {
    match command {
        EncOrDec::Encrypt => Ok(input_path.with_added_extension("smet")),
        EncOrDec::Decrypt { dek_encrypted: _ } => {
            if let Some(ext) = input_path.extension()
                && ext.to_str() == Some("smet")
            {
                Ok(input_path.with_extension(""))
            } else {
                eprintln!(
                    "Error: No output file provided for Decrypt mode, and input is not a .smet file!"
                );
                Err(ExitCode::FAILURE)
            }
        }
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

    // The input is streamed chunk-by-chunk, so open it as a reader rather than slurping it.
    let mut infile = open_input_file(&args.file)?;

    // Both paths need a file to output to and KEK Encrypt specifically needs outfile path, doesn't hurt
    let outfile_path = match args.output {
        Some(p) => p,
        None => output_file_generator(&args.command, &args.file)?,
    };
    let mut outfile = create_output_file(&outfile_path)?;

    if let Some(kek) = args.kek {
        if args.password.is_some() {
            eprintln!("Fatal: Password and KEK provided");
            return Err(ExitCode::FAILURE);
        }
        let kek_bytes = kek::read_kek_bytes(&kek)?;

        match args.command {
            EncOrDec::Encrypt => {
                kek::encrypt_with_kek(&mut infile, &kek_bytes, &outfile_path, &mut outfile)
            }
            EncOrDec::Decrypt { dek_encrypted } => {
                kek::decrypt_with_kek(&mut infile, &kek_bytes, dek_encrypted, &mut outfile)
            }
        }
    } else if let Some(password) = args.password {
        match args.command {
            EncOrDec::Encrypt => {
                passwd::encrypt_with_password(&password, &mut infile, &mut outfile)
            }
            EncOrDec::Decrypt { dek_encrypted: _ } => {
                passwd::decrypt_with_password(&password, &mut infile, &mut outfile)
            }
        }
    } else {
        eprintln!("Must provide Password or KEK to proceed.");
        Err(ExitCode::FAILURE)
    }
}

fn open_input_file(path: &Path) -> Result<File, ExitCode> {
    File::open(path).map_err(|e| {
        eprintln!("Error: Failed to open input file: {e}");
        ExitCode::FAILURE
    })
}

fn create_output_file(path: &Path) -> Result<File, ExitCode> {
    File::create(path).map_err(|e| {
        eprintln!("Error creating output file for ciphertext: {e}");
        ExitCode::FAILURE
    })
}
