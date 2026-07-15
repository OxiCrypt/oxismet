#![warn(clippy::pedantic)]
mod header;
mod kek;
mod passwd;
use clap::Parser;
use std::{
    fs::File,
    io::Read,
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
        long,
        help = "Password to be used for encryption/decryption, sourced from a file."
    )]
    password_file: Option<PathBuf>,
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
    let mut infile = open_file_helper(&args.file, "Error opening input file.")?;

    // Both paths need a file to output to and KEK Encrypt specifically needs outfile path, doesn't hurt
    let outfile_path = match args.output {
        Some(p) => p,
        None => output_file_generator(&args.command, &args.file)?,
    };
    let mut outfile =
        create_file_helper(&outfile_path, "Error creating output file for ciphertext.")?;

    if let Some(kek) = args.kek {
        if args.password.is_some() || args.password_file.is_some() {
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
        if args.password_file.is_some() {
            eprintln!("Fatal: Password and Password File provided");
            return Err(ExitCode::FAILURE);
        }
        match args.command {
            EncOrDec::Encrypt => {
                passwd::encrypt_with_password(&password, &mut infile, &mut outfile)
            }
            EncOrDec::Decrypt { dek_encrypted: _ } => {
                passwd::decrypt_with_password(&password, &mut infile, &mut outfile)
            }
        }
    } else if let Some(passpath) = args.password_file {
        let mut passfile = open_file_helper(&passpath, "Failed to open path to password file")?;
        let mut password = String::new();
        passfile.read_to_string(&mut password).map_err(|e| {
            eprintln!("Error reading password file: {e}");
            ExitCode::FAILURE
        })?;
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

fn open_file_helper(path: &Path, msg: &str) -> Result<File, ExitCode> {
    File::open(path).map_err(|e| {
        eprintln!("{msg}");
        eprintln!("Root Error: {e}");
        ExitCode::FAILURE
    })
}

fn create_file_helper(path: &Path, error_message: &str) -> Result<File, ExitCode> {
    File::create(path).map_err(|e| {
        eprintln!("{error_message}");
        eprintln!("Root Error: {e}");
        ExitCode::FAILURE
    })
}
