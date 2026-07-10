#![warn(clippy::pedantic)]
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use argon2::{Algorithm::Argon2id, Argon2, ParamsBuilder, Version::V0x13};
use rand::{RngExt, rng};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::Error::ConversionError;
const MEM_COST: u32 = 20000;
const PARALLELISM: u32 = 4;
const ITERATION_COST: u32 = 4;
pub struct EncryptedData {
    pub bytes: Vec<u8>,
    pub nonce: GcmNonce,
}
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Gcm256Key([u8; 32]);
impl Gcm256Key {
    #[must_use]
    fn from_slice(slice: &[u8; 32]) -> Self {
        Self(*slice)
    }
    #[must_use]
    fn as_slice(&self) -> &[u8; 32] {
        &self.0
    }
    /// Exposes a key encrypted with the given KEK
    /// ## WARNING
    /// Encrypting ~2^32 DEKS with one KEK makes Nonce Reuse a non-negligible factor!
    /// To mitigate this, please rotate KEKs regularly as Nonce Reuse is catastrophic.
    /// # Errors
    /// Can error out during Encryption. No further information can be given, as `aes-gcm::Error` is opaque.
    pub fn expose_with_kek(&self, kek: &[u8; 32]) -> Result<(Vec<u8>, GcmNonce), Error> {
        let mut randgen = rng();
        let nonce = GcmNonce::from_slice(&randgen.random());
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*kek));
        Ok((
            cipher.encrypt(&Nonce::from(nonce.0), self.0.as_slice())?,
            nonce,
        ))
    }
    /// Recovers a key with the source(encrypted DEK) and the KEK
    /// # Errors
    /// Can error out during Decryption. No further information can be given, as `aes-gcm::Error` is opaque.
    pub fn recover_with_kek(
        source: &[u8; 48],
        kek: &[u8; 32],
        nonce: &GcmNonce,
    ) -> Result<Gcm256Key, Error> {
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*kek));
        let plaintext = Zeroizing::new(cipher.decrypt(&Nonce::from(nonce.0), source.as_slice())?);
        Ok(Gcm256Key::from_slice(
            plaintext
                .as_slice()
                .try_into()
                .map_err(|_| ConversionError)?,
        ))
    }
}
pub struct GcmNonce([u8; 12]);
impl GcmNonce {
    #[must_use]
    pub fn from_slice(slice: &[u8; 12]) -> Self {
        Self(*slice)
    }
    #[must_use]
    pub fn as_slice(&self) -> &[u8; 12] {
        &self.0
    }
}
pub struct Salt([u8; 16]);
impl Salt {
    #[must_use]
    pub fn from_slice(slice: &[u8; 16]) -> Self {
        Self(*slice)
    }
    #[must_use]
    pub fn as_slice(&self) -> &[u8; 16] {
        &self.0
    }
}
/// This type is opaque as the `Error` type of `aes_gcm` is opaque for security
/// This leads to no information being recoverable from the error and thus this Error cannot be better
pub enum Error {
    /// Error in encryption or decryption. That's all we know.
    Aes,
    /// The parameters are valid so if you get this error file an issue on the GitHub
    ArgonParams,
    /// I have no idea what this means because the argon2 crate Docs won't tell me.
    Argon2Hashing,
    /// Another error that should be held up by the invariant that a 48-byte ciphertext + auth tag will produce 32-byte plaintext.
    /// Report an issue if this occurs.
    ConversionError,
}
impl From<aes_gcm::Error> for Error {
    fn from(_: aes_gcm::Error) -> Self {
        Self::Aes
    }
}
/// Encrypts using randomly generated key, uses AES-256-GCM under the hood
/// # Errors
/// The only error that can happen is during encryption, and that will return `Error::Aes`.
/// The cause of the Error cannot be known as `aes-gcm::Error` is a unit struct.
pub fn encrypt_with_random_key(bytes: &[u8]) -> Result<(EncryptedData, Gcm256Key), Error> {
    let mut randgen = rng();
    let rawkey = Gcm256Key::from_slice(&randgen.random());
    let key = Key::<Aes256Gcm>::from(*rawkey.as_slice());
    let cipher = Aes256Gcm::new(&key);
    let rawnonce = GcmNonce::from_slice(&randgen.random());
    let nonce = Nonce::from(*rawnonce.as_slice());
    Ok((
        EncryptedData {
            bytes: cipher.encrypt(&nonce, bytes)?,
            nonce: rawnonce,
        },
        rawkey,
    ))
}
/// Decrypts using provided key, uses AES-256-GCM under the hood.
/// Intended for use with `encrypt_with_random_key`
/// # Errors
/// The only error that can happen is during decryption, and that will return `Error::Aes`.
/// The cause of the Error cannot be known as `aes-gcm::Error` is a unit struct.
pub fn decrypt_with_key(bytes: &[u8], key: &Gcm256Key, nonce: &GcmNonce) -> Result<Vec<u8>, Error> {
    let key = Key::<Aes256Gcm>::from(*key.as_slice());
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from(*nonce.as_slice());
    Ok(cipher.decrypt(&nonce, bytes)?)
}
/// Encrypts using provided password, uses AES-256-GCM and Argon2 under the hood.
/// # Errors
/// First, there can be an Error during encryption
/// The cause of the Error in encryption cannot be known as `aes-gcm::Error` is a unit struct.
/// Second, the Error with Argon2 parameters
/// This should not be possible, file an issue if you get this Error because the parameters are valid
/// Third, the possible Error during hashing
/// I couldn't tell you why this is happening because it's completely undocumented on how `hash_password_into` can fail
pub fn encrypt_with_password(bytes: &[u8], password: &str) -> Result<(EncryptedData, Salt), Error> {
    let mut randgen = rng();
    let mut params = ParamsBuilder::new();
    params.m_cost(MEM_COST);
    params.p_cost(PARALLELISM);
    params.t_cost(ITERATION_COST);
    let hasher = Argon2::new(
        Argon2id,
        V0x13,
        params.build().map_err(|_| Error::ArgonParams)?,
    );
    let salt = Salt::from_slice(&randgen.random());
    let mut rawkey = Gcm256Key::from_slice(&[0u8; 32]);
    hasher
        .hash_password_into(password.as_bytes(), salt.as_slice(), &mut rawkey.0)
        .map_err(|_| Error::Argon2Hashing)?;
    let key = Key::<Aes256Gcm>::from(*rawkey.as_slice());
    let cipher = Aes256Gcm::new(&key);
    let rawnonce = GcmNonce::from_slice(&randgen.random());
    let nonce = Nonce::from(*rawnonce.as_slice());
    Ok((
        EncryptedData {
            bytes: cipher.encrypt(&nonce, bytes)?,
            nonce: rawnonce,
        },
        salt,
    ))
}
/// Decrypts using provided password, uses AES-256-GCM and Argon2 under the hood.
/// # Errors
/// First, there can be an Error during decryption
/// The cause of the Error in decryption cannot be known as `aes-gcm::Error` is a unit struct.
/// Second, the Error with Argon2 parameters
/// This should not be possible, file an issue if you get this Error because the parameters are valid
/// Third, the possible Error during hashing
/// I couldn't tell you why this is happening because it's completely undocumented on how `hash_password_into` can fail
pub fn decrypt_with_password(
    bytes: &[u8],
    password: &str,
    salt: &Salt,
    nonce: &GcmNonce,
) -> Result<Vec<u8>, Error> {
    let mut params = ParamsBuilder::new();
    params.m_cost(MEM_COST);
    params.p_cost(PARALLELISM);
    params.t_cost(ITERATION_COST);
    let hasher = Argon2::new(
        Argon2id,
        V0x13,
        params.build().map_err(|_| Error::ArgonParams)?,
    );
    let mut rawkey = Gcm256Key::from_slice(&[0u8; 32]);
    hasher
        .hash_password_into(password.as_bytes(), salt.as_slice(), &mut rawkey.0)
        .map_err(|_| Error::Argon2Hashing)?;
    let key = Key::<Aes256Gcm>::from(*rawkey.as_slice());
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from(*nonce.as_slice());
    Ok(cipher.decrypt(&nonce, bytes)?)
}
