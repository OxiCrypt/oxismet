use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use rand::{RngExt, rng};
pub struct EncryptedData {
    pub bytes: Vec<u8>,
    pub nonce: [u8; 12],
}
/// This Error is opaque as the Error type of aes_gcm is opaque for security
/// This leads to no information being recoverable from the error and thus this Error cannot be better
pub enum Error {
    /// Shouldn't be possible
    Aes,
    /// Also impossible
    ArgonParams,
}
impl From<aes_gcm::Error> for Error {
    fn from(_: aes_gcm::Error) -> Self {
        Self::Aes
    }
}
pub fn encrypt_with_random_key(bytes: &[u8]) -> Result<(EncryptedData, [u8; 32]), Error> {
    let mut randgen = rng();
    let rawkey: [u8; 32] = randgen.random();
    let key = Key::<Aes256Gcm>::from(rawkey);
    let cipher = Aes256Gcm::new(&key);
    let rawnonce: [u8; 12] = randgen.random();
    let nonce = Nonce::from(rawnonce);
    Ok((
        EncryptedData {
            bytes: cipher.encrypt(&nonce, bytes)?,
            nonce: rawnonce,
        },
        rawkey,
    ))
}
pub fn decrypt_with_key(bytes: &[u8], key: [u8; 32], nonce: [u8; 12]) -> Result<Vec<u8>, Error> {
    let key = Key::<Aes256Gcm>::from(key);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from(nonce);
    Ok(cipher.decrypt(&nonce, bytes)?)
}
