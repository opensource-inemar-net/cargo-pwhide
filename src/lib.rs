use anyhow::anyhow;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::AeadCore;
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::KeyInit;
use sha2::{Digest, Sha256};

/// The macro is used for easy decrpytion of password
/// it expands to
/// pwdecrpyt(env!("CARGO_PACKAGE_NAME"),parameter)
#[macro_export]
macro_rules! pwdecrypt {
    ($value:expr) => {
        cargo_pwhide::pwdecrypt(env!("CARGO_PACKAGE_NAME"), $value)
    };
}

/// This is used to decrpyt the passowrd encrypted with subcommand tools cargo pwhide encrypt
pub fn pwdecrypt(
    packagename: impl Into<String>,
    data: impl Into<String>,
) -> anyhow::Result<String> {
    let secret: String = packagename.into();
    let mut hasher = Sha256::new();
    hasher.update(secret);

    let cipher = ChaCha20Poly1305::new(&hasher.finalize());

    let value: String = data.into();
    if value.len() < 18 {
        return Err(anyhow!(
            "Decoding not possible, encrypted value is too short"
        ));
    }
    let (nonce, text) = value.split_at(17);
    let nonce = if let Ok(dec) = base_62::decode(nonce) {
        GenericArray::clone_from_slice(dec.as_slice())
    } else {
        return Err(anyhow!("Decoding not possible, encrypted value is invalid"));
    };

    let text = if let Ok(dec) = base_62::decode(text) {
        dec
    } else {
        return Err(anyhow!("Decoding not possible, encrypted value is invalid"));
    };
    let plain = match cipher.decrypt(&nonce, text.as_ref()) {
        Ok(dec) => dec,
        Err(e) => {
            return Err(anyhow!("Decryption failed with {:?}", e));
        }
    };
    if let Ok(dec) = String::from_utf8(plain) {
        Ok(dec)
    } else {
        Err(anyhow!("Decryption failed decypted data is no vailid text"))
    }
}

pub fn pwencrypt(
    packagename: impl Into<String>,
    data: impl Into<String>,
) -> anyhow::Result<String> {
    let secret: String = packagename.into();
    let mut hasher = Sha256::new();
    hasher.update(secret);

    let cipher = ChaCha20Poly1305::new(&hasher.finalize());

    let value: String = data.into();

    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, value.as_bytes().as_ref());
    match ciphertext {
        Err(e) => Err(anyhow!(
            "Encryption failed with error {:?} -raise github issue",
            e
        )),
        Ok(data) => Ok(format!(
            "{}{}",
            base_62::encode(nonce.as_slice()),
            base_62::encode(data.as_slice())
        )),
    }
}
