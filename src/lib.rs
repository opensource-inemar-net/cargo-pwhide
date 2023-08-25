//! cargo-pwhide provides tooling to hide passwords  
//!     
//!     
//! **This doesn't provide any security**
//! 
//! It consists of a cargo subcommand to encrypt passwords and a simple macro for decrypting
//! 
//! # Encryption
//! 
//! install the cargo subcommand with:  
//! **cargo install cargo-pwhide**
//! 
//! Then go to the root of your project where the Cargo.toml is   
//! and encrypt a password
//! 
//! **cargo pwhide encrypt MySecretPassword**
//! 
//! This will deliver an encrypted data for example:
//! 
//! QDc2rswTJRHrFEgT2Ech77xuScNGfGGKFIJq6MJcI1lKg1hfaowsg5
//! 
//! Use this in configuration files on in the command code
//! 
//! # Decryption in the program
//! 
//! Add to your Config.toml   
//! ```
//! cargo-pwhide = {version="*", feature=["lib"], default-features = false}**
//! ``` 
//!    
//! This reduces the number of dependencies and is great for compile time :)
//! 
//! For decryption just use the provided macro
//! 
//! ```
//! use cargo_pwhide::pwdecrypt;    
//! let cleartext:Result<String,anyhow::Error>=pwdecrypt!("QDc2rswTJRHrFEgT2Ech77xuScNGfGGKFIJq6MJcI1lKg1hfaowsg5");  
//! ```
//! 
//! and automatically decrpytion is done
//! 
//! # how does it work?
//! 
//! The tool is using the package name as secret
//! The password is encrypted using ChaCha20Poly1305 and a random nounce
//! 
//! This doesn't provide any security but is better compared to storing plain text passwords in version control
//! 


use anyhow::anyhow;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::AeadCore;
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::KeyInit;
use sha2::{Digest, Sha256};





/// The macro is used for easy decrpytion of password  
/// 
/// 
/// The macro expands to    
/// pwdecrpyt(env!("CARGO_PKG_NAME"),parameter) -> String
/// 
/// # Example
/// ```  
/// use cargo_pwhide::pwdecrypt;    
/// let cleartext:Result<String,anyhow::Error>=pwdecrypt!("QDc2rswTJRHrFEgT2Ech77xuScNGfGGKFIJq6MJcI1lKg1hfaowsg5");     
/// ```
///     
/// it returns are result with the string if decryption was possible  
/// The secret is the package name   
/// 
#[macro_export]
macro_rules! pwdecrypt {
    ($value:expr) => {
        cargo_pwhide::pwdecrypt(env!("CARGO_PKG_NAME"), $value)
    };
}

/// This is used to decrpyt the password encrypted with subcommand tools cargo pwhide encrypt
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


/// This is used to encrpyt a password function used by subcommand tools cargo pwhide encrypt
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
