use anyhow::anyhow;
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::KeyInit;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::generic_array::GenericArray;
use sha2::{Sha256, Digest};

pub fn decrypt(packagename:impl Into<String>,data:impl Into<String>) -> anyhow::Result<String> {
    let secret:String=packagename.into();
    let mut hasher = Sha256::new();
    hasher.update(secret);


    let cipher = ChaCha20Poly1305::new(&hasher.finalize());

    let value:String=data.into();
    if value.len()<18 {
        return Err(anyhow!("Decoding not possible, encrypted value is too short"))
    }
    let (nonce,text)=value.split_at(17);
    let nonce=if let Ok(dec)=base_62::decode(nonce) {
        GenericArray::clone_from_slice(dec.as_slice())
    } else {
        return Err(anyhow!("Decoding not possible, encrypted value is invalid"));
    };
    
    let text=if let Ok(dec)=base_62::decode(text) {
        dec
    } else {
        return Err(anyhow!("Decoding not possible, encrypted value is invalid"))
        
    };
    let plain=match cipher.decrypt(&nonce,text.as_ref()) {
        Ok(dec) => dec,
        Err(e) => { 
            return Err(anyhow!("Decryption failed with {:?}",e));
            
        },
    };
    if let Ok(dec)=String::from_utf8(plain) {
        Ok(dec)
    } else {
        Err(anyhow!("Decryption failed decypted data is no vailid text"))
    }
}