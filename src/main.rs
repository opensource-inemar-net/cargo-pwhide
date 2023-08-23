

use chacha20poly1305::AeadCore;
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::KeyInit;
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::generic_array::GenericArray;
use clap::{Command, Arg};
use std::fs::read_to_string;
use toml::Table;
use toml::Value;
use sha2::{Sha256, Digest};

fn main() {
    let matches =Command::new("pwhide")
    .version(env!("CARGO_PKG_VERSION"))
    .author(env!("CARGO_PKG_AUTHORS"))
    .about("pwhide encrypts passwords using the crate name as secret. This is marginal better then plain text. pwhide-lib is used to decode it a program")
    .bin_name("cargo pwhide")
    .propagate_version(true)
//        .subcommand_required(true)
.arg_required_else_help(true)
.arg(Arg::new("action")
.value_parser(["encrypt","decrypt"]))
    .arg(Arg::new("password").help("The data which should be encrypted or decrypted"))

.get_matches();

    //We know what to do read the Cargo.toml file


    let cargo=read_to_string("./Cargo.toml");
    
    let secret:String =match cargo {
        Ok(cargo) => {
            let toml=cargo.as_str().parse::<Table>();
            //println!("toml {:?}",toml);
            match toml {
                Ok(toml) => {
                    match toml.get("package") {
                        Some(package) => {
                            match package.get("name") {
                                Some(value) => {
                                    match value {
                                        Value::String(s) => {
                                            s.clone()
                                        }
                                        _ => {
                                            println!("The subcommand must be executed in a folder with a valid Cargo.toml file");
                                            println!("Failure parsing Cargo.toml [package] name is nit a string");
                                            return
                                        }
                                    }
                                },
                                None => {
                                    println!("The subcommand must be executed in a folder with a valid Cargo.toml file");
                                    println!("Failure parsing Cargo.toml [package] name is missing");
                                    return                        
                                }
                            }

                        },
                        None =>{
                            println!("The subcommand must be executed in a folder with a valid Cargo.toml file");
                            println!("Failure parsing Cargo.toml [package] is missing");
                            return
                        }
                    }
                }
                Err(e) => {
                    println!("The subcommand must be executed in a folder with a valid Cargo.toml file");
            println!("Failure parsing Cargo.toml cause by {:?}",e);
            return;
                }
            }
        },
        Err(e) => {
            println!("The subcommand must be executed in a folder with a valid Cargo.toml file");
            println!("Failure cause by {:?}",e);
            return;
        }
    };

    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());


    let cipher = ChaCha20Poly1305::new(&hasher.finalize());

    //now we decide encrypt or decrypt
    let value:&String=matches.get_one("password").unwrap();
    let action:&String=matches.get_one("action").unwrap();
    match action.as_str() {
        "encrypt" => {
            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
            let ciphertext = cipher.encrypt(&nonce, value.as_bytes().as_ref());
            match ciphertext {
                Err(e) => {
                    println!("Encryption failed with error {:?}",e);
                    println!("please raise a github issue");
                    return
                },
                Ok(data) => {
                    println!("Encrypted: {}{}",base_62::encode(nonce.as_slice()),base_62::encode(data.as_slice()))
                }
            };
            
        },
        "decrypt" => {
            if value.len()<18 {
                println!("Decoding not possible, encrypted value is too short");
                return;
            }
            let (nonce,text)=value.split_at(17);
            let nonce=if let Ok(dec)=base_62::decode(nonce) {
                GenericArray::clone_from_slice(dec.as_slice())
            } else {
                println!("Decoding not possible, encrypted value is invalid");
                return;
            };
            
            let text=if let Ok(dec)=base_62::decode(text) {
                dec
            } else {
                println!("Decoding not possible, encrypted value is invalid");
                return;
            };
            let plain=match cipher.decrypt(&nonce,text.as_ref()) {
                Ok(dec) => dec,
                Err(e) => { 
                    println!("Decryption failed with {:?}",e);
                    return
                },
            };
            if let Ok(dec)=String::from_utf8(plain) {
                println!("Decrypted: {}",dec)
            } else {
                println!("Decryption failed decypted data is no vailid text");
            }
            
            
        },
        _ => {
            println!("Only actions encrypt/decrypt are supported");
        },
    }

    //let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    //println!("Nonce: {}",base_62::encode(nonce.as_slice()).len());
    //let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref());
    



    //println!("Hello, world! {:?}",matches);
}
