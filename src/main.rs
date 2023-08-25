use clap::{Arg, Command};
use std::fs::read_to_string;
use toml::Table;
use toml::Value;

fn main() {
    let matches =Command::new("pwhide")
    .version(env!("CARGO_PKG_VERSION"))
    .author(env!("CARGO_PKG_AUTHORS"))
    .about("pwhide encrypts passwords using the crate name as secret. This is marginal better then plain text. pwhide-lib is used to decode it a program")
    .bin_name("cargo pwhide")
    .propagate_version(true)
    .arg_required_else_help(true)
    .arg(Arg::new("cargosubcommand")
        .help("When wunning as cargo subcommand this contains the command - not used")
    )
    .arg(Arg::new("action")
        .value_parser(["encrypt","decrypt"])
    )
    .arg(Arg::new("password").help("The data which should be encrypted or decrypted")
    )

    .get_matches();

    //We know what to do read the Cargo.toml file

    let cargo = read_to_string("./Cargo.toml");

    let secret: String = match cargo {
        Ok(cargo) => {
            let toml = cargo.as_str().parse::<Table>();
            //println!("toml {:?}",toml);
            match toml {
                Ok(toml) => match toml.get("package") {
                    Some(package) => match package.get("name") {
                        Some(value) => match value {
                            Value::String(s) => s.clone(),
                            _ => {
                                println!("The subcommand must be executed in a folder with a valid Cargo.toml file");
                                println!(
                                    "Failure parsing Cargo.toml [package] name is nit a string"
                                );
                                return;
                            }
                        },
                        None => {
                            println!("The subcommand must be executed in a folder with a valid Cargo.toml file");
                            println!("Failure parsing Cargo.toml [package] name is missing");
                            return;
                        }
                    },
                    None => {
                        println!("The subcommand must be executed in a folder with a valid Cargo.toml file");
                        println!("Failure parsing Cargo.toml [package] is missing");
                        return;
                    }
                },
                Err(e) => {
                    println!(
                        "The subcommand must be executed in a folder with a valid Cargo.toml file"
                    );
                    println!("Failure parsing Cargo.toml cause by {:?}", e);
                    return;
                }
            }
        }
        Err(e) => {
            println!("The subcommand must be executed in a folder with a valid Cargo.toml file");
            println!("Failure cause by {:?}", e);
            return;
        }
    };

    //now we decide encrypt or decrypt
    let value: &String = matches.get_one("password").unwrap();
    let action: &String = matches.get_one("action").unwrap();
    match action.as_str() {
        "encrypt" => match cargo_pwhide::pwencrypt(secret, value) {
            Ok(dec) => {
                println!("Encrypted: {}", dec);
            }
            Err(e) => {
                println!("Error {:?}", e);
            }
        },
        "decrypt" => match cargo_pwhide::pwdecrypt(secret, value) {
            Ok(dec) => {
                println!("Decrypted: {}", dec);
            }
            Err(e) => {
                println!("Error {:?}", e);
            }
        },
        _ => {
            println!("Only actions encrypt/decrypt are supported");
        }
    }

    //let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    //println!("Nonce: {}",base_62::encode(nonce.as_slice()).len());
    //let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref());

    //println!("Hello, world! {:?}",matches);
}
