# cargo-pwhide
This tooling allows to hide/obfuscate password. It adds no security

Unfortunately not everywhere a secret managment is available. Especially in internal tools.
This missing secret managment means that passwords must be handled it a non secure way.

The worst part is to commit passwords in config files in plain text to git.
A little less worse is to have them in clear text on server config files.

This tooling tries to make it easy to hide the passwords from somebody, who is just looking at the git content,
without spending time to try to decrypt the passwords.

The solution doesn't provide any real security.

The solution contains of two parts:
- cargo subcommand
- lib to decrypt

# Install the cargo subcommand with

**cargo install cargo-pwhide**

This allow to encrypt/decrypt password with

cargo pwhide encryt [password]
or 
cargo pwhide decryt [password}

This must be executed in a directory with a valid Cargo.toml file.
The secret for encryption and decrpytion is the name of the crate.

Each encrytpion run provides a different output, because a random nounce is selected
Encryption is done using Chacha20poly1305 and base62 encoding

# The lib provides a function to decrypt

install it by adding to your Cargo.toml

**cargo-pwhide = {version="*", feature=["lib"], default-features = false}**


This includes only the minimum number of dependencies. 



The easiet way to use it is by using the simple macro

**use cargo_pwhide::pwdecrypt;**    
**let clear_text=pwdecrypt!(encrypted_password);**


The macro 

pwdecrypt!(encrypted_password)  -> String expands to   
pwdecrypt(env!("CARGO_PKG_NAME"),encrypted_password) -> String



Instead of using the macro the decrypt function can be also
called directly.

**pwdecrypt (secret:Into<String>,enrypted_data:Into<String>) -> String**

It should be called with 
pwdecrypt(env!("CARGO_PKG_NAME"),encrypted_password)


If anybody needs this the following enhancments would be done:
 - remove dependencies for clap etc if just doing decryption
 - allow to specify the secret for encryption
 - allow to use a static nounce for  reproducible encryption

 
