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
cargo install cargo-pwhide

This allow to encrypt/decrypt password with

cargo pwhide encryt **password**
or 
cargo pwhide decryt **password**

This must be executed in a directory with a valid Cargo.toml file.
The secret for encryption and decrpytion is the name of the crate.

Each encrytpion run provides a different output, because a random nounce is selected
Encryption is done using Chacha20poly1305 and base62 encoding

# The lib provides a function to decrypt

install wit with
cargo-pwhide = {version="*", feature=["lib"]}
This includes only the minimum number of dependencies


pwdecrypt (secret:Into<String>,enrypted_data:Into<String>) -> String

This should be called with 
pwdecrypt(env!("CARGO_PKG_NAME"),encrypted_password)

To make live easier a macro is provided

pwdecrypt(encrypted_password) which expands to 
pwdecrypt(env!("CARGO_PKG_NAME"),encrypted_password)


If anybody needs this the following enhancments would be done:
 - remove dependencies for clap etc if just doing decryption
 - allow to specify the secret for encryption
 - allow to use a static nounce for  reproducible encryption

 
