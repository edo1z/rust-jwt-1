use pkcs8::{self, EncodePrivateKey, EncodePublicKey, LineEnding::LF};
use rsa::RsaPrivateKey;
use std::error;
use std::fs::File;
use std::io::prelude::*;

type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

pub struct RsaKeys {
    pub private_pem: String,
    pub public_pem: String,
}

pub fn create_rsa_keys(bits: usize) -> Result<RsaKeys> {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, bits)?;
    let private_pem = private_key.to_pkcs8_pem(LF).unwrap().to_string();
    let public_pem = private_key.to_public_key_pem(LF).unwrap();
    Ok(RsaKeys {
        private_pem,
        public_pem,
    })
}

pub fn create_rsa_key_files(bits: usize) -> Result<()> {
    let rsa_keys = create_rsa_keys(bits)?;
    let mut private_key_file = File::create(".private_key")?;
    let mut public_key_file = File::create(".public_key")?;
    private_key_file.write_all(rsa_keys.private_pem.as_bytes())?;
    public_key_file.write_all(rsa_keys.public_pem.as_bytes())?;
    Ok(())
}

pub fn get_rsa_keys_from_files() -> Result<RsaKeys> {
    let mut private_key_file = File::open(".private_key")?;
    let mut public_key_file = File::open(".public_key")?;
    let mut rsa_keys = RsaKeys {
        private_pem: String::from(""),
        public_pem: String::from(""),
    };
    private_key_file.read_to_string(&mut rsa_keys.private_pem)?;
    public_key_file.read_to_string(&mut rsa_keys.public_pem)?;
    Ok(rsa_keys)
}
