use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rsa_key::{create_rsa_keys_and_dotenv_file, get_rsa_keys_from_files};
use serde::{Deserialize, Serialize};
use std::error;

type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

fn main() {
    let rsa_keys_result = get_rsa_keys_from_files();
    if rsa_keys_result.is_err() {
        println!("creating RSA kyes...");
        let result = create_rsa_keys_and_dotenv_file(2048);
        match result {
            Ok(_) => println!("created RSA kyes!"),
            Err(err) => println!("{:?}", err),
        }
        std::process::exit(0);
    }
    let rsa_keys = rsa_keys_result.unwrap();
    let private_key = rsa_keys.private_pem;
    let user_id = String::from("abcd");
    let token = create_jwt_token(private_key, user_id);
    println!("TOKEN : {:?}", token);
    let result = verify_jwt_token(token);
    println!("RESULT : {:?}", result);
}

fn create_jwt_token(secret: String, user_id: String) -> String {
    String::from("token")
}

fn verify_jwt_token(token: String) -> Result<()> {
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    user_id: String,
    iat: usize,
    exp: usize,
}
