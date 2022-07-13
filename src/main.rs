use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rsa_key::{create_rsa_key_files, get_rsa_keys_from_files};
use serde::{Deserialize, Serialize};
use std::error;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

fn main() -> Result<()> {
    let rsa_keys_result = get_rsa_keys_from_files();
    if rsa_keys_result.is_err() {
        println!("creating RSA kyes...");
        let result = create_rsa_key_files(2048);
        match result {
            Ok(_) => println!("created RSA kyes!"),
            Err(err) => println!("{:?}", err),
        }
        std::process::exit(0);
    }
    let rsa_keys = rsa_keys_result.unwrap();
    let private_key = rsa_keys.private_pem;
    let user_id = String::from("abcd");
    let token = create_jwt_token(private_key, user_id)?;
    println!("token : {}", token);
    let public_key = rsa_keys.public_pem;
    let result = verify_jwt_token(token, public_key)?;
    println!("user_id : {}", result.user_id);
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    iat: usize,
    aud: String,
    iss: String,
    user_id: String,
}

fn create_jwt_token(secret: String, user_id: String) -> Result<String> {
    let header = Header::new(Algorithm::RS256);
    let iat = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as usize;
    let ext_sec = Duration::from_secs(60 * 30).as_secs() as usize;
    let exp = iat + ext_sec;
    let claims = Claims {
        sub: String::from("test"),
        exp,
        iat,
        aud: String::from("B"),
        iss: String::from("A"),
        user_id,
    };
    let token = encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(secret.as_bytes())?,
    )?;
    Ok(token)
}

fn verify_jwt_token(token: String, public_key: String) -> Result<Claims> {
    let result = decode::<Claims>(
        &token,
        &DecodingKey::from_rsa_pem(public_key.as_bytes())?,
        &Validation::new(Algorithm::RS256),
    )?;
    Ok(result.claims)
}
