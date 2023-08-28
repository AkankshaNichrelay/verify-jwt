use std::error::Error;

use josekit::Value;
use josekit::jws::JwsVerifier;
use serde::Deserialize;
use josekit::jwk::Jwk;
use josekit::jwt::{decode_with_verifier, decode_header};
use josekit::jws::alg::{ ecdsa::EcdsaJwsAlgorithm, rsassa::RsassaJwsAlgorithm };

#[derive(Debug, Deserialize)]
pub struct MyTokens {
    pub jwt: String,
    pub jwk: Jwk,
}

// returns if the JWT signature is valid as per the public JWK provided
pub fn verify_jwt(jwt: &String, jwk: &Jwk) -> Result<bool, Box<dyn Error>> {

    let signing_algo = get_jwt_algorithm(&jwt)?;
    println!("signing algo: {:?}", signing_algo);

    let verifier = get_jws_verifier(signing_algo, &jwk)?;
    
    match decode_with_verifier(
            jwt.to_string(),
            &*verifier,
        ) {
        
        Ok((payload, header)) => {
            println!("payload {}", payload);
            println!("header {}", header);
            Ok(true)
        },
        Err(_) => {
            Ok(false)
        }
    }
}

// returns the appropriate JWS verifier based on signing algorithm provided
fn get_jws_verifier(signing_algo: String, jwk: & Jwk) -> Result<Box<dyn JwsVerifier>, &'static str> {
    let error = "Invalid JWK";
    // get verifier as per the signing algorithm
    match signing_algo.as_str() {
        // could create enums and support more algorithms
        "ES256" => {
            match EcdsaJwsAlgorithm::Es256.verifier_from_jwk(jwk) {
                Ok(verifier) => Ok(Box::new(verifier)),
                _ => Err(error),
            }
        },
        "ES512" => {
            match EcdsaJwsAlgorithm::Es512.verifier_from_jwk(jwk) {
                Ok(verifier) => Ok(Box::new(verifier)),
                _ => Err(error),
            }
        },
        "RS256" => {
            match RsassaJwsAlgorithm::Rs256.verifier_from_jwk(jwk) {
                Ok(verifier) => Ok(Box::new(verifier)),
                _ => Err(error),
            }
        },

        _ => Err("JWT: Algorithm not supported")
    }
}

// returns the algorithm used for signing JWT 
fn get_jwt_algorithm(jwt: &str) -> Result<String, &str> {
    let jwt_header = match decode_header(jwt) {
        Ok(val) => val,
        _ => return Err("JWT is Invalid"),
    };
    match  jwt_header.claim("alg") {
        Some(Value::String(val)) => Ok(val.to_string()),
        _ => Err("JWT Header Algo not found"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;       // importing everything from parent module

    #[test]
    fn test_get_jwt_algorithm() -> Result<(), String> {
        let jwt_header = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA";
        let actual_algo = get_jwt_algorithm(jwt_header)?;
        assert_eq!("ES256", actual_algo);
        Ok(())
    }

    #[test]
    fn test_verify_jwt() -> Result<(), String> {
        Ok(())
    }
    // TODO: Add more unit tests
}