

use actix_web::web;
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

pub fn verify_jwt(my_tokens: web::Json<MyTokens>) -> bool {

    let signing_algo = get_jwt_algorithm(&my_tokens.jwt.to_string());
    println!("signing algo: {:?}", signing_algo);

    let verifier = get_jws_verifier(signing_algo, &my_tokens.jwk);
    
    let (payload, header) 
        = decode_with_verifier(
            my_tokens.jwt.to_string(),
            &*verifier,
        ).unwrap();
    
    println!("payload {}", payload);
    println!("header {}", header);
    
    true
}

fn get_jws_verifier(signing_algo: String, jwk: & Jwk) -> Box<dyn JwsVerifier> {
    let error = "error while getting Jws Verifier";
    // get verifier as per the signing algorithm
    match signing_algo.as_str() {
        // could create enums and support more algorithms
        "ES256" => {
            let verifier = EcdsaJwsAlgorithm::Es256.verifier_from_jwk(jwk).unwrap();
            Box::new(verifier)
        },
        "ES512" => {
            let verifier = EcdsaJwsAlgorithm::Es512.verifier_from_jwk(jwk).unwrap();
            Box::new(verifier)
        },
        "RS256" => {
            let verifier = RsassaJwsAlgorithm::Rs256.verifier_from_jwk(jwk).unwrap();
            Box::new(verifier)
        },

        _ => panic!("Algorithm not supported")
    }
}

fn get_jwt_algorithm(jwt: &String) -> String {
    let jwt_header = decode_header(jwt).unwrap();
    let signing_algo = match  jwt_header.claim("alg") {
        Some(Value::String(val)) => val,
        _ => panic!("JWT Header Algo not found"),
    };

    signing_algo.to_string()
}