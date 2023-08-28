use actix_web::{get, post, web, App, HttpServer, Responder, HttpResponse};
use josekit::Value;
use serde::{Deserialize};
use josekit::jwk::Jwk;
use josekit::jwt::{decode_with_verifier, decode_header};
use josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm;

#[derive(Debug, Deserialize)]
struct MyTokens {
    jwt: String,
    jwk: Jwk,
}

#[get("/")]
async fn index() -> impl Responder {
    "Hello, World!"
}

#[post("/verify-jwt")]
async fn verify_jwt(my_tokens: web::Json<MyTokens>) -> impl Responder {
    println!("jwt: {:?}", my_tokens.jwt);
    println!("jwk: {:?}", my_tokens.jwk);

    let jwt_header = decode_header(&my_tokens.jwt).unwrap();
    let signing_algo = match  jwt_header.claim("alg") {
        Some(Value::String(val)) => val,
        _ => panic!("JWT Header Algo not found"),
    };

    println!("signing algo: {:?}", signing_algo);

    // get verifier as per the signing algorithm
    let verifier = match signing_algo.as_str() {
        "ES256"| "ES384"| "ES512"| "ES256K" => 
            EcdsaJwsAlgorithm::Es256.verifier_from_jwk(&my_tokens.jwk).unwrap(),
        _ => panic!("Algorithm not supported")
    };
    
    let (payload, header) 
        = decode_with_verifier(
            &my_tokens.jwt,
            &verifier,
        ).unwrap();
    
    println!("payload {}", payload);
    println!("header {}", header);
    HttpResponse::Ok().body("Received tokens.")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(index).service(verify_jwt))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}
