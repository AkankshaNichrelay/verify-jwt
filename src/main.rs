use actix_web::{get, post, web, App, HttpServer, Responder, HttpResponse};
use serde::{Deserialize};

#[derive(Debug, Deserialize)]
struct MyToken {
    jwt: String,
    jwk: String,
}

#[get("/")]
async fn index() -> impl Responder {
    "Hello, World!"
}

#[post("/verify-jwt")]
async fn verify_jwt(mytokens: web::Json<MyToken>) -> impl Responder {
    println!("jwt: {:?}", mytokens.jwt);
    println!("jwk: {:?}", mytokens.jwk);
    HttpResponse::Ok().body("Received tokens.")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(index).service(verify_jwt))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}
