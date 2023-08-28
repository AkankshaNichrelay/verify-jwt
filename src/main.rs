use actix_web::{get, post, web, App, HttpServer, Responder, HttpResponse};
mod api;
use api::MyTokens;



#[get("/")]
async fn index() -> impl Responder {
    "Hello, World!"
}

#[post("/verify-jwt")]
async fn verify_jwt_handler(my_tokens: web::Json<MyTokens>) -> HttpResponse {
    println!("jwt received: {:?}", my_tokens.jwt);
    println!("jwk received: {:?}", my_tokens.jwk);

    match api::verify_jwt(&my_tokens.jwt, &my_tokens.jwk) {
        Ok(true) => HttpResponse::Ok().body("Received token is Valid."),
        Err(e) => 
            HttpResponse::BadRequest().body(format!("Error while verifying: {}", e)),
        _ => HttpResponse::BadGateway().body("Application Server Error"),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(index).service(verify_jwt_handler))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}
