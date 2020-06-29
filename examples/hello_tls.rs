use std::env;
use tide::prelude::*;
use tide_rustls::TlsListener;

async fn endpoint(req: tide::Request<()>) -> tide::Result {
    Ok(json!({
        "localAddr": req.local_addr().unwrap_or("[unknown]"),
        "method": req.method().to_string(),
        "url": req.url().to_string()
    })
    .into())
}

#[async_std::main]
async fn main() -> std::io::Result<()> {
    let mut app = tide::new();
    app.at("*").all(endpoint);
    app.at("/").all(endpoint);

    if let (Ok(cert), Ok(key)) = (env::var("TIDE_CERT"), env::var("TIDE_KEY")) {
        tide::log::with_level(tide::log::LevelFilter::Info);
        app.listen(
            TlsListener::build()
                .addrs("localhost:4433")
                .cert(cert)
                .key(key),
        )
        .await?;
    } else {
        eprintln!(
            "
To run this app locally:
* install https://github.com/FiloSottile/mkcert
* $ mkcert -key-file key.pem -cert-file cert.pem localhost 127.0.0.1 ::1
* $ env TIDE_CERT=cert.pem TIDE_KEY=key.pem cargo run --example hello_tls
* $ curl -v https://localhost:4433/secure
"
        );
    }

    Ok(())
}
