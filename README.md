# Experimental Tide TLS Listener

To run the example locally:
* install [mkcert](https://github.com/FiloSottile/mkcert)
* `$ mkcert -key-file key.pem -cert-file cert.pem localhost 127.0.0.1 ::1`
* `$ env TIDE_CERT=cert.pem TIDE_KEY=key.pem cargo run --example hello_tls`
* `$ curl -v https://localhost:4433`

# Outstanding issues

* `key` currently only works with pkcs8 keys
* documentation and tests
