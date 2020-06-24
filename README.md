# Experimental Tide TLS app

This is built as a bin project instead of a library or PR for tide
because it's mostly just an experiment at this point. With some help,
it might turn into an async-listen/rustls based tls listener for Tide.

To run this app locally:
* install [mkcert](https://github.com/FiloSottile/mkcert)
* `$ mkcert -key-file key.pem -cert-file cert.pem localhost 127.0.0.1 ::1`
* `$ env TIDE_CERT=cert.pem TIDE_KEY=key.pem cargo run`
* `$ curl -v https://localhost:4433`

# Outstanding issues

* The `TlsStreamWrapper` implementation is probably either wrong or
  just slow. Ideally I think it would return pending if the lock is
  unavailable and wake when it is, but I didn't know how to make that
  happen. I was happy enough I got this to compile and work at all.
* `TlsListener` probably should have a builder and a bunch more
  configurable options, since people would want to be able to
  customize things that are currently hardcoded.
* `load_keys` currently only works with pkcs8 keys, but that's
  certainly wrong

