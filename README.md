# Tide rustls listener

## async tls listener based on [async-tls](https://github.com/async-rs/async-tls) and [rustls](https://github.com/ctz/rustls)

* [CI ![CI][ci-badge]][ci]
* [API Docs][docs] [![docs.rs docs][docs-badge]][docs]
* [Releases][releases] [![crates.io version][version-badge]][lib-rs]

[ci]: https://github.com/jbr/tide-rustls/actions?query=workflow%3ACI
[ci-badge]: https://github.com/jbr/tide-rustls/workflows/CI/badge.svg
[releases]: https://github.com/jbr/tide-rustls/releases
[docs]: https://docs.rs/tide-rustls
[lib-rs]: https://lib.rs/tide-rustls
[docs-badge]: https://img.shields.io/badge/docs-latest-blue.svg?style=flat-square
[version-badge]: https://img.shields.io/crates/v/tide-rustls.svg?style=flat-square

## Installation
```sh
$ cargo add tide-rustls
```

## Safety
This crate uses ``#![deny(unsafe_code)]`` to ensure everything is implemented in
100% Safe Rust.

## License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br/>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>
