
[![](https://img.shields.io/github/workflow/status/spruceid/didkit/ci)](https://github.com/spruceid/didkit/actions?query=workflow%3Aci+branch%3Amain) [![](https://img.shields.io/badge/Docker-19.03.x-blue)](https://www.docker.com/) [![](https://img.shields.io/badge/Rust-v1.51.0-orange)](https://www.rust-lang.org/) [![](https://img.shields.io/badge/ssi-v0.1-green)](https://www.github.com/spruceid/ssi) [![](https://img.shields.io/badge/License-Apache--2.0-green)](https://github.com/spruceid/didkit/blob/main/LICENSE) [![](https://img.shields.io/twitter/follow/spruceid?label=Follow&style=social)](https://twitter.com/spruceid)

Check out the DIDKit documentation [here](https://spruceid.dev/didkit/didkit/).

# DIDKit

DIDKit provides Verifiable Credential and Decentralized Identifier
functionality across different platforms. It was written primarily in Rust due
to Rust's expressive type system, memory safety, simple dependency web, and
suitability across different platforms including embedded systems. DIDKit
embeds the [`ssi`](https://github.com/spruceid/ssi) library, which contains the
core functionality.

## Security Audits
DIDKit has undergone the following security reviews:
- [March 14th, 2022 - Trail of Bits](https://github.com/trailofbits/publications/blob/master/reviews/SpruceID.pdf) | [Summary of Findings](https://blog.spruceid.com/spruce-completes-first-security-audit-from-trail-of-bits/)

We are setting up a process to accept contributions. Please feel free to open
issues or PRs in the interim, but we cannot merge external changes until this
process is in place.

## Install

### Manual

DIDKit is written in [Rust][]. To get Rust, you can use [Rustup][].

Spruce's [ssi][] library must be cloned alongside the `didkit` repository:
```sh
$ git clone https://github.com/spruceid/ssi ../ssi --recurse-submodules
```

Build DIDKit using [Cargo][]:
```sh
$ cargo build
```
That will give you the DIDKit CLI and HTTP server executables located at
`target/debug/didkit` and `target/debug/didkit-http`, respectively. You can also build and install DIDKit's components separately. Building the FFI libraries will require additional dependencies. See the corresponding readmes linked below for more info.


### Container

This fork's publishing workflow targets `ghcr.io/learningeconomy/didkit-http`.
Pull requests build the image without publishing it; main and release builds use
the repository's `GITHUB_TOKEN` to publish.

Run the HTTP server with:
```bash
$ docker run --init -p 8080:3000 ghcr.io/learningeconomy/didkit-http:latest
```

#### Build the HTTP image

Build from a directory containing sibling `didkit/` and `ssi/` checkouts.
Use the SSI revision pinned in `didkit/.github/workflows/push_image.yml`.
The build uses these sources and DIDKit's committed workspace lock, rather than
substituting registry versions for path dependencies.

```bash
$ docker build -f didkit/http/Dockerfile -t didkit-http .
$ docker run --init -p 8080:3000 didkit-http
```

## Usage

DIDKit can be used in any of the following ways:

- [CLI](cli/) - `didkit` command-line program
- [HTTP](http/) - HTTP server (Rust library and CLI program)
- [FFI](lib/FFI.md) - libraries for C, Java, Android, and Dart/Flutter

[Rust]: https://www.rust-lang.org/
[rustup]: https://rustup.rs/
[Cargo]: https://doc.rust-lang.org/cargo/
[ssi]: https://github.com/spruceid/ssi
