# Overview

This repo contains a SDK to
* parse, verify the AWS Nitro SDK attestation document
  * [attestation-doc-validation](./attestation-doc-validation/) contains a rust crate which implements the core logic required for attesting an Enclave (validating certs, and attestation docs)
* generate ed25519 keypair, sign the message, and verify the ed25519 signature
* generate RSA keypair, encrypt and decrypt


## Wasm Setup Guide

The WASM project requires [wasm-pack](https://rustwasm.github.io/wasm-pack/).

To build the WASM bindings, you can run the following command:

```sh
wasm-pack build ./wasm-sdk-bindings -s evervault --out-name index --release --target=web
```

This will:
- Build the wasm lib, with the output going into `./wasm-sdk-bindings/pkg`
- Sets the `scope` of the output JS package as `@evervault` (so the full name as `@evervault/wasm-sdk-bindings`)
- Use `index` as the base for each file name e.g. `index.js`, `index_bg.js`, `index_bg.wasm` etc.
- Sets the build to be a release build, targetting the web as its platform.

### Compiling WASM on Mac

It's not possible to compile the wasm bindings on Mac using the version of Clang shipped in MacOS. 
One approach to get around this is to install LLVM from homebrew, and set it as your C-Compiler using the `TARGET_CC` env var:

For release target
```sh
TARGET_CC="/opt/homebrew/opt/llvm/bin/clang" wasm-pack build ./wasm-sdk-bindings -s evervault --out-name index --release --target=web
```

For debug target
```sh
TARGET_CC="/opt/homebrew/opt/llvm/bin/clang" wasm-pack build ./wasm-sdk-bindings -s evervault --out-name index --dev --target=web
```