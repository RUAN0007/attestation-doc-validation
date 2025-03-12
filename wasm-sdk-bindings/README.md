
# Overview
A NodeJS SDK for TEE-wallet project, [source code](https://github.com/RUAN0007/attestation-doc-validation) in Rust. 

The SDK can: 
* verify, parse AWS Nitro attestation document 
* generate, encrypt and decrypt in RSA
* sign and verify in ed25519

Note: all input-output parameters, including pk, sk, plaintext, ciphertexts, are hex encoded. 

# How to compile
## Setup 
### Install clang
```sh 
brew install llvm
```
### Install wasm-pack
```sh
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
```

## Debug mode
```sh
TARGET_CC="/opt/homebrew/opt/llvm/bin/clang" wasm-pack build ./wasm-sdk-bindings -s evervault --out-name index --dev --target=web
```
Note: The debug mode will treat an expired attestation document as valid. This is to facilitate testing on a hardcoded doc. 

## Release mode
```sh
TARGET_CC="/opt/homebrew/opt/llvm/bin/clang" wasm-pack build ./wasm-sdk-bindings -s evervault --out-name index --release --target=web
```

# How to use
refer to source code [unit tests](https://github.com/RUAN0007/attestation-doc-validation/blob/main/wasm-sdk-bindings/src/attestation_doc.rs#L200) in Rust. 