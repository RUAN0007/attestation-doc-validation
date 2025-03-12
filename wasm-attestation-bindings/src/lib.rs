use anyhow::{Result, anyhow};

pub mod attestation_doc;
pub mod crypto;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

    #[wasm_bindgen(js_namespace = console)]
    fn error(s: &str);
}

#[cfg(not(target_arch = "wasm32"))]
fn error(s: &str) {
    println!("error: {}", s);
}

fn hex_encode(data : &[u8]) -> String {
	format!("0x{}", hex::encode(data))
}

fn hex_decode(data: &str) -> Result<Vec<u8>>  {
    if data.starts_with("0x") {
        return Ok(hex::decode(&data[2..])?);
    }
    Err(anyhow!("Invalid hex string, not prefixed with '0x'"))
}

