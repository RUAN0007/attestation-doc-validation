use attestation_doc_validation::{
    validate_and_parse_attestation_doc,
    validate_expected_pcrs, PCRProvider,
};
use wasm_bindgen::prelude::*;
use anyhow::{Result, anyhow};

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

    #[wasm_bindgen(js_namespace = console)]
    fn error(s: &str);
}

const LOG_NAMESPACE: &'static str = "ATTESTATION ::";

#[wasm_bindgen(js_name = PCRHexes)]
pub struct JsPCRHexes {
    #[wasm_bindgen(getter_with_clone, js_name = pcr0_hex)]
    pub pcr_0_hex: Option<String>,
    #[wasm_bindgen(getter_with_clone, js_name = pcr1_hex)]
    pub pcr_1_hex: Option<String>,
    #[wasm_bindgen(getter_with_clone, js_name = pcr2_hex)]
    pub pcr_2_hex: Option<String>,
    #[wasm_bindgen(getter_with_clone, js_name = pcr8_hex)]
    pub pcr_8_hex: Option<String>,
}

#[wasm_bindgen(js_name = DocParsingResult)]
pub struct DocParsingResult {
    #[wasm_bindgen(getter_with_clone, js_name = valid)]
    pub valid: bool,
    #[wasm_bindgen(getter_with_clone, js_name = pubkey_hex)]
    pub pubkey_hex: String,
    #[wasm_bindgen(getter_with_clone, js_name = user_data_hex)]
    pub user_data_hex: String,
    #[wasm_bindgen(getter_with_clone, js_name = nonce_hex)]
    pub nonce_hex: String,
}


#[wasm_bindgen(js_class = PCRHexes)]
impl JsPCRHexes {
    #[wasm_bindgen(constructor)]
    pub fn new(
        pcr_0_hex: Option<String>,
        pcr_1_hex: Option<String>,
        pcr_2_hex: Option<String>,
        pcr_8_hex: Option<String>,
    ) -> Self {
      Self {
        pcr_0_hex,
        pcr_1_hex,
        pcr_2_hex,
        pcr_8_hex,
      }
    }

    /// Helper to create an empty PCR container, to support setting the PCRs explicitly
    /// ```js
    /// const pcrs = PCRHexes.empty();
    /// pcrs.pcr0_hex = "...";
    /// pcrs.pcr8_hex = "...";
    /// ```
    pub fn empty() -> Self {
      Self {
        pcr_0_hex: None,
        pcr_1_hex: None,
        pcr_2_hex: None,
        pcr_8_hex: None,
      }
    }
}

impl PCRProvider for JsPCRHexes {
    // remove "0x" prefix
    fn pcr_0(&self) -> Option<&str> {
        self.pcr_0_hex.as_deref().map(|s| {
            if s.starts_with("0x") {
                &s[2..]
            } else {
                s
            }
        })    
    }

    fn pcr_1(&self) -> Option<&str> {
        self.pcr_1_hex.as_deref().map(|s| {
            if s.starts_with("0x") {
                &s[2..]
            } else {
                s
            }
        })    
    }

    fn pcr_2(&self) -> Option<&str> {
        self.pcr_2_hex.as_deref().map(|s| {
            if s.starts_with("0x") {
                &s[2..]
            } else {
                s
            }
        })    
    }

    fn pcr_8(&self) -> Option<&str> {
        self.pcr_8_hex.as_deref().map(|s| {
            if s.starts_with("0x") {
                &s[2..]
            } else {
                s
            }
        })    
    }
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


#[wasm_bindgen(js_name = parseAndValidateAttestationDoc)]
pub fn parse_validate_attestation_doc_pcrs(
    attestation_doc_hex: &str,
    expected_pcrs: JsPCRHexes,
) -> DocParsingResult {
    console_error_panic_hook::set_once();
    let mut res = DocParsingResult {
        valid: false,
        pubkey_hex: "".to_owned(),
        user_data_hex: "".to_owned(),
        nonce_hex: "".to_owned(),
    };
    let decoded_ad = match hex_decode(attestation_doc_hex) {
        Ok(ad) => ad,
        Err(e) => {
            let error_msg = format!("{LOG_NAMESPACE} Failed to decode the provided attestation document as hex - {e}");
            error(&error_msg);
            return res;
        }
    };

    let validated_attestation_doc = match validate_and_parse_attestation_doc(&decoded_ad) {
        Ok(attestation_doc) => attestation_doc,
        Err(e) => {
            let error_msg = format!("{LOG_NAMESPACE} An error occur while validating the attestation doc against the Enclave connection's cert: {e}");
            error(&error_msg);

            return res;
        }
    };


    match validate_expected_pcrs(&validated_attestation_doc, &expected_pcrs) {
        Ok(_) => {
            res.valid = true;
            if let Some(pub_key) = validated_attestation_doc.public_key {
                res.pubkey_hex = hex_encode(&pub_key.to_vec());
            }
            if let Some(user_data) = validated_attestation_doc.user_data {
                res.user_data_hex = hex_encode(&user_data.to_vec());
            }
            if let Some(nonce) = validated_attestation_doc.nonce {
                res.nonce_hex = hex_encode(&nonce.to_vec());
            }
            return res;
        }
        Err(e) => {
            let error_msg = format!("{LOG_NAMESPACE} An error occur while comparing the pcrs: {e}");
            error(&error_msg);
            return res;
        }
    }
}