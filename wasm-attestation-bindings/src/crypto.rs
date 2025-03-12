use pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey};
use sha2::Digest;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
use rand::rngs::OsRng;
use rand::RngCore;
use ed25519_dalek::{Signer, Verifier};
use super::*;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = Ed25519KeyPair))]
pub struct Ed25519KeyPair {
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(getter_with_clone, js_name = pk_hex))]
    pub pk: String,
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(getter_with_clone, js_name = sk_hex))]
    pub sk: String,
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = newEd25519KeyPair))]
pub fn new_ed25519_keypair() -> Ed25519KeyPair {
    let mut rng = OsRng;
    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);

    let sk = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
    let pk = ed25519_dalek::VerifyingKey::from(&sk);    
	Ed25519KeyPair {
        sk: hex_encode(&sk.to_bytes()),
        pk: hex_encode(&pk.to_bytes()),
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = ed25519_sign))]
// return empty str if failed.
pub fn ed25519_sign(data_hex: String, sk_hex: String) -> String {
    let data = match hex_decode(&data_hex) {
        Ok(data) => data,
        Err(e) => {
            error(format!("fail to hex-decode data {} due to error {}", data_hex, e).as_str());
            return "".to_owned();
        }
    };

    let sk = match hex_decode(&sk_hex) {
        Ok(sk) => sk,
        Err(e) => {
            error(format!("fail to hex-decode sk {} due to error {}", sk_hex, e).as_str());
            return "".to_owned();
        }
    };

    let sk: [u8; 32] = match sk.try_into() {
        Ok(sk) => sk,
        Err(_) => {
            error("fail to convert sk to [u8; 32]");
            return "".to_owned();
        }
    };

    let sk = match ed25519_dalek::SigningKey::try_from(&sk) {
        Ok(sk) => {
			let mut hasher = sha2::Sha256::new(); // Create a Sha256 hasher
			hasher.update(data); // Feed the data into the hasher
			let result = hasher.finalize(); // Retrieve the hash result
			let signature = sk.sign(&result);
            signature.to_bytes()
        }
        Err(e) => {
            error(format!("fail to create SecretKey from bytes due to error {}", e).as_str());
            return "".to_owned();
        }
    };

    return hex_encode(&sk);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = ed25519_verify))]
pub fn ed25519_verify(signature_hex: String, data_hex: String, pk_hex: String) -> bool {
	let data = match hex_decode(&data_hex) {
		Ok(data_hex) => data_hex,
		Err(e) => {
			error(format!("fail to hex-decode {} due to error {}", signature_hex, e).as_str());
			return false;
		}
	};
	
	let pk = match hex_decode(&pk_hex) {
		Ok(pk) => pk,
		Err(e) => {
			error(format!("fail to hex-decode {} due to error {}", pk_hex, e).as_str());
			return false;
		}
	};

    let pk: [u8; 32] = match pk.try_into() {
        Ok(pk) => pk,
        Err(_) => {
            error("fail to convert pk to [u8; 32]");
            return false;
        }
    };

	let sig = match hex_decode(&signature_hex) {
		Ok(sig) => sig,
		Err(e) => {
			error(format!("fail to hex-decode {} due to error {}", signature_hex, e).as_str());
			return false;
		}
	};

    let sig: [u8; 64] = match sig.try_into() {
        Ok(sig) => sig,
        Err(_) => {
            error("fail to convert sig to [u8; 64]");
            return false;
        }
    };

    let sig = ed25519_dalek::Signature::from_bytes(&sig);

    let pk = match ed25519_dalek::VerifyingKey::from_bytes(&pk) {
        Ok(pk) => pk,
        Err(e) => {
            error(format!("fail to create VerifyingKey from bytes due to error {}", e).as_str());
            return false;
        }
    };

	let mut hasher = sha2::Sha256::new(); // Create a Sha256 hasher
    hasher.update(data); // Feed the data into the hasher
    let data_hash = hasher.finalize(); // Retrieve the hash result

    let result = match pk.verify(&data_hash, &sig){
		Ok(_) => true,
		Err(e) => {
			error(format!("fail to verify signature due to error {}", e).as_str());
			false
		}
	};

    return result;
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = RsaKeyPair))]
pub struct RsaKeyPair {
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(getter_with_clone, js_name = pk_der_hex))]
    pub pk: String,
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(getter_with_clone, js_name = sk_der_hex))]
    pub sk: String,
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = newRsaKeyPair))]
pub fn new_rsa_keypair() -> RsaKeyPair {
    let (sk, pk) = {
		let mut rng = OsRng;
		let bits = 2048;
		let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
		let public_key = RsaPublicKey::from(&private_key);
		(private_key, public_key)
	};

    let sk_der = match sk.to_pkcs1_der() {
        Ok(sk_der) => sk_der,
        Err(e) => {
            error(format!("fail to convert sk to pkcs1 der due to error {}", e).as_str());
            return RsaKeyPair {
                sk: "".to_owned(),
                pk: "".to_owned(),
            };
        }
    };

    let pk_der = match pk.to_pkcs1_der() {
        Ok(pk_der) => pk_der,
        Err(e) => {
            error(format!("fail to convert pk to pkcs1 der due to error {}", e).as_str());
            return RsaKeyPair {
                sk: "".to_owned(),
                pk: "".to_owned(),
            };
        }
    };

    RsaKeyPair {
        sk: hex_encode(&sk_der.as_bytes()),
        pk: hex_encode(&pk_der.as_bytes()),
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = rsaEncrypt))]
pub fn rsa_encrypt(pubkey_der_hex: String, plaintext_hex: String) -> String {
	let pubkey_der = match hex_decode(&pubkey_der_hex) {
		Ok(pubkey_der) => pubkey_der,
		Err(e) => {
			error(format!("fail to hex-decode {} due to error {}", pubkey_der_hex, e).as_str());
			return "".to_owned();
		}
	};
	
	let plaintext = match hex_decode(&plaintext_hex) {
		Ok(plaintext) => plaintext,
		Err(e) => {
			error(format!("fail to hex-decode {} due to error {}", plaintext_hex, e).as_str());
			return "".to_owned();
		}
	};
    let public_key = RsaPublicKey::from_pkcs1_der(&pubkey_der).expect("fail for pkcs der");

    let ciphertext = match public_key.encrypt(&mut OsRng, Pkcs1v15Encrypt, &plaintext) {
        Ok(ciphertext) => ciphertext,
        Err(e) => {
            error(format!("fail to encrypt data due to error {}", e).as_str());
            return "".to_owned();
        }
    };

    return hex_encode(&ciphertext);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = rsaDecrypt))]
pub fn rsa_decrypt(sk_der_hex: String, ciphertext_hex: String) -> String {
	let sk_der = match hex_decode(&sk_der_hex) {
		Ok(sk_der) => sk_der,
		Err(e) => {
			error(format!("fail to hex-decode {} due to error {}", sk_der_hex, e).as_str());
			return "".to_owned();
		}
	};
	
	let ciphertext = match hex_decode(&ciphertext_hex) {
		Ok(ciphertext) => ciphertext,
		Err(e) => {
			error(format!("fail to hex-decode {} due to error {}", ciphertext_hex, e).as_str());
			return "".to_owned();
		}
	};

    let sk = match RsaPrivateKey::from_pkcs1_der(&sk_der) {
        Ok(sk) => sk,
        Err(e) => {
            error(
                format!(
                    "fail to create RsaPrivateKey from pkcs1 der due to error {}",
                    e
                )
                .as_str(),
            );
            return "".to_owned();
        }
    };
    let plaintext = match sk.decrypt(Pkcs1v15Encrypt, &ciphertext) {
        Ok(ciphertext) => ciphertext,
        Err(e) => {
            error(format!("fail to decrypt data due to error {}", e).as_str());
            return "".to_owned();
        }
    };

    return hex_encode(&plaintext);
}

