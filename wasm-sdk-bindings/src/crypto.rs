use pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey};
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
pub fn ed25519_sign(msg_hex: String, sk_hex: String) -> String {
    let msg = match hex_decode(&msg_hex) {
        Ok(msg) => msg,
        Err(e) => {
            error(format!("fail to hex-decode data {} due to error {}", msg_hex, e).as_str());
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
			let signature = sk.sign(&msg);
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
pub fn ed25519_verify(signature_hex: String, msg_hex: String, pk_hex: String) -> bool {
	let msg = match hex_decode(&msg_hex) {
		Ok(msg) => msg,
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

    let result = match pk.verify(&msg, &sig){
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



#[cfg(test)]
mod tests {
    #[test]
    fn test_rsa_from_new_keypair() {
        let kp = super::new_rsa_keypair();
        println!("rsa pub_key: {}", kp.pk);
        println!("rsa sk_key: {}", kp.sk);

        let plaintext = "0x1234abcd".to_owned();
        println!("rsa plaintext: {}", plaintext);
        let ciphertext = super::rsa_encrypt(kp.pk.clone(), plaintext.clone());
        println!("rsa ciphertext: {}", ciphertext);
        let recovered = super::rsa_decrypt(kp.sk.clone(), ciphertext.clone());
        assert_eq!(recovered, plaintext);

        // rsa pub_key: 0x3082010a0282010100c72eb864475fbcf605f689000be19a9d8c912bd29eb795f3283481c0d2793311025e662cc4b44e08d2cf095a891468db09ef869bab4a12d6afc93bae6482ee1767e93efd7bccd24c2ad38ebf6f08bbbfc887a5da0c89309a93201c1c9af5b724fa8f13d181b9db4e647727e9f9fae1f9805bd94857bcc1892c12b16301cddc460da84a785161b9f869d7467ebc00b93e4e4fa2d90747174f4a8239d97ad3fc571e6fa86733846733c7fa88b4a9ac36252597dcdbd203202239f3236a4b7d55f47d7fe31a520b416af62836b464a7574994c534f6bf80bd36c5ba727477bed46c4fe3589afc204052b5ccf7d5210ab8a15a0dad2f27e87983180b4cc137a35b230203010001
        // rsa sk_key: 0x308204a40201000282010100c72eb864475fbcf605f689000be19a9d8c912bd29eb795f3283481c0d2793311025e662cc4b44e08d2cf095a891468db09ef869bab4a12d6afc93bae6482ee1767e93efd7bccd24c2ad38ebf6f08bbbfc887a5da0c89309a93201c1c9af5b724fa8f13d181b9db4e647727e9f9fae1f9805bd94857bcc1892c12b16301cddc460da84a785161b9f869d7467ebc00b93e4e4fa2d90747174f4a8239d97ad3fc571e6fa86733846733c7fa88b4a9ac36252597dcdbd203202239f3236a4b7d55f47d7fe31a520b416af62836b464a7574994c534f6bf80bd36c5ba727477bed46c4fe3589afc204052b5ccf7d5210ab8a15a0dad2f27e87983180b4cc137a35b230203010001028201010083c29335bac54941d23600f0a7eb689559fc5a69ec96733a33d9700ff6eb37edc38c60b8b2b2b7803cbbba6b4a8cd6c436f15d313301402f067feedbf11f6f92ca295082ec5754b2100e7cba841fd9db07333c725ea28e2562b7f600b23d6316b22cdda654d3769088030ec3479b3fcb05af3cb00f620d00c9c7dfd227ca5f3047b431f7e04c020e93a429df8389110a76fbfd53d31568a4c30f9fa4d72aceaccc81d49c27eda797fd084e228bd1434f44f60ddf5ca3e6cd99963923bafe01f61063268a90ceeb530995956d15bfea0b84ec2ed0251913dd751de19853e4c32dd47941cdd10791c36fd81f05c9b2a1c7860442772a3c5e6669fa7258d3d2bfa102818100cad3307770b8947adaf4d84ba3d92941c5f22b1d279b2ddbf65e2dbac14c354b9f24799885103d46d07df1cd8a49e7577ede8363c5d4389ba37c510cb077dcd9ca8d730655e77af325c62c9d41eb24ab8d281a3758927397e015766aaf5080f34a57a0e4bd890f644f0b41238f9073155990fb32c41d6671b79fe7675aa624d102818100fb6710488a0bf3f32a05c35584a659f9e011cf93f4126caeb795b87784fedd65d0365663839d304fa2c406fe1df341e5d1a2430a0bc633338f9c066217b38c1523ed25b7c9b3c1a3529a3fc95f1d28c3e3103c6f0f1ab005b29069c513423d22f0c0f31daa760924abb7d1505f987309c62291f2dde65d1b3043d49506490db302818100c145715fbf8803e4f6146eafd558301a3ef7bee1af460df316d733984c6dc4336558aa8e0dee2595ff42a4520a3ed635e7ed3d22abf6c86276ed158693fa03f77d2e40b77ed06fb696fe3ab137894c8e349a4c310533b8f6b64f7d61b7e16c9f68ee0ba12c8318a9ab30bc47989c3b2dd30576792fac1c5cac6fb160295f3ca10281805ddf2af65b0d81869f7f4d63a647533b794e4d3b0a9cc2962e98aa2b7eae87ced7832298bff136b3d5abea8c82746d7bb9de23b821935d54f85fa30687a11442648acd55a5ec07f6cb062ba12e71bde1feebf614e607ea080697e3d6a18d4f34b7bee4488478d48b2bcf5449f59800047b463746ff52601ba1d7020eaf2d21ff02818006708fcf365923530b3f7d24188984b3cc6037ce46253801cf8a7736c2f379b355f2ab896fa7579486641375e6b804c12a913cc55d75baeabf5acf0023b9028705d98de20c0c256fdd12cbe8298ec1f5b9b659238254a8ab64ffc33e32751a01f610027dd19ee33a434e2d15203a770eb0e0ccc8a412e8b8d82729f451d69ab3
        // rsa plaintext: 0x1234abcd
        // rsa ciphertext: 0x0160fbf6a2071042a29a44602e217f613baa1414dd216a86b9da29f98a0410d510708de04e34e6e5ba649de52c3b31a352c833fac35d808fecfce63a981718c9d920b90a58d8885f5a16724eb89e5e912a21d2907b605b013af58427ec87cdb054f9bf6f1254ba51d9a982d803c3c3c9849172cdff0b68055f5b4850215a33a6bb7c9d456a754cd9a89d489fbf0fccecc5166766793cfe267927b3b9ce5c21375ce8dc808889cf4f5999f9b098c75d8d14ad317242d4981523901b108b13138b8d7f925b4a34024b01f0093108063db0f883c30ab855c7d6fa689481493f42fc85d3c6d5843d30bea698ab34d05288b61b397427822cafab400e50132cfa1a39
    }

    #[test]
    fn test_rsa_from_given_keypair() {
        // generated from golang crypto lib. 
        let pk_der_hex = "0x3082010a0282010100c70b3183b6d939b070e74190c0cf32202e883629df138cc42d8aec30ac17be65a6ae1c11a682f531e740ec15f95ed348f6ca87d1833454952cf83d8ef24dee36f8ca84b5f164e2f5c292c3b18c2ce6b98e8753d299eb3abcafd581ddc4d5c43f4658a563a2ae6885b1ef694b8cd07a5608509a52197981fd743e3b3f3d0f69ca36cb6bc91876e02cd9f25bb8b128283d397ed8fad8c03bc488f306a789998a720a9e4ebe1a3550293428bf1525a4155ffcaad01f6720bfe31d0ad28b24753fb67344d01cc921a13d69b9935394855d140abe15365966b9259bce87734cc6d0d2195607c1fcf4d0464be7d6df7d6b933c822231bb5414f62e0e49b27a133fc8130203010001".to_owned();
        let sk_der_hex = "0x308204a30201000282010100c70b3183b6d939b070e74190c0cf32202e883629df138cc42d8aec30ac17be65a6ae1c11a682f531e740ec15f95ed348f6ca87d1833454952cf83d8ef24dee36f8ca84b5f164e2f5c292c3b18c2ce6b98e8753d299eb3abcafd581ddc4d5c43f4658a563a2ae6885b1ef694b8cd07a5608509a52197981fd743e3b3f3d0f69ca36cb6bc91876e02cd9f25bb8b128283d397ed8fad8c03bc488f306a789998a720a9e4ebe1a3550293428bf1525a4155ffcaad01f6720bfe31d0ad28b24753fb67344d01cc921a13d69b9935394855d140abe15365966b9259bce87734cc6d0d2195607c1fcf4d0464be7d6df7d6b933c822231bb5414f62e0e49b27a133fc81302030100010282010036caed097e37543b2f096a3227f1a1b1dc3d60f3abd61ce5104872f67f19562f736ff08827575b9a2e37e005b88d130abded48f032f71fe5a4e87d41b19024687b9a7c67fd98b125c83750a9ba95cdb9fcf361eed2b23f8c1bb761b5a3eed8c4366046bf23d4712f84a90c4a60ec2f1129dece6c9558aea10ff3e5a965ecad4921f5358c9c4a07fccc44cba795a116185bad0c71359ef5357b9f90d3538c8692ce95e9c755707d5569961549b630abaebc50f1c505cec737ad07b09bdd9a5ffc1f5bff1e5f513a46ec973d7110218db2946911dcf053d1ea8efe4feebaa693fef75a9f55b1e12b36fc17bdaf39e9c70aa86548049718c8d9f688dd58608d6be902818100dc5c0f58f61626a60fdd12d7c0d82cbfc59bbdd16b462c56905a1833152ded6777064120dab7a9f4708833d78af5d9c31f658b2ed41317f46358ee21bd44e2067d1f6cd4acf6526da64033bef05a223ba4102434b0bfbf106ca3dd14f6b041da6d90ab8d741dc12d4521c19eef257124895795748565be8b949c0ab663f4ac7f02818100e73c8dd5ebb58fec95878e9a39f672b16efc606b483634e278f904e402ad1cbee64850a13090c7cb84d0ca965750d292c67c73ddc01bee405054666d085e5c7d03cf29c76a675d8299cbc9b03b8617195c6591adb90b85e797e77693248f9e160f8f6680a909f4f18f5afeb8153f8cb97d4149f67a094f4af5f11662ab7aaa6d0281801c067d513423071151ad2d2b51746ce48aee4ecae698cb24cb411a18cd15c53ec66d7e34fe7c235a5a41884e5e76fc160bd52f496a616f477ea71dca1eb73703da3ff7e86882ff62c0a523afa203e49caf35fa54d531ddcbe9f54135dc55f85a1e5b2ae657a13d2353ca82448367c0a703eca6ae6614d5920cf9778750d91a6302818100a64153794b4fef7b1ac7ac30171caaba08224cf0d5aaa3bb715f19b516778103806ede0a06f111b5b278ac300bf7806f2766b3a7ec4828b4f50cb9d80afc4d635529cdd02320ce8ae8292d8a184200b9ab451bc8dc12fce3d6c404ed268c5c0d6082aa20376981436cdeefe54ae1b63c676259db6d42e44ff124b6039b6746c1028180320be9332da15c2dee69bdb6e4887a7448b312f03074a30ec1178d6f51ced1ebea283bff0c90b1bbb9a0aed631a8b272c094b17938c02376a2ea03c25fdd14ac5120252f5563e8ce0addd75027e15a043bc57d88b2f91dd9f95dd936bb470f62955cf9c59f1fbef604a70c6fd48d6abf528cc65b208c16427d9e452b1ce043b8".to_owned();


        let plaintext = "0xabcd1234".to_owned();
        println!("rsa plaintext: {}", plaintext);
        let ciphertext = super::rsa_encrypt(pk_der_hex.clone(), plaintext.clone());
        println!("rsa ciphertext: {}", ciphertext);
        let recovered = super::rsa_decrypt(sk_der_hex.clone(), ciphertext.clone());
        assert_eq!(recovered, plaintext);


        // generated from golang crypto lib. 
        let ciphertext = "0x9defe1bcf66bdc891263d5260dbbd02d70cedb8924b7ad121a01b80ebc758fc1f5afecac86a5d563582b81afddbde8f6c1586a6ade8510f567786b7c70fb51700f4c074b22fd573fa383f836cfd127830efc534bd8a6d7c9dd95563172b15055acc29a250e48617e94f2a2b107d654752c3b7560ac468ebc52025971c7a14570dc2043c8cf0b56658c6ed1877924ef286b7a21812ce34575d9a22efba9913804ecbd526926174a432de26d2c7b12a2528866ceecaccac1db14d92392f0a09ef41407e978819dc953fcf511b0a499cf45a0cf9a41ff003c0c8ee5cbaad51d49a5e25996b106311d28e4661ddda3ff357f918612dee30eb5c7caf89e904a755992".to_owned();
        let recovered = super::rsa_decrypt(sk_der_hex.clone(), ciphertext.clone());
        assert_eq!(recovered, "0xabcd1234".to_owned());

    }

    #[test]
    fn test_ed25519_from_new_keypair() {
        let kp = super::new_ed25519_keypair();
        println!("ed25519 pub_key: {}", kp.pk);
        println!("ed25519 sk_key: {}", kp.sk);

        let msg = "0x1234abcd".to_owned();
        println!("ed25519 msg: {}", msg);
        let sig = super::ed25519_sign(msg.clone(), kp.sk.clone());
        println!("ed25519 sig: {}", sig);
        assert!(super::ed25519_verify(sig.clone(), msg, kp.pk.clone()));

		// ed25519 pub_key: 0xb7ce60a8da0fa85030cbca3e4f862d363a5b02095e5f91c1edcf0d81b7adb702
		// ed25519 sk_key: 0x2ec9dd53043ab33ab602f954cdc0b180df3c18c7406c78f81127f9497fdb78c5
		// ed25519 msg: 0x1234abcd
		// ed25519 sig: 0x7a6543e5d6a6cf492ef82530a0996e94fe67c1fff10cbfa02fd16c63c9c197f96d1c50f027995ce2efe5ed6f4081c0ea49037f585b2454b77e2c4f033f6c4e00
    }

    #[test]
    fn test_ed25519_from_given_keypair() {
        let sk = "0xe96b2d1ace52a7260cd8ea2dc848ffcbfbe696e525e191b665cad4a7f2bfb7d6".to_owned();
        let pk = "0xabf2b9f541120c65a461c5e69051720d40b8f2269ea7b4253eb427ec4d588ecc".to_owned();
        let msg = "0x1234abcd".to_owned();
        let expected_sig = "0xfedbe9734dced4be853d26a4f9b0cf60ffbc9946291a1642721b5fccaabd29614e6d41ba92c9e25e50cf07fe94d0ca9a8d3c608ab9fff5a94bc7cb282777d901".to_owned();

        println!("ed25519 msg: {}", msg);
        let sig = super::ed25519_sign(msg.clone(), sk.clone());
        println!("ed25519 sig: {}", sig);
        assert!(super::ed25519_verify(sig.clone(), msg, pk.clone()));
        assert_eq!(expected_sig, sig);
    }
}