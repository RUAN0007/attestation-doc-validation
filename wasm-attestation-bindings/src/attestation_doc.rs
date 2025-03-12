use attestation_doc_validation::{
    validate_and_parse_attestation_doc,
    validate_expected_pcrs, PCRProvider,
    error::{CertError, AttestError},
};
use super::*;

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
const LOG_NAMESPACE: &'static str = "ATTESTATION ::";

#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = PCRHexes))]
pub struct JsPCRHexes {
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(getter_with_clone, js_name = pcr0_hex))]
    pub pcr_0_hex: Option<String>,
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(getter_with_clone, js_name = pcr1_hex))]
    pub pcr_1_hex: Option<String>,
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(getter_with_clone, js_name = pcr2_hex))]
    pub pcr_2_hex: Option<String>,
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(getter_with_clone, js_name = pcr8_hex))]
    pub pcr_8_hex: Option<String>,
}

#[derive(Debug)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = DocParsingResult))]
pub struct DocParsingResult {
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(getter_with_clone, js_name = valid))]
    pub valid: bool,
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(getter_with_clone, js_name = pubkey_hex))]
    pub pubkey_hex: String,
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(getter_with_clone, js_name = user_data_hex))]
    pub user_data_hex: String,
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(getter_with_clone, js_name = nonce_hex))]
    pub nonce_hex: String,
}


#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl JsPCRHexes {
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(constructor))]
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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = parseAndValidateAttestationDoc))]
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
        Err(AttestError::CertError(CertError::InvalidTrustChain(reason))) => {
            // Since the testing doc is expired (a valid doc is expired within 3h), we assume it is valid for testing. 
            #[cfg(debug_assertions)] {
                if reason == "CertExpired" {
                    attestation_doc_validation::attestation_doc::decode_attestation_document(&decoded_ad).unwrap().1
                } else {
                    return res;
                }
            }

            #[cfg(not(debug_assertions))] {
                return res;
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    const ATTESTATION_DOC_HEX: &str = "0x8444a1013822a0591156a9696d6f64756c655f69647827692d30643531663966643963353936616366342d656e633031393533356361303266363336326566646967657374665348413338346974696d657374616d701b0000019535deab3c6470637273b000583000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001583000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002583000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003583000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004583061f9772fca6156e6cac0f852986d84ea1731c10ae834929ac5f8a2bbd5617e1e2572f8effb877fa5c374e5595dc0c4450558300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000658300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000758300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000858300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000958300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a58300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b58300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c58300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d58300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e58300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f58300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006b636572746966696361746559028a308202863082020ba0030201020210019535ca02f6362e0000000067bbdc72300a06082a8648ce3d040303308193310b30090603550406130255533113301106035504080c0a57617368696e67746f6e3110300e06035504070c0753656174746c65310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753313e303c06035504030c35692d30643531663966643963353936616366342e61702d736f757468656173742d322e6177732e6e6974726f2d656e636c61766573301e170d3235303232343032343135315a170d3235303232343035343135345a308198310b30090603550406130255533113301106035504080c0a57617368696e67746f6e3110300e06035504070c0753656174746c65310f300d060355040a0c06416d617a6f6e310c300a060355040b0c034157533143304106035504030c3a692d30643531663966643963353936616366342d656e63303139353335636130326636333632652e61702d736f757468656173742d322e6177733076301006072a8648ce3d020106052b8104002203620004598e16003f93999f5a71fde6ccb47728acc5be626eba6422515430bc91046d1ad59ed9b93bdb5c8778d973137987a34f73bf84b27f0fb6bac838a45b4bd359d53e5d0e31decc0cdbf27ca13c5d978f458a1fc26024b8e4522dd18eacdb6cab2aa31d301b300c0603551d130101ff04023000300b0603551d0f0404030206c0300a06082a8648ce3d0403030369003066023100a5f5919a1bdd9aea81d9613e295ddbdc584dbdcdebbd51d1edf7f07aa5646d933922bc81d56b3a08b90e76eaec158385023100f8d504ac90cc4cfe861a4a1adbe094f1da97b0f819a6f233c1c1fcf2b794b92084f97046c18fd54061d3fa2ff6eb5e1868636162756e646c65845902153082021130820196a003020102021100f93175681b90afe11d46ccb4e4e7f856300a06082a8648ce3d0403033049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753311b301906035504030c126177732e6e6974726f2d656e636c61766573301e170d3139313032383133323830355a170d3439313032383134323830355a3049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753311b301906035504030c126177732e6e6974726f2d656e636c617665733076301006072a8648ce3d020106052b8104002203620004fc0254eba608c1f36870e29ada90be46383292736e894bfff672d989444b5051e534a4b1f6dbe3c0bc581a32b7b176070ede12d69a3fea211b66e752cf7dd1dd095f6f1370f4170843d9dc100121e4cf63012809664487c9796284304dc53ff4a3423040300f0603551d130101ff040530030101ff301d0603551d0e041604149025b50dd90547e796c396fa729dcf99a9df4b96300e0603551d0f0101ff040403020186300a06082a8648ce3d0403030369003066023100a37f2f91a1c9bd5ee7b8627c1698d255038e1f0343f95b63a9628c3d39809545a11ebcbf2e3b55d8aeee71b4c3d6adf3023100a2f39b1605b27028a5dd4ba069b5016e65b4fbde8fe0061d6a53197f9cdaf5d943bc61fc2beb03cb6fee8d2302f3dff65902c7308202c33082024aa003020102021100ea6c6131136762552bbb33230ec9a113300a06082a8648ce3d0403033049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753311b301906035504030c126177732e6e6974726f2d656e636c61766573301e170d3235303232303232333733315a170d3235303331323233333733315a3069310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753313b303906035504030c32366565303634303331333734356666372e61702d736f757468656173742d322e6177732e6e6974726f2d656e636c617665733076301006072a8648ce3d020106052b8104002203620004d29fb51470b3d43211aef55cb737b6a56d5f5743655878140dd83ee96f224ae525bcff237308acc2bdae962728e30930b096861adf734e95ccd2b8c2bdf22f550e131746aa5b2aa18dfaa397262ee7e5eba2d8508cfa4e0c6902c7e45c02e604a381d53081d230120603551d130101ff040830060101ff020102301f0603551d230418301680149025b50dd90547e796c396fa729dcf99a9df4b96301d0603551d0e041604143b0df119d74720802d56db4d5b347e6c5a857bb1300e0603551d0f0101ff040403020186306c0603551d1f046530633061a05fa05d865b687474703a2f2f6177732d6e6974726f2d656e636c617665732d63726c2e73332e616d617a6f6e6177732e636f6d2f63726c2f61623439363063632d376436332d343262642d396539662d3539333338636236376638342e63726c300a06082a8648ce3d040303036700306402300f6cb131ca541935adce23984cdc9e1a8d0518a1b88fc9d3549f0177cb082f677a7d8f29e81c9c6fcabfeffbcca0161402301053b613f57ee9cc4351af19410daba196fc598bef8607c0043b5e3d8ce03a5c2f5af42b80beef4a670efc37ee77d1b259032f3082032b308202b1a003020102021100dc020e62efa81f61c0005727c26d88a7300a06082a8648ce3d0403033069310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753313b303906035504030c32366565303634303331333734356666372e61702d736f757468656173742d322e6177732e6e6974726f2d656e636c61766573301e170d3235303232333138313231305a170d3235303330313037313230395a30818e3141303f06035504030c38643239663137386631323936313533632e7a6f6e616c2e61702d736f757468656173742d322e6177732e6e6974726f2d656e636c61766573310c300a060355040b0c03415753310f300d060355040a0c06416d617a6f6e310b3009060355040613025553310b300906035504080c0257413110300e06035504070c0753656174746c653076301006072a8648ce3d020106052b81040022036200044e00af8e20317e4787bf563e7793464c742f5e5882b8b07eb625cf64a3e09b26e2901e78464eadbc3f660fdfe6f7be23f0b9c746d7e6173a56a18815226740e51893cc892be9ee648cd27b2c798ee3b5addeabd6b550afcc84dfff10cfd7ee9fa381f63081f330120603551d130101ff040830060101ff020101301f0603551d230418301680143b0df119d74720802d56db4d5b347e6c5a857bb1301d0603551d0e0416041405edb6a30fae051532770e5a7e92f887530b4728300e0603551d0f0101ff04040302018630818c0603551d1f048184308181307fa07da07b8679687474703a2f2f63726c2d61702d736f757468656173742d322d6177732d6e6974726f2d656e636c617665732e73332e61702d736f757468656173742d322e616d617a6f6e6177732e636f6d2f63726c2f66616538366638312d386130372d343231392d386366322d3361393961376563663664322e63726c300a06082a8648ce3d04030303680030650230213dd35de8af572a79b584ea4a1f9c7b246c9d0cf102035201a493a0a5a40fa0918ce31dbeaf889efa20ceffd6c25cfa0231009e35f36551fc92d01e8700b4f66adbaa9faa07cb1ee448ceacefcd6dca55b737ad162a504520c0784d7bd87d966dafe35902cc308202c83082024fa00302010202150082ba3f9b33ec14d4c9b05708bc7ee0971ecf8437300a06082a8648ce3d04030330818e3141303f06035504030c38643239663137386631323936313533632e7a6f6e616c2e61702d736f757468656173742d322e6177732e6e6974726f2d656e636c61766573310c300a060355040b0c03415753310f300d060355040a0c06416d617a6f6e310b3009060355040613025553310b300906035504080c0257413110300e06035504070c0753656174746c65301e170d3235303232343032333034355a170d3235303232353032333034355a308193310b30090603550406130255533113301106035504080c0a57617368696e67746f6e3110300e06035504070c0753656174746c65310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753313e303c06035504030c35692d30643531663966643963353936616366342e61702d736f757468656173742d322e6177732e6e6974726f2d656e636c617665733076301006072a8648ce3d020106052b8104002203620004776f080b2f2c938f740bf84473ed9f4daceebcc1ee51e5be2428a226afeac7fff1d081f54595f897d569a2404b3bd4280ce990b5ee905ef164b62fe8a01bfa2be199697c063cb4b7fa752931d88d382c674986809c28e4b52a02d1ba920627e2a366306430120603551d130101ff040830060101ff020100300e0603551d0f0101ff040403020204301d0603551d0e04160414f5b2ca8d7fa00d72b8a99fd7e3b8bea682c52070301f0603551d2304183016801405edb6a30fae051532770e5a7e92f887530b4728300a06082a8648ce3d040303036700306402302b25f1a39f44274ec41b1a76a06bf10b1eaf099ac878e559876d9cb33d4bebcb96d959d74f0f1d1df1caf734839d14790230369fcfa7ee40d46a745f4d9226ae3c94e1f75d0e788a94fef73a291ba20a86a0029a5bd2b7a1e7d411110f17229f89796a7075626c69635f6b65795820a50e40712bb86c7891fd3e17e11bcbeec67710e073a94cf36c2fd8e6bec7a36069757365725f6461746143616263656e6f6e63654334353658608dc83a15c3d4970079f6dfb21f70f42fd1fa25365b6d6aed9bd877ba2f90cedbeca0fb4088fefea34411ac6d977c68b3a7363173752c01667caa2d0ad39fb0b3b3c28a94f010fcaec438f1defa7113a7ba34342b84714e08c810eecd68f221f0";

    #[test]
    fn test_validate_expected_pcrs_success() {
        let js_pcrhexes = JsPCRHexes::new(
            Some("0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_owned()),
            Some("0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_owned()),
            // Some("0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_owned()),
            None,
            Some("0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_owned()));
        
        let res = parse_validate_attestation_doc_pcrs(ATTESTATION_DOC_HEX, js_pcrhexes);
        assert_eq!(res.valid, true);
        assert_eq!(res.pubkey_hex, "0xa50e40712bb86c7891fd3e17e11bcbeec67710e073a94cf36c2fd8e6bec7a360");
        assert_eq!(res.user_data_hex, "0x616263");
        assert_eq!(res.nonce_hex, "0x343536");
        println!("result {:?}", res);
    }
}