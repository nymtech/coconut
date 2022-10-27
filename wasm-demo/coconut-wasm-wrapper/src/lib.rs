// Copyright 2022 Nym Technologies SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use coconut_rs::{
    aggregate_signature_shares, aggregate_verification_keys, blind_sign, elgamal, hash_to_scalar,
    prepare_blind_sign, prove_credential, ttp_keygen, verify_credential, BlindedSignature, KeyPair,
    Parameters, Signature, SignatureShare, VerificationKey,
};
use js_sys::Array;
use rand::prelude::SliceRandom;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

mod utils;

pub use utils::set_panic_hook;

#[wasm_bindgen]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RawAttribute {
    value: String,
    is_private: bool,
}

#[wasm_bindgen]
#[derive(Debug, Serialize, Deserialize)]
pub struct IssuedPartialSignatures {
    blinded: BlindedSignature,
    unblinded: Signature,
}

#[wasm_bindgen]
#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureAggregationResult {
    used_indices: Vec<u64>,
    aggregated_signature: Signature,
}

#[wasm_bindgen]
#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationKeysAggregationResult {
    used_indices: Vec<u64>,
    aggregated_verification_key: VerificationKey,
}

#[wasm_bindgen]
impl RawAttribute {
    #[wasm_bindgen(constructor)]
    pub fn new(value: String, is_private: bool) -> Self {
        Self { value, is_private }
    }
}

#[wasm_bindgen]
pub struct CoconutDemoState {
    pub threshold: u64,
    params: Parameters,
    client_elgamal: elgamal::ElGamalKeyPair,
    raw_attributes: Vec<RawAttribute>,
    signing_authorities: Vec<KeyPair>,
    issued_signatures: Vec<IssuedPartialSignatures>,
    aggregated_credential: Option<Signature>,
}

#[wasm_bindgen]
impl CoconutDemoState {
    #[wasm_bindgen(constructor)]
    pub fn new(max_attributes: u32, num_signing_authorities: u64, threshold: u64) -> Self {
        let params = Parameters::new(max_attributes).unwrap();
        let client_elgamal = elgamal::elgamal_keygen(&params);
        let signing_authorities = ttp_keygen(&params, threshold, num_signing_authorities).unwrap();

        console_warn!("creating coconutdemostate");

        CoconutDemoState {
            threshold,
            params,
            signing_authorities,
            client_elgamal,
            raw_attributes: Vec::new(),
            issued_signatures: Vec::new(),
            aggregated_credential: None,
        }
    }

    pub fn signing_authorities_public_keys(&self) -> JsValue {
        let vks = &self
            .signing_authorities
            .iter()
            .map(|key| key.verification_key())
            .collect::<Vec<_>>();

        serde_wasm_bindgen::to_value(&vks).unwrap()
    }

    #[wasm_bindgen(getter)]
    pub fn current_credential(&self) -> JsValue {
        if let Some(ref credential) = self.aggregated_credential {
            let serialized = serde_wasm_bindgen::to_value(credential).unwrap();
            serialized
        } else {
            console_error!("Cannot return credential value - no credential was actually issued");
            JsValue::NULL
        }
    }

    pub fn randomise_credential(&mut self) -> JsValue {
        if let Some(credential) = self.aggregated_credential.as_mut() {
            let randomised = credential.randomise(&self.params);
            let serialized = serde_wasm_bindgen::to_value(&randomised).unwrap();
            *credential = randomised;
            serialized
        } else {
            console_error!("Cannot randomise credential - no credential was actually issued");
            JsValue::NULL
        }
    }

    pub fn issued_signatures(&self) -> JsValue {
        serde_wasm_bindgen::to_value(&self.issued_signatures).unwrap()
    }

    pub fn aggregate_signatures(&mut self) -> JsValue {
        let indices = (1u64..=self.issued_signatures.len() as u64).collect::<Vec<_>>();
        let samples: Vec<_> = indices
            .choose_multiple(&mut rand::thread_rng(), self.threshold as usize)
            .copied()
            .collect();

        let target_sigs: Vec<_> = samples
            .iter()
            .map(|&id| SignatureShare::new(self.issued_signatures[id as usize - 1].unblinded, id))
            .collect();

        let aggregated_signature =
            aggregate_signature_shares(&target_sigs).expect("failed to aggregate signatures");

        let res = SignatureAggregationResult {
            used_indices: samples,
            aggregated_signature,
        };
        let serialized = serde_wasm_bindgen::to_value(&res).unwrap();
        self.aggregated_credential = Some(res.aggregated_signature);
        serialized
    }

    pub fn aggregate_verification_keys(&mut self) -> JsValue {
        let indices = (1u64..=self.issued_signatures.len() as u64).collect::<Vec<_>>();
        let samples: Vec<_> = indices
            .choose_multiple(&mut rand::thread_rng(), self.threshold as usize)
            .copied()
            .collect();

        let target_vks: Vec<_> = samples
            .iter()
            .map(|&id| self.signing_authorities[id as usize - 1].verification_key())
            .collect();

        let aggregated_verification_key = aggregate_verification_keys(&target_vks, Some(&samples))
            .expect("failed to aggregate verification keys");

        let res = VerificationKeysAggregationResult {
            used_indices: samples,
            aggregated_verification_key,
        };
        let serialized = serde_wasm_bindgen::to_value(&res).unwrap();
        // self.aggregated_credential = Some(res.aggregated_signature);
        serialized
    }

    pub fn verify_credential(
        &self,
        raw_attributes: Array,
        credential: JsValue,
        aggregated_vk: JsValue,
    ) -> bool {
        let raw_attributes: Vec<RawAttribute> = raw_attributes
            .iter()
            .map(|val| serde_wasm_bindgen::from_value(val).unwrap())
            .collect();

        let credential: Signature = serde_wasm_bindgen::from_value(credential).unwrap();
        let vk: VerificationKey = serde_wasm_bindgen::from_value(aggregated_vk).unwrap();

        let public = raw_attributes
            .iter()
            .filter(|attr| !attr.is_private)
            .map(|attr| hash_to_scalar(&attr.value))
            .collect::<Vec<_>>();

        let private = raw_attributes
            .iter()
            .filter(|attr| attr.is_private)
            .map(|attr| hash_to_scalar(&attr.value))
            .collect::<Vec<_>>();

        let theta = prove_credential(&self.params, &vk, &credential, &private)
            .expect("failed to prove the credential!");

        verify_credential(&self.params, &vk, &theta, &public)
    }

    #[wasm_bindgen(setter)]
    pub fn set_raw_attributes(&mut self, raw_attributes: Array) {
        let raw_attributes: Vec<RawAttribute> = raw_attributes
            .iter()
            .map(|val| serde_wasm_bindgen::from_value(val).unwrap())
            .collect();

        self.raw_attributes = raw_attributes
    }

    pub fn blind_sign_attributes(&mut self) -> JsValue {
        let public = self
            .raw_attributes
            .iter()
            .filter(|attr| !attr.is_private)
            .map(|attr| hash_to_scalar(&attr.value))
            .collect::<Vec<_>>();

        let private = self
            .raw_attributes
            .iter()
            .filter(|attr| attr.is_private)
            .map(|attr| hash_to_scalar(&attr.value))
            .collect::<Vec<_>>();

        let lambda = prepare_blind_sign(
            &self.params,
            self.client_elgamal.public_key(),
            &private,
            &public,
        )
        .expect("failed to create a blind sign request");

        let signatures = self
            .signing_authorities
            .iter()
            .map(|sa| {
                let blinded_sig = blind_sign(
                    &self.params,
                    &sa.secret_key(),
                    self.client_elgamal.public_key(),
                    &lambda,
                    &public,
                )
                .expect("failed to blind sign attributes");
                let unblinded_sig = blinded_sig.unblind(self.client_elgamal.private_key());
                IssuedPartialSignatures {
                    blinded: blinded_sig,
                    unblinded: unblinded_sig,
                }
            })
            .collect::<Vec<_>>();

        let serialized = serde_wasm_bindgen::to_value(&signatures).unwrap();
        self.issued_signatures = signatures;
        serialized
    }
}

// will cause messages to be written as if console.log("...") was called
#[macro_export]
macro_rules! console_log {
    ($($t:tt)*) => ($crate::log(&format_args!($($t)*).to_string()))
}

// will cause messages to be written as if console.warm("...") was called
#[macro_export]
macro_rules! console_warn {
    ($($t:tt)*) => ($crate::warn(&format_args!($($t)*).to_string()))
}

// will cause messages to be written as if console.error("...") was called
#[macro_export]
macro_rules! console_error {
    ($($t:tt)*) => ($crate::error(&format_args!($($t)*).to_string()))
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(s: &str);

    #[wasm_bindgen(js_namespace = console)]
    pub fn warn(s: &str);

    #[wasm_bindgen(js_namespace = console)]
    pub fn error(s: &str);
}
