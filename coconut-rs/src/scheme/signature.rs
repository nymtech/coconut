// Copyright 2021 Nym Technologies SA
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

use bls12_381::{G1Affine, G1Projective};
use group::GroupEncoding;
use rand_core::{CryptoRng, RngCore};

use crate::error::Result;
use crate::proofs::ProofOfS;
use crate::scheme::setup::Parameters;
use crate::scheme::SecretKey;
use crate::utils::hash_g1;
use crate::{elgamal, Attribute};

pub struct Signature(G1Projective, G1Projective);

impl Signature {
    fn randomise<R: RngCore + CryptoRng>(&self, params: &Parameters<R>) -> Signature {
        todo!()
    }
}

pub struct BlindedSignature(G1Projective, elgamal::Ciphertext);

impl BlindedSignature {
    fn unblind<R: RngCore + CryptoRng>(
        self,
        params: &Parameters<R>,
        private_key: &elgamal::PrivateKey,
    ) -> Signature {
        let sig2 = private_key.decrypt(&self.1);
        Signature(self.0, sig2)
    }
}

// perhaps this should take signature by reference? we'll see how it goes
struct SignatureShare {
    signature: Signature,
    index: Option<u64>,
}

/// Produces h0 ^ m0 * h1^m1 * .... * hn^mn
// TODO: is it an actual commitment?
fn construct_attribute_commitment(
    private_attributes: &[Attribute],
    public_attributes: &[Attribute],
    generators: &[G1Affine],
) -> G1Projective {
    private_attributes
        .iter()
        .chain(public_attributes.iter())
        .zip(generators)
        .map(|(&m, h)| h * m)
        .sum()
}

// Lambda
pub struct BlindSignRequest {
    commitment: G1Projective,                         // cm
    attributes_ciphertexts: Vec<elgamal::Ciphertext>, // c
    pi_s: ProofOfS,                                   // pi_s
}

pub fn prepare_blind_sign<R: RngCore + CryptoRng>(
    params: &mut Parameters<R>,
    pub_key: &elgamal::PublicKey,
    private_attributes: &[Attribute],
    public_attributes: &[Attribute],
) -> Result<BlindSignRequest> {
    if private_attributes.is_empty() {
        // return Err
    }

    let hs = params.additional_g1_generators();
    if hs.len() < private_attributes.len() + public_attributes.len() {
        // return Err
    }

    // prepare commitment
    let attr_cm = construct_attribute_commitment(private_attributes, public_attributes, hs);
    let blinding_factor = params.random_scalar();
    let commitment = params.gen1() * blinding_factor + attr_cm;

    // build ElGamal encryption
    let commitment_hash = hash_g1(commitment.to_bytes());
    let (attributes_ciphertexts, ephemeral_keys): (Vec<_>, Vec<_>) = private_attributes
        .iter()
        .map(|m| pub_key.encrypt(params, &commitment_hash, m))
        .unzip();

    let pi_s = ProofOfS::construct(
        params,
        pub_key,
        &ephemeral_keys,
        &commitment,
        &blinding_factor,
        private_attributes,
        public_attributes,
    );

    Ok(BlindSignRequest {
        commitment,
        attributes_ciphertexts,
        pi_s,
    })
}
