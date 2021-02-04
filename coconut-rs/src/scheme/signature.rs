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

use crate::error::Result;
use crate::scheme::setup::Parameters;
use crate::scheme::SecretKey;
use crate::{elgamal, Attribute};
use bls12_381::{G1Affine, G1Projective};
use rand_core::{CryptoRng, RngCore};

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

// TODO: is `derive` a correct word here?
/// Produces h0 ^ m0 * h1^m1 * .... * hn^mn
fn derive_group_element(
    private_attributes: &[&Attribute],
    public_attributes: &[&Attribute],
    generators: &[G1Affine],
) -> G1Projective {
    private_attributes
        .iter()
        .chain(public_attributes.iter())
        .zip(generators)
        .map(|(&m, h)| h * m)
        .sum()
}

pub fn prepare_blind_sign<R: RngCore + CryptoRng>(
    params: &mut Parameters<R>,
    pub_key: &elgamal::PublicKey,
    private_attributes: &[&Attribute],
    public_attributes: &[&Attribute],
) -> Result<Signature> {
    if private_attributes.is_empty() {
        // return Err
    }

    let hs = params.additional_g1_generators();
    if hs.len() < private_attributes.len() + public_attributes.len() {
        // return Err
    }

    // prepare commitment
    let attr_cm = derive_group_element(private_attributes, public_attributes, hs);
    let r = params.random_scalar();
    let cm = params.gen1() * r + attr_cm;
    // h = hashG1(cm)...

    todo!()
}
