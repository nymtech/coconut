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

// TODO: implement https://crates.io/crates/signature traits?

use crate::elgamal;
use crate::error::Result;
use crate::scheme::aggregation::{aggregate_signature_shares, aggregate_signatures};
use crate::scheme::setup::Parameters;
use bls12_381::G1Projective;
pub use keygen::{SecretKey, VerificationKey};
use rand_core::{CryptoRng, RngCore};

pub mod aggregation;
pub mod issuance;
pub mod keygen;
pub mod setup;
pub mod verification;

pub type SignerIndex = u64;

// (h, s)
#[derive(Debug, Clone, Copy)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Signature(pub(crate) G1Projective, pub(crate) G1Projective);
// just a type alias for ease of use
pub type Credential = Signature;

pub type PartialSignature = Signature;

impl Signature {
    pub(crate) fn sig1(&self) -> &G1Projective {
        &self.0
    }

    pub(crate) fn sig2(&self) -> &G1Projective {
        &self.1
    }

    pub fn randomise<R: RngCore + CryptoRng>(&self, params: &mut Parameters<R>) -> Signature {
        let r = params.random_scalar();
        Signature(self.0 * r, self.1 * r)
    }

    pub fn aggregate(sigs: &[Self], indices: Option<&[SignerIndex]>) -> Result<Self> {
        aggregate_signatures(sigs, indices)
    }
}

pub struct BlindedSignature(pub G1Projective, pub elgamal::Ciphertext);
// pub struct BlindedSignature(G1Projective, elgamal::Ciphertext);

impl BlindedSignature {
    pub fn unblind(self, private_key: &elgamal::PrivateKey) -> Signature {
        let sig2 = private_key.decrypt(&self.1);
        Signature(self.0, sig2)
    }
}

// perhaps this should take signature by reference? we'll see how it goes
pub struct SignatureShare {
    signature: Signature,
    index: SignerIndex,
}

impl SignatureShare {
    pub fn new(signature: Signature, index: SignerIndex) -> Self {
        SignatureShare { signature, index }
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    pub fn index(&self) -> SignerIndex {
        self.index
    }

    pub fn aggregate(shares: &[Self]) -> Result<Signature> {
        aggregate_signature_shares(shares)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme::aggregation::aggregate_verification_keys;
    use crate::scheme::issuance::{blind_sign, prepare_blind_sign, sign};
    use crate::scheme::keygen::{keygen, ttp_keygen};
    use crate::scheme::verification::{prove_credential, verify, verify_credential};
    use rand_core::OsRng;

    #[test]
    fn verification_on_two_public_attributes() {
        let rng = OsRng;

        let mut params = Parameters::new(rng, 2).unwrap();
        let attributes = params.n_random_scalars(2);

        let keypair1 = keygen(&mut params);
        let keypair2 = keygen(&mut params);
        let sig1 = sign(&mut params, &keypair1.secret_key, &attributes).unwrap();
        let sig2 = sign(&mut params, &keypair2.secret_key, &attributes).unwrap();

        assert!(verify(
            &params,
            &keypair1.verification_key,
            &attributes,
            &sig1,
        ));

        assert!(!verify(
            &params,
            &keypair2.verification_key,
            &attributes,
            &sig1,
        ));

        assert!(!verify(
            &params,
            &keypair1.verification_key,
            &attributes,
            &sig2,
        ));
    }

    #[test]
    fn verification_on_two_public_and_two_private_attributes() {
        let rng = OsRng;

        let mut params = Parameters::new(rng, 4).unwrap();
        let public_attributes = params.n_random_scalars(2);
        let private_attributes = params.n_random_scalars(2);
        let elgamal_keypair = elgamal::keygen(&mut params);

        let keypair1 = keygen(&mut params);
        let keypair2 = keygen(&mut params);

        let lambda = prepare_blind_sign(
            &mut params,
            elgamal_keypair.public_key(),
            &private_attributes,
            &public_attributes,
        )
        .unwrap();

        let sig1 = blind_sign(
            &mut params,
            &keypair1.secret_key,
            elgamal_keypair.public_key(),
            &lambda,
            &public_attributes,
        )
        .unwrap()
        .unblind(elgamal_keypair.private_key());
        let sig2 = blind_sign(
            &mut params,
            &keypair2.secret_key,
            elgamal_keypair.public_key(),
            &lambda,
            &public_attributes,
        )
        .unwrap()
        .unblind(elgamal_keypair.private_key());

        let theta1 = prove_credential(
            &mut params,
            &keypair1.verification_key,
            &sig1,
            &private_attributes,
        )
        .unwrap();
        let theta2 = prove_credential(
            &mut params,
            &keypair2.verification_key,
            &sig2,
            &private_attributes,
        )
        .unwrap();

        assert!(verify_credential(
            &params,
            &keypair1.verification_key,
            &theta1,
            &public_attributes,
        ));

        assert!(verify_credential(
            &params,
            &keypair2.verification_key,
            &theta2,
            &public_attributes,
        ));

        assert!(!verify_credential(
            &params,
            &keypair1.verification_key,
            &theta2,
            &public_attributes,
        ));
    }

    #[test]
    fn verification_on_two_public_and_two_private_attributes_from_two_signers() {
        let rng = OsRng;

        let mut params = Parameters::new(rng, 4).unwrap();
        let public_attributes = params.n_random_scalars(2);
        let private_attributes = params.n_random_scalars(2);
        let elgamal_keypair = elgamal::keygen(&mut params);

        let keypairs = ttp_keygen(&mut params, 2, 3).unwrap();

        let lambda = prepare_blind_sign(
            &mut params,
            elgamal_keypair.public_key(),
            &private_attributes,
            &public_attributes,
        )
        .unwrap();

        let sigs = keypairs
            .iter()
            .map(|keypair| {
                blind_sign(
                    &mut params,
                    &keypair.secret_key,
                    elgamal_keypair.public_key(),
                    &lambda,
                    &public_attributes,
                )
                .unwrap()
                .unblind(elgamal_keypair.private_key())
            })
            .collect::<Vec<_>>();

        let vks = keypairs
            .into_iter()
            .map(|keypair| keypair.verification_key)
            .collect::<Vec<_>>();

        let aggr_vk = aggregate_verification_keys(&vks[..2], Some(&[1, 2])).unwrap();
        let aggr_sig = aggregate_signatures(&sigs[..2], Some(&[1, 2])).unwrap();

        let theta =
            prove_credential(&mut params, &aggr_vk, &aggr_sig, &private_attributes).unwrap();

        assert!(verify_credential(
            &params,
            &aggr_vk,
            &theta,
            &public_attributes,
        ));

        // taking different subset of keys and credentials
        let aggr_vk = aggregate_verification_keys(&vks[1..], Some(&[2, 3])).unwrap();
        let aggr_sig = aggregate_signatures(&sigs[1..], Some(&[2, 3])).unwrap();

        let theta =
            prove_credential(&mut params, &aggr_vk, &aggr_sig, &private_attributes).unwrap();

        assert!(verify_credential(
            &params,
            &aggr_vk,
            &theta,
            &public_attributes,
        ));
    }
}
