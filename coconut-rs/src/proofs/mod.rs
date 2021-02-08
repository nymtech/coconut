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

// TODO: look at https://crates.io/crates/merlin to perhaps use it instead?

use std::borrow::Borrow;
use std::ops::Deref;

use bls12_381::{G1Projective, Scalar};
use digest::generic_array::typenum::Unsigned;
use digest::Digest;
use group::GroupEncoding;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;

use crate::error::Result;
use crate::scheme::setup::Parameters;
use crate::utils::hash_g1;
use crate::{elgamal, Attribute};

// as per the reference python implementation
type ChallengeDigest = Sha256;

// TODO what is s??
pub struct ProofOfS {
    challenge: Scalar,
    // TODO: is this really a blinder?
    response_blinder: Scalar,
    // rr
    response_keys: Vec<Scalar>,
    // rk
    response_attributes: Vec<Scalar>, // rm
}

// note: this is slightly different from the reference python implementation
// as we omit the unnecessary string conversion. Instead we concatenate byte
// representations together and hash that.
// note2: G1 and G2 elements are using their compressed representations
// and as per the bls12-381 library, all elements are using big-endian form
/// Generates a Scalar [or Fp] challenge by hashing a number of elliptic curve points.  
fn compute_challenge<D, I, B>(iter: I) -> Scalar
where
    D: Digest,
    I: Iterator<Item = B>,
    B: AsRef<[u8]>,
{
    let mut h = D::new();
    for point_representation in iter {
        h.update(point_representation);
    }
    let digest = h.finalize();

    // TODO: I don't like the 0 padding here (though it's what we've been using before,
    // but we never had a security audit anyway...)
    // instead we could maybe use the `from_bytes` variant and adding some suffix
    // when computing the digest until we produce a valid scalar.
    let mut bytes = [0u8; 64];
    let pad_size = 64usize
        .checked_sub(D::OutputSize::to_usize())
        .unwrap_or_default();

    &mut bytes[pad_size..].copy_from_slice(&digest);

    Scalar::from_bytes_wide(&bytes)
}

fn produce_response(witness: &Scalar, challenge: &Scalar, secret: &Scalar) -> Scalar {
    witness - challenge * secret
}

fn produce_responses<S>(witnesses: &[Scalar], challenge: &Scalar, secrets: &[S]) -> Vec<Scalar>
where
    S: Borrow<Scalar>,
{
    debug_assert_eq!(witnesses.len(), secrets.len());

    witnesses
        .iter()
        .zip(secrets.iter())
        .map(|(w, x)| produce_response(w, challenge, x.borrow()))
        .collect()
}

impl ProofOfS {
    /// Construct proof of correctness of the ciphertexts and the commitment.
    pub(crate) fn construct<R: RngCore + CryptoRng>(
        params: &mut Parameters<R>,
        pub_key: &elgamal::PublicKey,
        ephemeral_keys: &[elgamal::EphemeralKey],
        commitment: &G1Projective,
        blinding_factor: &Scalar,
        private_attributes: &[Attribute],
        public_attributes: &[Attribute],
    ) -> Self {
        // note: this is only called from `prepare_blind_sign` that already checks
        // whether private attributes are non-empty and whether we don't have too many
        // attributes in total to sign.
        // we also know, due to the single call place, that ephemeral_keys.len() == private_attributes.len()

        // witness creation
        let witness_blinder = params.random_scalar();
        let witness_keys = params.n_random_scalars(ephemeral_keys.len());
        let witness_attributes =
            params.n_random_scalars(private_attributes.len() + public_attributes.len());

        // make h
        let h = hash_g1(commitment.to_bytes());

        // witnesses commitments
        let g1 = params.gen1();
        let hs_bytes = params
            .additional_g1_generators()
            .iter()
            .map(|h| h.to_bytes())
            .collect::<Vec<_>>();

        // Aw[i] = (wk[i] * g1)
        let Aw_bytes = witness_keys
            .iter()
            .map(|wk_i| g1 * wk_i)
            .map(|witness| witness.to_bytes())
            .collect::<Vec<_>>();

        // Bw[i] = (wm[i] * h) + (wk[i] * gamma)
        let Bw_bytes = witness_keys
            .iter()
            .zip(witness_attributes.iter())
            .map(|(wk_i, wm_i)| pub_key.deref() * wk_i + h * wm_i)
            .map(|witness| witness.to_bytes())
            .collect::<Vec<_>>();

        // Cw = (wr * g1) + (wm[0] * hs[0]) + ... + (wm[i] * hs[i])
        let commitment_attributes = g1 * witness_blinder
            + witness_attributes
                .iter()
                .zip(params.additional_g1_generators().iter())
                .map(|(wm_i, hs_i)| hs_i * wm_i)
                .sum::<G1Projective>();

        // challenge ([g1, g2, cm, h, Cw]+hs+Aw+Bw)
        let challenge = compute_challenge::<ChallengeDigest, _, _>(
            std::iter::once(params.gen1().to_bytes().as_ref())
                .chain(std::iter::once(params.gen2().to_bytes().as_ref()))
                .chain(std::iter::once(commitment.to_bytes().as_ref()))
                .chain(std::iter::once(h.to_bytes().as_ref()))
                .chain(std::iter::once(commitment_attributes.to_bytes().as_ref()))
                .chain(hs_bytes.iter().map(|hs| hs.as_ref()))
                .chain(Aw_bytes.iter().map(|aw| aw.as_ref()))
                .chain(Bw_bytes.iter().map(|bw| bw.as_ref())),
        );

        // responses
        let response_blinder = produce_response(&witness_blinder, &challenge, &blinding_factor);

        // TODO: maybe make `produce_responses` take an iterator instead?
        let response_keys = produce_responses(&witness_keys, &challenge, ephemeral_keys);
        let response_attributes = produce_responses(
            &witness_attributes,
            &challenge,
            &private_attributes
                .iter()
                .chain(public_attributes.iter())
                .collect::<Vec<_>>(),
        );

        ProofOfS {
            challenge,
            response_blinder,
            response_keys,
            response_attributes,
        }
    }

    // fn verify(&)
}
