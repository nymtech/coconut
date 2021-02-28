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

use crate::scheme::setup::Parameters;
use crate::scheme::signature::Signature;
use crate::scheme::VerificationKey;
use crate::utils::hash_g1;
use crate::{elgamal, Attribute};
use bls12_381::{G1Projective, G2Projective, Scalar};
use digest::generic_array::typenum::Unsigned;
use digest::Digest;
use group::GroupEncoding;
use itertools::izip;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use std::borrow::Borrow;

// as per the reference python implementation
type ChallengeDigest = Sha256;

pub struct ProofCmCs {
    challenge: Scalar,
    // rr
    response_random: Scalar,
    // rk
    response_keys: Vec<Scalar>,
    // rm
    response_attributes: Vec<Scalar>,
}

// note: this is slightly different from the reference python implementation
// as we omit the unnecessary string conversion. Instead we concatenate byte
// representations together and hash that.
// note2: G1 and G2 elements are using their compressed representations
// and as per the bls12-381 library all elements are using big-endian form
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

    bytes[pad_size..].copy_from_slice(&digest);

    Scalar::from_bytes_wide(&bytes)
}
//
// #[cfg(test)]
// mod tests {
//     use super::*;
//
//     #[test]
//     fn foo() {
//         let d1 = [1, 2, 3, 4, 5];
//         let d2 = [6, 7, 8, 9, 10];
//         let vec = vec![d1, d2];
//         let iter = vec.iter();
//
//         let s = compute_challenge::<ChallengeDigest, _, _>(iter);
//         println!("{:?}", s.to_string());
//         println!("{:?}", s.to_bytes());
//         println!("{:?}", s);
//
//         assert!(false)
//     }
//
//     #[test]
//     fn bar() {
//         let mut bytes = [0u8; 64];
//         let data = [1, 2, 3, 4];
//
//         bytes[60..].copy_from_slice(&data);
//         let s = Scalar::from_bytes_wide(&bytes);
//
//         println!("s: {:?}", s);
//         println!("s: {:?}", s.to_bytes());
//
//         let s42 = Scalar::from(42);
//         let foo = s * s42;
//
//         println!("FOO");
//         println!("{:?}", foo.to_bytes());
//         println!("{:?}", foo.to_string());
//         // assert!(false)
//
//         println!();
//         println!();
//         println!();
//         println!();
//         println!();
//         let s_bytes_go = [
//             48, 40, 98, 96, 151, 178, 153, 124, 62, 43, 26, 188, 204, 223, 246, 103, 194, 210, 177,
//             140, 32, 195, 75, 10, 188, 234, 92, 118, 32, 17, 118, 71,
//         ];
//         let s_go = Scalar::from_bytes(&s_bytes_go).unwrap();
//         assert_eq!(s, s_go);
//
//         println!("foo");
//         let foo_bytes_go = [
//             199, 151, 26, 208, 238, 76, 55, 113, 89, 28, 116, 220, 75, 179, 251, 224, 95, 123, 94,
//             36, 142, 234, 199, 175, 204, 70, 221, 90, 52, 120, 41, 103,
//         ];
//         let foo_go = Scalar::from_bytes(&foo_bytes_go).unwrap();
//         assert_eq!(foo, foo_go);
//     }
// }

fn produce_response(witness: &Scalar, challenge: &Scalar, secret: &Scalar) -> Scalar {
    witness - challenge * secret
}

// note: it's caller's responsibility to ensure witnesses.len() = secrets.len()
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

impl ProofCmCs {
    /// Construct non-interactive zero-knowledge proof of correctness of the ciphertexts and the commitment.
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
            .gen_hs()
            .iter()
            .map(|h| h.to_bytes())
            .collect::<Vec<_>>();

        // TODO NAMING: Aw, Bw, Cw.... ?
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
            .map(|(wk_i, wm_i)| pub_key * wk_i + h * wm_i)
            .map(|witness| witness.to_bytes())
            .collect::<Vec<_>>();

        // Cw = (wr * g1) + (wm[0] * hs[0]) + ... + (wm[i] * hs[i])
        let commitment_attributes = g1 * witness_blinder
            + witness_attributes
                .iter()
                .zip(params.gen_hs().iter())
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

        ProofCmCs {
            challenge,
            response_random: response_blinder,
            response_keys,
            response_attributes,
        }
    }

    pub(crate) fn verify<R>(
        &self,
        params: &Parameters<R>,
        pub_key: &elgamal::PublicKey,
        commitment: &G1Projective,
        attributes_ciphertexts: &[elgamal::Ciphertext],
    ) -> bool {
        if self.response_keys.len() != attributes_ciphertexts.len() {
            return false;
        }

        // recompute h
        let h = hash_g1(commitment.to_bytes());

        // recompute witnesses commitments

        let g1 = params.gen1();
        let hs_bytes = params
            .gen_hs()
            .iter()
            .map(|h| h.to_bytes())
            .collect::<Vec<_>>();

        // Aw[i] = (c * c1[i]) + (rk[i] * g1)
        // TODO NAMING: Aw, Bw...
        let Aw_bytes = attributes_ciphertexts
            .iter()
            .map(|ciphertext| ciphertext.c1())
            .zip(self.response_keys.iter())
            .map(|(c1, res_attr)| c1 * self.challenge + g1 * res_attr)
            .map(|witness| witness.to_bytes())
            .collect::<Vec<_>>();

        // Bw[i] = (c * c2[i]) + (rk[i] * gamma) + (rm[i] * h)
        let Bw_bytes = izip!(
            attributes_ciphertexts
                .iter()
                .map(|ciphertext| ciphertext.c2()),
            self.response_keys.iter(),
            self.response_attributes.iter()
        )
        .map(|(c2, res_key, res_attr)| c2 * self.challenge + pub_key * res_key + h * res_attr)
        .map(|witness| witness.to_bytes())
        .collect::<Vec<_>>();

        // Cw = (cm * c) + (rr * g1) + (rm[0] * hs[0]) + ... + (rm[n] * hs[n])
        let commitment_attributes = commitment * self.challenge
            + g1 * self.response_random
            + self
                .response_attributes
                .iter()
                .zip(params.gen_hs().iter())
                .map(|(res_attr, hs)| hs * res_attr)
                .sum::<G1Projective>();

        // compute the challenge prime ([g1, g2, cm, h, Cw]+hs+Aw+Bw)
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

        challenge == self.challenge
    }
}

pub struct ProofKappaNu {
    // c
    challenge: Scalar,

    // rm
    response_attributes: Vec<Scalar>,

    // TODO NAMING: blinder or blinding factor?
    // rt
    response_blinder: Scalar,
}

impl ProofKappaNu {
    pub(crate) fn construct<R: RngCore + CryptoRng>(
        params: &mut Parameters<R>,
        verification_key: &VerificationKey,
        signature: &Signature,
        private_attributes: &[Attribute],
        blinding_factor: &Scalar,
    ) -> Self {
        // create the witnesses
        let witness_blinder = params.random_scalar();
        let witness_attributes = params.n_random_scalars(private_attributes.len());

        let h = signature.sig1();

        let hs_bytes = params
            .gen_hs()
            .iter()
            .map(|h| h.to_bytes())
            .collect::<Vec<_>>();

        let beta_bytes = verification_key
            .beta
            .iter()
            .map(|beta_i| beta_i.to_bytes())
            .collect::<Vec<_>>();

        // witnesses commitments
        // Aw = g2 * wt + alpha + beta[0] * wm[0] + ... + beta[i] * wm[i]
        // TODO: kappa commitment??
        // TODO NAMING: Aw, Bw
        let Aw = params.gen2() * witness_blinder
            + verification_key.alpha
            + witness_attributes
                .iter()
                .zip(verification_key.beta.iter())
                .map(|(wm_i, beta_i)| beta_i * wm_i)
                .sum::<G2Projective>();

        let Bw = h * witness_blinder;

        let challenge = compute_challenge::<ChallengeDigest, _, _>(
            std::iter::once(params.gen1().to_bytes().as_ref())
                .chain(std::iter::once(params.gen2().to_bytes().as_ref()))
                .chain(std::iter::once(verification_key.alpha.to_bytes().as_ref()))
                .chain(std::iter::once(Aw.to_bytes().as_ref()))
                .chain(std::iter::once(Bw.to_bytes().as_ref()))
                .chain(hs_bytes.iter().map(|hs| hs.as_ref()))
                .chain(beta_bytes.iter().map(|b| b.as_ref())),
        );

        // responses
        let response_blinder = produce_response(&witness_blinder, &challenge, &blinding_factor);
        let response_attributes =
            produce_responses(&witness_attributes, &challenge, private_attributes);

        ProofKappaNu {
            challenge,
            response_attributes,
            response_blinder,
        }
    }

    pub(crate) fn private_attributes(&self) -> usize {
        self.response_attributes.len()
    }

    pub(crate) fn verify<R>(
        &self,
        params: &Parameters<R>,
        verification_key: &VerificationKey,
        signature: &Signature,
        // TODO NAMING: kappa, nu...
        kappa: &G2Projective,
        nu: &G1Projective,
    ) -> bool {
        let hs_bytes = params
            .gen_hs()
            .iter()
            .map(|h| h.to_bytes())
            .collect::<Vec<_>>();

        let beta_bytes = verification_key
            .beta
            .iter()
            .map(|beta_i| beta_i.to_bytes())
            .collect::<Vec<_>>();

        // re-compute witnesses commitments
        // Aw = (c * kappa) + (rt * g2) + ((1 - c) * alpha) + (rm[0] * beta[0]) + ... + (rm[i] * beta[i])
        // TODO NAMING: Aw, Bw...
        let Aw = kappa * self.challenge
            + params.gen2() * self.response_blinder
            + verification_key.alpha * (Scalar::one() - self.challenge)
            + self
                .response_attributes
                .iter()
                .zip(verification_key.beta.iter())
                .map(|(priv_attr, beta_i)| beta_i * priv_attr)
                .sum::<G2Projective>();

        // Bw = (c * nu) + (rt * h)
        let Bw = nu * self.challenge + signature.sig1() * self.response_blinder;

        // compute the challenge prime ([g1, g2, alpha, Aw, Bw]+hs+beta)
        let challenge = compute_challenge::<ChallengeDigest, _, _>(
            std::iter::once(params.gen1().to_bytes().as_ref())
                .chain(std::iter::once(params.gen2().to_bytes().as_ref()))
                .chain(std::iter::once(verification_key.alpha.to_bytes().as_ref()))
                .chain(std::iter::once(Aw.to_bytes().as_ref()))
                .chain(std::iter::once(Bw.to_bytes().as_ref()))
                .chain(hs_bytes.iter().map(|hs| hs.as_ref()))
                .chain(beta_bytes.iter().map(|b| b.as_ref())),
        );

        challenge == self.challenge
    }
}
