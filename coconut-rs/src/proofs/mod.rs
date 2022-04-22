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

use crate::error::{CoconutError, Result};
use crate::scheme::setup::Parameters;
use crate::scheme::{Signature, VerificationKey};
use crate::utils::{hash_g1, try_deserialize_scalar, try_deserialize_scalar_vec};
use crate::{elgamal, Attribute};
use bls12_381::{G1Projective, G2Projective, Scalar};
use digest::generic_array::typenum::Unsigned;
use digest::Digest;
use group::GroupEncoding;
use itertools::izip;
use sha2::Sha256;
use std::borrow::Borrow;
use std::convert::TryInto;

// as per the reference python implementation
type ChallengeDigest = Sha256;

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
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
    pub(crate) fn construct(
        params: &Parameters,
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
        let commitment_keys1_bytes = witness_keys
            .iter()
            .map(|wk_i| g1 * wk_i)
            .map(|witness| witness.to_bytes())
            .collect::<Vec<_>>();

        // Bw[i] = (wm[i] * h) + (wk[i] * gamma)
        let commitment_keys2_bytes = witness_keys
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
                .chain(commitment_keys1_bytes.iter().map(|aw| aw.as_ref()))
                .chain(commitment_keys2_bytes.iter().map(|bw| bw.as_ref())),
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

    pub(crate) fn verify(
        &self,
        params: &Parameters,
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
        let commitment_keys1_bytes = attributes_ciphertexts
            .iter()
            .map(|ciphertext| ciphertext.c1())
            .zip(self.response_keys.iter())
            .map(|(c1, res_attr)| c1 * self.challenge + g1 * res_attr)
            .map(|witness| witness.to_bytes())
            .collect::<Vec<_>>();

        // Bw[i] = (c * c2[i]) + (rk[i] * gamma) + (rm[i] * h)
        let commitment_keys2_bytes = izip!(
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
                .chain(commitment_keys1_bytes.iter().map(|aw| aw.as_ref()))
                .chain(commitment_keys2_bytes.iter().map(|bw| bw.as_ref())),
        );

        challenge == self.challenge
    }

    // challenge || rr || rk.len() || rk || rm.len() || rm
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let keys_len = self.response_keys.len() as u64;
        let attributes_len = self.response_attributes.len() as u64;

        let mut bytes = Vec::with_capacity(16 + (keys_len + attributes_len + 2) as usize * 32);

        bytes.extend_from_slice(&self.challenge.to_bytes());
        bytes.extend_from_slice(&self.response_random.to_bytes());
        bytes.extend_from_slice(&keys_len.to_le_bytes());

        for rk in &self.response_keys {
            bytes.extend_from_slice(&rk.to_bytes());
        }

        bytes.extend_from_slice(&attributes_len.to_le_bytes());

        for rm in &self.response_attributes {
            bytes.extend_from_slice(&rm.to_bytes());
        }

        bytes
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // at the very minimum there must be a single attribute being proven
        if bytes.len() < 32 * 4 + 16 || (bytes.len() - 16) % 32 != 0 {
            return Err(
                CoconutError::Deserialization(
                "tried to deserialize proof of ciphertexts and commitment with bytes of invalid length".to_string())
            );
        }

        let challenge_bytes = bytes[..32].try_into().unwrap();
        let rr_bytes = bytes[32..64].try_into().unwrap();

        let challenge = try_deserialize_scalar(
            &challenge_bytes,
            CoconutError::Deserialization("Failed to deserialize challenge".to_string()),
        )?;
        let response_random = try_deserialize_scalar(
            &rr_bytes,
            CoconutError::Deserialization(
                "Failed to deserialize the response to the random".to_string(),
            ),
        )?;

        let rk_len = u64::from_le_bytes(bytes[64..72].try_into().unwrap());
        if bytes[72..].len() < rk_len as usize * 32 + 8 {
            return Err(
                CoconutError::Deserialization(
                "tried to deserialize proof of ciphertexts and commitment with insufficient number of bytes provided".to_string()),
            );
        }

        let rk_end = 72 + rk_len as usize * 32;
        let response_keys = try_deserialize_scalar_vec(
            rk_len,
            &bytes[72..rk_end],
            CoconutError::Deserialization("Failed to deserialize keys response".to_string()),
        )?;

        let rm_len = u64::from_le_bytes(bytes[rk_end..rk_end + 8].try_into().unwrap());
        let response_attributes = try_deserialize_scalar_vec(
            rm_len,
            &bytes[rk_end + 8..],
            CoconutError::Deserialization("Failed to deserialize attributes response".to_string()),
        )?;

        Ok(ProofCmCs {
            challenge,
            response_random,
            response_keys,
            response_attributes,
        })
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
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
    pub(crate) fn construct(
        params: &Parameters,
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
            .beta_g2
            .iter()
            .map(|beta_i| beta_i.to_bytes())
            .collect::<Vec<_>>();

        // witnesses commitments
        // Aw = g2 * wt + alpha + beta[0] * wm[0] + ... + beta[i] * wm[i]
        // TODO: kappa commitment??
        // TODO NAMING: Aw, Bw
        let commitment_kappa = params.gen2() * witness_blinder
            + verification_key.alpha
            + witness_attributes
                .iter()
                .zip(verification_key.beta_g2.iter())
                .map(|(wm_i, beta_i)| beta_i * wm_i)
                .sum::<G2Projective>();

        let commitment_blinder = h * witness_blinder;

        let challenge = compute_challenge::<ChallengeDigest, _, _>(
            std::iter::once(params.gen1().to_bytes().as_ref())
                .chain(std::iter::once(params.gen2().to_bytes().as_ref()))
                .chain(std::iter::once(verification_key.alpha.to_bytes().as_ref()))
                .chain(std::iter::once(commitment_kappa.to_bytes().as_ref()))
                .chain(std::iter::once(commitment_blinder.to_bytes().as_ref()))
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

    pub(crate) fn verify(
        &self,
        params: &Parameters,
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
            .beta_g2
            .iter()
            .map(|beta_i| beta_i.to_bytes())
            .collect::<Vec<_>>();

        // re-compute witnesses commitments
        // Aw = (c * kappa) + (rt * g2) + ((1 - c) * alpha) + (rm[0] * beta[0]) + ... + (rm[i] * beta[i])
        // TODO NAMING: Aw, Bw...
        let commitment_kappa = kappa * self.challenge
            + params.gen2() * self.response_blinder
            + verification_key.alpha * (Scalar::one() - self.challenge)
            + self
                .response_attributes
                .iter()
                .zip(verification_key.beta_g2.iter())
                .map(|(priv_attr, beta_i)| beta_i * priv_attr)
                .sum::<G2Projective>();

        // Bw = (c * nu) + (rt * h)
        let commitment_blinder = nu * self.challenge + signature.sig1() * self.response_blinder;

        // compute the challenge prime ([g1, g2, alpha, Aw, Bw]+hs+beta)
        let challenge = compute_challenge::<ChallengeDigest, _, _>(
            std::iter::once(params.gen1().to_bytes().as_ref())
                .chain(std::iter::once(params.gen2().to_bytes().as_ref()))
                .chain(std::iter::once(verification_key.alpha.to_bytes().as_ref()))
                .chain(std::iter::once(commitment_kappa.to_bytes().as_ref()))
                .chain(std::iter::once(commitment_blinder.to_bytes().as_ref()))
                .chain(hs_bytes.iter().map(|hs| hs.as_ref()))
                .chain(beta_bytes.iter().map(|b| b.as_ref())),
        );

        challenge == self.challenge
    }

    // challenge || rm.len() || rm || rt
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let attributes_len = self.response_attributes.len() as u64;

        let mut bytes = Vec::with_capacity(8 + (attributes_len + 1) as usize * 32);

        bytes.extend_from_slice(&self.challenge.to_bytes());

        bytes.extend_from_slice(&attributes_len.to_le_bytes());
        for rm in &self.response_attributes {
            bytes.extend_from_slice(&rm.to_bytes());
        }

        bytes.extend_from_slice(&self.response_blinder.to_bytes());

        bytes
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // at the very minimum there must be a single attribute being proven
        if bytes.len() < 32 * 3 + 8 || (bytes.len() - 8) % 32 != 0 {
            return Err(CoconutError::DeserializationInvalidLength {
                actual: bytes.len(),
                modulus_target: bytes.len() - 8,
                modulus: 32,
                object: "kappa and nu".to_string(),
                target: 32 * 3 + 8,
            });
        }

        let challenge_bytes = bytes[..32].try_into().unwrap();
        let challenge = try_deserialize_scalar(
            &challenge_bytes,
            CoconutError::Deserialization("Failed to deserialize challenge".to_string()),
        )?;

        let rm_len = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
        if bytes[40..].len() != (rm_len + 1) as usize * 32 {
            return Err(
                CoconutError::Deserialization(
                    format!("Tried to deserialize proof of kappa and nu with insufficient number of bytes provided, expected {} got {}.", (rm_len + 1) as usize * 32, bytes[40..].len())
                )
            );
        }

        let rm_end = 40 + rm_len as usize * 32;
        let response_attributes = try_deserialize_scalar_vec(
            rm_len,
            &bytes[40..rm_end],
            CoconutError::Deserialization("Failed to deserialize attributes response".to_string()),
        )?;

        let blinder_bytes = bytes[rm_end..].try_into().unwrap();
        let response_blinder = try_deserialize_scalar(
            &blinder_bytes,
            CoconutError::Deserialization("failed to deserialize the blinder".to_string()),
        )?;

        Ok(ProofKappaNu {
            challenge,
            response_attributes,
            response_blinder,
        })
    }
}

// proof builder:
// - commitment
// - challenge
// - responses

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme::keygen::keygen;
    use crate::scheme::setup::setup;
    use group::Group;
    use rand::thread_rng;

    #[test]
    fn proof_cm_cs_bytes_roundtrip() {
        let mut rng = thread_rng();
        let mut params = setup(1).unwrap();

        let elgamal_keypair = elgamal::elgamal_keygen(&params);
        let private_attributes = params.n_random_scalars(1);
        let public_attributes = params.n_random_scalars(0);

        // we don't care about 'correctness' of the proof. only whether we can correctly recover it from bytes
        let cm = G1Projective::random(&mut rng);
        let r = params.random_scalar();

        let ephemeral_keys = params.n_random_scalars(1);

        // 0 public 1 private
        let pi_s = ProofCmCs::construct(
            &mut params,
            elgamal_keypair.public_key(),
            &ephemeral_keys,
            &cm,
            &r,
            &private_attributes,
            &public_attributes,
        );

        let bytes = pi_s.to_bytes();
        assert_eq!(ProofCmCs::from_bytes(&bytes).unwrap(), pi_s);

        // 2 public 2 private
        let private_attributes = params.n_random_scalars(2);
        let public_attributes = params.n_random_scalars(2);
        let ephemeral_keys = params.n_random_scalars(2);

        let pi_s = ProofCmCs::construct(
            &mut params,
            elgamal_keypair.public_key(),
            &ephemeral_keys,
            &cm,
            &r,
            &private_attributes,
            &public_attributes,
        );

        let bytes = pi_s.to_bytes();
        assert_eq!(ProofCmCs::from_bytes(&bytes).unwrap(), pi_s);
    }

    #[test]
    fn proof_kappa_nu_bytes_roundtrip() {
        let mut params = setup(1).unwrap();

        let keypair = keygen(&mut params);
        let r = params.random_scalar();
        let s = params.random_scalar();

        // we don't care about 'correctness' of the proof. only whether we can correctly recover it from bytes
        let signature = Signature(params.gen1() * r, params.gen1() * s);
        let private_attributes = params.n_random_scalars(1);
        let r = params.random_scalar();

        // 0 public 1 private
        let pi_v = ProofKappaNu::construct(
            &mut params,
            &keypair.verification_key(),
            &signature,
            &private_attributes,
            &r,
        );

        let bytes = pi_v.to_bytes();
        assert_eq!(ProofKappaNu::from_bytes(&bytes).unwrap(), pi_v);

        // 2 public 2 private
        let mut params = setup(4).unwrap();
        let keypair = keygen(&mut params);
        let private_attributes = params.n_random_scalars(2);

        let pi_v = ProofKappaNu::construct(
            &mut params,
            &keypair.verification_key(),
            &signature,
            &private_attributes,
            &r,
        );

        let bytes = pi_v.to_bytes();
        assert_eq!(ProofKappaNu::from_bytes(&bytes).unwrap(), pi_v);
    }
}
