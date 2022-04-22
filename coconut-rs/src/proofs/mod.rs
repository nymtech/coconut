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
use crate::Attribute;
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
    response_opening: Scalar,
    response_openings: Vec<Scalar>,
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
        commitment: &G1Projective,
        commitment_opening: &Scalar,
        commitments: &[G1Projective],
        pedersen_commitments_openings: &[Scalar],
        private_attributes: &[Attribute],
    ) -> Self {
        // note: this is only called from `prepare_blind_sign` that already checks
        // whether private attributes are non-empty and whether we don't have too many
        // attributes in total to sign.
        // we also know, due to the single call place, that ephemeral_keys.len() == private_attributes.len()

        // witness creation
// witness creation
        let witness_commitment_opening = params.random_scalar();
        let witness_pedersen_commitments_openings =
            params.n_random_scalars(pedersen_commitments_openings.len());
        let witness_attributes = params.n_random_scalars(private_attributes.len());

        // recompute h
        let h = hash_g1(commitment.to_bytes());
        let hs_bytes = params
            .gen_hs()
            .iter()
            .map(|h| h.to_bytes())
            .collect::<Vec<_>>();

        let g1 = params.gen1();

        // compute commitments

        // zkp commitment for the attributes commitment cm
        // Ccm = (wr * g1) + (wm[0] * hs[0]) + ... + (wm[i] * hs[i])
        let commitment_attributes = g1 * witness_commitment_opening
            + witness_attributes
            .iter()
            .zip(params.gen_hs().iter())
            .map(|(wm_i, hs_i)| hs_i * wm_i)
            .sum::<G1Projective>();

        // zkp commitments for the individual attributes
        let commitments_attributes = witness_pedersen_commitments_openings
            .iter()
            .zip(witness_attributes.iter())
            .map(|(o_j, m_j)| g1 * o_j + h * m_j)
            .collect::<Vec<_>>();

        let commitments_bytes = commitments
            .iter()
            .map(|cm| cm.to_bytes())
            .collect::<Vec<_>>();

        let commitments_attributes_bytes = commitments_attributes
            .iter()
            .map(|cm| cm.to_bytes())
            .collect::<Vec<_>>();

        // compute challenge
        let challenge = compute_challenge::<ChallengeDigest, _, _>(
            std::iter::once(params.gen1().to_bytes().as_ref())
                .chain(hs_bytes.iter().map(|hs| hs.as_ref()))
                .chain(std::iter::once(h.to_bytes().as_ref()))
                .chain(std::iter::once(commitment.to_bytes().as_ref()))
                .chain(commitments_bytes.iter().map(|cm| cm.as_ref()))
                .chain(std::iter::once(commitment_attributes.to_bytes().as_ref()))
                .chain(commitments_attributes_bytes.iter().map(|cm| cm.as_ref())),
        );

        // Responses
        let response_opening =
            produce_response(&witness_commitment_opening, &challenge, commitment_opening);
        let response_openings = produce_responses(
            &witness_pedersen_commitments_openings,
            &challenge,
            &pedersen_commitments_openings.iter().collect::<Vec<_>>(),
        );
        let response_attributes = produce_responses(
            &witness_attributes,
            &challenge,
            &private_attributes.iter().collect::<Vec<_>>(),
        );

        ProofCmCs {
            challenge,
            response_opening,
            response_openings,
            response_attributes,
        }
    }

    pub(crate) fn verify(
        &self,
        params: &Parameters,
        commitment: &G1Projective,
        commitments: &[G1Projective],
        public_attributes: &[Attribute],
    ) -> bool {
        if self.response_attributes.len() != commitments.len() {
            return false;
        }

        // recompute h
        let h = hash_g1(commitment.to_bytes());
        let g1 = params.gen1();

        let hs_bytes = params
            .gen_hs()
            .iter()
            .map(|h| h.to_bytes())
            .collect::<Vec<_>>();

        // recompute witnesses commitments
        // Cw = (cm * c) + (rr * g1) + (rm[0] * hs[0]) + ... + (rm[n] * hs[n])
        let commitment_attributes = (commitment
            - public_attributes
            .iter()
            .zip(params.gen_hs().iter().skip(self.response_attributes.len()))
            .map(|(pub_attr, hs)| hs * pub_attr)
            .sum::<G1Projective>())
            * self.challenge
            + g1 * self.response_opening
            + self
            .response_attributes
            .iter()
            .zip(params.gen_hs().iter())
            .map(|(res_attr, hs)| hs * res_attr)
            .sum::<G1Projective>();

        let commitments_attributes = izip!(
            commitments.iter(),
            self.response_openings.iter(),
            self.response_attributes.iter()
        )
            .map(|(cm_j, r_o_j, r_m_j)| cm_j * self.challenge + g1 * r_o_j + h * r_m_j)
            .collect::<Vec<_>>();

        let commitments_bytes = commitments
            .iter()
            .map(|cm| cm.to_bytes())
            .collect::<Vec<_>>();

        let commitments_attributes_bytes = commitments_attributes
            .iter()
            .map(|cm| cm.to_bytes())
            .collect::<Vec<_>>();

        // re-compute the challenge
        let challenge = compute_challenge::<ChallengeDigest, _, _>(
            std::iter::once(params.gen1().to_bytes().as_ref())
                .chain(hs_bytes.iter().map(|hs| hs.as_ref()))
                .chain(std::iter::once(h.to_bytes().as_ref()))
                .chain(std::iter::once(commitment.to_bytes().as_ref()))
                .chain(commitments_bytes.iter().map(|cm| cm.as_ref()))
                .chain(std::iter::once(commitment_attributes.to_bytes().as_ref()))
                .chain(commitments_attributes_bytes.iter().map(|cm| cm.as_ref())),
        );

        challenge == self.challenge
    }

    // challenge || response opening || openings len || response openings || attributes len ||
    // response attributes
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let openings_len = self.response_openings.len() as u64;
        let attributes_len = self.response_attributes.len() as u64;

        let mut bytes = Vec::with_capacity(16 + (2 + openings_len + attributes_len) as usize * 32);

        bytes.extend_from_slice(&self.challenge.to_bytes());
        bytes.extend_from_slice(&self.response_opening.to_bytes());

        bytes.extend_from_slice(&openings_len.to_le_bytes());
        for ro in &self.response_openings {
            bytes.extend_from_slice(&ro.to_bytes());
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
            return Err(CoconutError::Deserialization(
                "tried to deserialize proof of commitments with bytes of invalid length"
                    .to_string(),
            ));
        }

        let mut idx = 0;
        let challenge_bytes = bytes[idx..idx + 32].try_into().unwrap();
        idx += 32;
        let response_opening_bytes = bytes[idx..idx + 32].try_into().unwrap();
        idx += 32;

        let challenge = try_deserialize_scalar(
            &challenge_bytes,
            CoconutError::Deserialization("Failed to deserialize challenge".to_string()),
        )?;

        let response_opening = try_deserialize_scalar(
            &response_opening_bytes,
            CoconutError::Deserialization(
                "Failed to deserialize the response to the random".to_string(),
            ),
        )?;

        let ro_len = u64::from_le_bytes(bytes[idx..idx + 8].try_into().unwrap());
        idx += 8;
        if bytes[idx..].len() < ro_len as usize * 32 + 8 {
            return Err(
                CoconutError::Deserialization(
                    "tried to deserialize proof of ciphertexts and commitment with insufficient number of bytes provided".to_string()),
            );
        }

        let ro_end = idx + ro_len as usize * 32;
        let response_openings = try_deserialize_scalar_vec(
            ro_len,
            &bytes[idx..ro_end],
            CoconutError::Deserialization("Failed to deserialize openings response".to_string()),
        )?;

        let rm_len = u64::from_le_bytes(bytes[ro_end..ro_end + 8].try_into().unwrap());
        let response_attributes = try_deserialize_scalar_vec(
            rm_len,
            &bytes[ro_end + 8..],
            CoconutError::Deserialization("Failed to deserialize attributes response".to_string()),
        )?;

        Ok(ProofCmCs {
            challenge,
            response_opening,
            response_openings,
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
        private_attributes: &[Attribute],
        blinding_factor: &Scalar,
    ) -> Self {
        // create the witnesses
        let witness_blinder = params.random_scalar();
        let witness_attributes = params.n_random_scalars(private_attributes.len());


        let beta_bytes = verification_key
            .beta_g2
            .iter()
            .map(|beta_i| beta_i.to_bytes())
            .collect::<Vec<_>>();

        // commitments
        let commitment_kappa = params.gen2() * witness_blinder
            + verification_key.alpha
            + witness_attributes
                .iter()
                .zip(verification_key.beta_g2.iter())
                .map(|(wm_i, beta_i)| beta_i * wm_i)
                .sum::<G2Projective>();


        let challenge = compute_challenge::<ChallengeDigest, _, _>(
            std::iter::once(params.gen1().to_bytes().as_ref())
                .chain(std::iter::once(params.gen2().to_bytes().as_ref()))
                .chain(std::iter::once(verification_key.alpha.to_bytes().as_ref()))
                .chain(std::iter::once(commitment_kappa.to_bytes().as_ref()))
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
        kappa: &G2Projective,
    ) -> bool {

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

        // compute the challenge prime ([g1, g2, alpha, Aw, Bw]+hs+beta)
        let challenge = compute_challenge::<ChallengeDigest, _, _>(
            std::iter::once(params.gen1().to_bytes().as_ref())
                .chain(std::iter::once(params.gen2().to_bytes().as_ref()))
                .chain(std::iter::once(verification_key.alpha.to_bytes().as_ref()))
                .chain(std::iter::once(commitment_kappa.to_bytes().as_ref()))
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
                object: "kappa".to_string(),
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

        let params = setup(1).unwrap();
        let cm = G1Projective::random(&mut rng);
        let r = params.random_scalar();
        let cms: [G1Projective; 1] = [G1Projective::random(&mut rng)];
        let rs = params.n_random_scalars(1);
        let private_attributes = params.n_random_scalars(1);

        // 0 public 1 private
        let pi_s = ProofCmCs::construct(&params, &cm, &r, &cms, &rs, &private_attributes);

        let bytes = pi_s.to_bytes();
        assert_eq!(ProofCmCs::from_bytes(&bytes).unwrap(), pi_s);

        let params = setup(2).unwrap();
        let cm = G1Projective::random(&mut rng);
        let r = params.random_scalar();
        let cms: [G1Projective; 2] = [
            G1Projective::random(&mut rng),
            G1Projective::random(&mut rng),
        ];
        let rs = params.n_random_scalars(2);
        let private_attributes = params.n_random_scalars(2);

        // 0 public 2 privates
        let pi_s = ProofCmCs::construct(&params, &cm, &r, &cms, &rs, &private_attributes);

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
        let private_attributes = params.n_random_scalars(1);
        let r = params.random_scalar();

        // 0 public 1 private
        let pi_v = ProofKappaNu::construct(
            &mut params,
            &keypair.verification_key(),
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
            &private_attributes,
            &r,
        );

        let bytes = pi_v.to_bytes();
        assert_eq!(ProofKappaNu::from_bytes(&bytes).unwrap(), pi_v);
    }
}
