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

use crate::elgamal::Ciphertext;
use crate::error::{Error, ErrorKind, Result};
use crate::proofs::ProofCmCs;
use crate::scheme::setup::Parameters;
use crate::scheme::SecretKey;
use crate::scheme::{BlindedSignature, Signature};
use crate::utils::{hash_g1, try_deserialize_g1_projective};
use crate::{elgamal, Attribute};
use bls12_381::{G1Affine, G1Projective, Scalar};
use group::{Curve, GroupEncoding};
use rand_core::{CryptoRng, RngCore};
use std::convert::TryInto;

// TODO NAMING: double check this one
// Lambda
pub struct BlindSignRequest {
    // cm
    commitment: G1Projective,
    // c
    attributes_ciphertexts: Vec<elgamal::Ciphertext>,
    // pi_s
    pi_s: ProofCmCs,
}

impl BlindSignRequest {
    fn verify_proof<R>(&self, params: &Parameters<R>, pub_key: &elgamal::PublicKey) -> bool {
        self.pi_s.verify(
            params,
            pub_key,
            &self.commitment,
            &self.attributes_ciphertexts,
        )
    }

    // TODO: perhaps also include pi_s.len()?
    // to be determined once we implement serde to make sure its 1:1 compatible
    // with bincode
    // cm || c.len() || c || pi_s
    pub fn to_bytes(&self) -> Vec<u8> {
        let cm_bytes = self.commitment.to_affine().to_compressed();
        let c_len = self.attributes_ciphertexts.len() as u64;
        let mut proof_bytes = self.pi_s.to_bytes();

        let mut bytes = Vec::with_capacity(48 + 8 + c_len as usize * 96 + proof_bytes.len());

        bytes.copy_from_slice(&cm_bytes);
        bytes.copy_from_slice(&c_len.to_le_bytes());
        for c in &self.attributes_ciphertexts {
            bytes.copy_from_slice(&c.to_bytes());
        }

        bytes.append(&mut proof_bytes);

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<BlindSignRequest> {
        if bytes.len() < 48 + 8 + 96 {
            return Err(Error::new(
                ErrorKind::Deserialization,
                "tried to deserialize blind sign request with insufficient number of bytes",
            ));
        }

        let cm_bytes = bytes[..48].try_into().unwrap();
        let commitment = try_deserialize_g1_projective(
            &cm_bytes,
            "failed to deserialize compressed commitment",
        )?;

        let c_len = u64::from_le_bytes(bytes[48..56].try_into().unwrap());
        if bytes[56..].len() < c_len as usize * 96 {
            return Err(Error::new(
                ErrorKind::Deserialization,
                "tried to deserialize blind sign request with insufficient number of bytes",
            ));
        }

        let mut attributes_ciphertexts = Vec::with_capacity(c_len as usize);
        for i in 0..c_len as usize {
            let start = 56 + i * 96;
            let end = start + 96;
            let c_bytes = bytes[start..end].try_into().unwrap();
            attributes_ciphertexts.push(Ciphertext::from_bytes(&c_bytes)?)
        }

        let pi_s = ProofCmCs::from_bytes(&bytes[56 + c_len as usize * 96..])?;

        Ok(BlindSignRequest {
            commitment,
            attributes_ciphertexts,
            pi_s,
        })
    }
}

/// Builds cryptographic material required for blind sign.
pub fn prepare_blind_sign<R: RngCore + CryptoRng>(
    params: &mut Parameters<R>,
    pub_key: &elgamal::PublicKey,
    private_attributes: &[Attribute],
    public_attributes: &[Attribute],
) -> Result<BlindSignRequest> {
    if private_attributes.is_empty() {
        return Err(Error::new(
            ErrorKind::Issuance,
            "tried to prepare blind sign request for an empty set of private attributes",
        ));
    }

    let hs = params.gen_hs();
    if private_attributes.len() + public_attributes.len() > hs.len() {
        return Err(Error::new(
            ErrorKind::Issuance,
            format!("tried to prepare blind sign request for higher than specified in setup number of attributes (max: {}, requested: {})",
                    hs.len(),
                    private_attributes.len() + public_attributes.len()
            )));
    }

    // prepare commitment
    // Produces h0 ^ m0 * h1^m1 * .... * hn^mn
    let attr_cm = private_attributes
        .iter()
        .chain(public_attributes.iter())
        .zip(hs)
        .map(|(&m, h)| h * m)
        .sum::<G1Projective>();
    let blinder = params.random_scalar();
    // g1^r * h0 ^ m0 * h1^m1 * .... * hn^mn
    let commitment = params.gen1() * blinder + attr_cm;

    // build ElGamal encryption
    let commitment_hash = hash_g1(commitment.to_bytes());
    let (attributes_ciphertexts, ephemeral_keys): (Vec<_>, Vec<_>) = private_attributes
        .iter()
        .map(|m| pub_key.encrypt(params, &commitment_hash, m))
        .unzip();

    let pi_s = ProofCmCs::construct(
        params,
        pub_key,
        &ephemeral_keys,
        &commitment,
        &blinder,
        private_attributes,
        public_attributes,
    );

    Ok(BlindSignRequest {
        commitment,
        attributes_ciphertexts,
        pi_s,
    })
}

pub fn blind_sign<R: RngCore + CryptoRng>(
    params: &mut Parameters<R>,
    secret_key: &SecretKey,
    pub_key: &elgamal::PublicKey,
    blind_sign_request: &BlindSignRequest,
    public_attributes: &[Attribute],
) -> Result<BlindedSignature> {
    let num_private = blind_sign_request.attributes_ciphertexts.len();
    let hs = params.gen_hs();

    if num_private + public_attributes.len() > hs.len() {
        return Err(Error::new(
            ErrorKind::Issuance,
            format!("tried to perform blind sign for higher than specified in setup number of attributes (max: {}, requested: {})",
                    hs.len(),
                    num_private + public_attributes.len()
            )));
    }

    if !blind_sign_request.verify_proof(params, pub_key) {
        return Err(Error::new(
            ErrorKind::Issuance,
            "failed to verify the proof of knowledge",
        ));
    }

    let h = hash_g1(blind_sign_request.commitment.to_bytes());

    // in python implementation there are n^2 G1 multiplications, let's do it with a single one instead.
    // i.e. compute h ^ (pub_m[0] * y[m + 1] + ... + pub_m[n] * y[m + n]) directly (where m is number of PRIVATE attributes)
    // rather than ((h ^ pub_m[0]) ^ y[m + 1] , (h ^ pub_m[1]) ^ y[m + 2] , ...).sum() separately
    let signed_public = h * public_attributes
        .iter()
        .zip(secret_key.ys.iter().skip(num_private))
        .map(|(attr, yi)| attr * yi)
        .sum::<Scalar>();

    // c1[0] ^ y[0] * ... * c1[m] ^ y[m]
    let sig_1 = blind_sign_request
        .attributes_ciphertexts
        .iter()
        .map(|ciphertext| ciphertext.c1())
        .zip(secret_key.ys.iter())
        .map(|(c1, yi)| c1 * yi)
        .sum();

    // h ^ x + c2[0] ^ y[0] + ... c2[m] ^ y[m] + h ^ (pub_m[0] * y[m + 1] + ... + pub_m[n] * y[m + n])
    let sig_2 = blind_sign_request
        .attributes_ciphertexts
        .iter()
        .map(|ciphertext| ciphertext.c2())
        .zip(secret_key.ys.iter())
        .map(|(c2, yi)| c2 * yi)
        .chain(std::iter::once(h * secret_key.x))
        .chain(std::iter::once(signed_public))
        .sum();

    Ok(BlindedSignature(h, elgamal::Ciphertext(sig_1, sig_2)))
}

// TODO: possibly completely remove those two functions.
// They only exist to have a simpler and smaller code snippets to test
// basic functionalities.
/// Creates a Coconut Signature under a given secret key on a set of public attributes only.
pub fn sign<R: RngCore + CryptoRng>(
    params: &mut Parameters<R>,
    secret_key: &SecretKey,
    public_attributes: &[Attribute],
) -> Result<Signature> {
    if public_attributes.len() > secret_key.ys.len() {
        return Err(Error::new(
            ErrorKind::Issuance,
            format!("tried to sign more attributes than allowed by the secret key (max: {}, requested: {})",
                    secret_key.ys.len(),
                    public_attributes.len()
            )));
    }

    // TODO: why in the python implementation this hash onto the curve is present
    // while it's not used in the paper? the paper uses random exponent instead.
    // (the python implementation hashes string representation of all attributes onto the curve,
    // but I think the same can be achieved by just summing the attributes thus avoiding the unnecessary
    // transformation. If I'm wrong, please correct me.)
    let attributes_sum = public_attributes.iter().sum::<Scalar>();
    let h = hash_g1((params.gen1() * attributes_sum).to_bytes());

    // x + m0 * y0 + m1 * y1 + ... mn * yn
    let exponent = secret_key.x
        + public_attributes
            .iter()
            .zip(secret_key.ys.iter())
            .map(|(m_i, y_i)| m_i * y_i)
            .sum::<Scalar>();

    let sig2 = h * exponent;
    Ok(Signature(h, sig2))
}
