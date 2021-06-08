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

use crate::error::{Error, ErrorKind, Result};
use crate::proofs::ProofKappaNu;
use crate::scheme::setup::Parameters;
use crate::scheme::Signature;
use crate::scheme::VerificationKey;
use crate::utils::{try_deserialize_g1_projective, try_deserialize_g2_projective};
use crate::Attribute;
use bls12_381::{multi_miller_loop, G1Affine, G1Projective, G2Prepared, G2Projective};
use core::ops::Neg;
use group::{Curve, Group};
use rand_core::{CryptoRng, RngCore};
use std::convert::TryInto;

// TODO NAMING: this whole thing
// Theta
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Theta {
    // kappa
    kappa: G2Projective,
    // nu
    nu: G1Projective,
    // sigma
    credential: Signature,
    // pi_v
    pi_v: ProofKappaNu,
}

impl Theta {
    fn verify_proof<R>(&self, params: &Parameters<R>, verification_key: &VerificationKey) -> bool {
        self.pi_v.verify(
            params,
            verification_key,
            &self.credential,
            &self.kappa,
            &self.nu,
        )
    }

    // TODO: perhaps also include pi_v.len()?
    // to be determined once we implement serde to make sure its 1:1 compatible
    // with bincode
    // kappa || nu || credential || pi_v
    pub fn to_bytes(&self) -> Vec<u8> {
        let kappa_bytes = self.kappa.to_affine().to_compressed();
        let nu_bytes = self.nu.to_affine().to_compressed();
        let credential_bytes = self.credential.to_bytes();
        let proof_bytes = self.pi_v.to_bytes();

        let mut bytes = Vec::with_capacity(240 + proof_bytes.len());
        bytes.extend_from_slice(&kappa_bytes);
        bytes.extend_from_slice(&nu_bytes);
        bytes.extend_from_slice(&credential_bytes);
        bytes.extend_from_slice(&proof_bytes);

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Theta> {
        if bytes.len() < 240 {
            return Err(Error::new(
                ErrorKind::Deserialization,
                "tried to deserialize theta with insufficient number of bytes",
            ));
        }

        let kappa_bytes = bytes[..96].try_into().unwrap();
        let kappa = try_deserialize_g2_projective(&kappa_bytes, || "failed to deserialize kappa")?;

        let nu_bytes = bytes[96..144].try_into().unwrap();
        let nu = try_deserialize_g1_projective(&nu_bytes, || "failed to deserialize kappa")?;

        let credential_bytes = bytes[144..240].try_into().unwrap();
        let credential = Signature::from_bytes(&credential_bytes)?;

        let pi_v = ProofKappaNu::from_bytes(&bytes[240..])?;

        Ok(Theta {
            kappa,
            nu,
            credential,
            pi_v,
        })
    }
}

pub fn prove_credential<R: RngCore + CryptoRng>(
    params: &mut Parameters<R>,
    verification_key: &VerificationKey,
    signature: &Signature,
    private_attributes: &[Attribute],
) -> Result<Theta> {
    if private_attributes.is_empty() {
        return Err(Error::new(
            ErrorKind::Verification,
            "tried to prove a credential with an empty set of private attributes",
        ));
    }

    if private_attributes.len() > verification_key.beta.len() {
        return Err(Error::new(
            ErrorKind::Verification,
            format!("tried to prove a credential for higher than supported by the provided verification key number of attributes (max: {}, requested: {})",
                    verification_key.beta.len(),
                    private_attributes.len()
            )));
    }

    // TODO: should randomization be part of this procedure or should
    // it be up to the user?
    let signature_prime = signature.randomise(params);

    // TODO NAMING: 'kappa', 'nu', 'blinding factor'
    let blinding_factor = params.random_scalar();
    let kappa = params.gen2() * blinding_factor
        + verification_key.alpha
        + private_attributes
            .iter()
            .zip(verification_key.beta.iter())
            .map(|(priv_attr, beta_i)| beta_i * priv_attr)
            .sum::<G2Projective>();
    let nu = signature_prime.sig1() * blinding_factor;

    let pi_v = ProofKappaNu::construct(
        params,
        verification_key,
        &signature_prime,
        private_attributes,
        &blinding_factor,
    );

    // kappa = alpha * beta^m * g2^r
    // nu = h^r

    Ok(Theta {
        kappa,
        nu,
        credential: signature_prime,
        pi_v,
    })
}

/// Checks whether e(P, Q) * e(-R, S) == id
fn check_bilinear_pairing(p: &G1Affine, q: &G2Prepared, r: &G1Affine, s: &G2Prepared) -> bool {
    // checking e(P, Q) * e(-R, S) == id
    // is equivalent to checking e(P, Q) == e(R, S)
    // but requires only a single final exponentiation rather than two of them
    // and therefore, as seen via benchmarks.rs, is almost 50% faster
    // (1.47ms vs 2.45ms, tested on R9 5900X)

    let multi_miller = multi_miller_loop(&[(p, q), (&r.neg(), s)]);
    multi_miller.final_exponentiation().is_identity().into()
}

pub fn verify_credential<R>(
    params: &Parameters<R>,
    verification_key: &VerificationKey,
    theta: &Theta,
    public_attributes: &[Attribute],
) -> bool {
    if public_attributes.len() + theta.pi_v.private_attributes() > verification_key.beta.len() {
        return false;
    }

    if !theta.verify_proof(params, verification_key) {
        return false;
    }

    let kappa = if public_attributes.is_empty() {
        theta.kappa
    } else {
        let signed_public_attributes = public_attributes
            .iter()
            .zip(
                verification_key
                    .beta
                    .iter()
                    .skip(theta.pi_v.private_attributes()),
            )
            .map(|(pub_attr, beta_i)| beta_i * pub_attr)
            .sum::<G2Projective>();

        theta.kappa + signed_public_attributes
    };

    check_bilinear_pairing(
        &theta.credential.0.to_affine(),
        &G2Prepared::from(kappa.to_affine()),
        &(theta.credential.1 + theta.nu).to_affine(),
        params.prepared_miller_g2(),
    ) && !bool::from(theta.credential.0.is_identity())
}

pub fn verify<R: RngCore + CryptoRng>(
    params: &Parameters<R>,
    verification_key: &VerificationKey,
    public_attributes: &[Attribute],
    sig: &Signature,
) -> bool {
    let kappa = (verification_key.alpha
        + public_attributes
            .iter()
            .zip(verification_key.beta.iter())
            .map(|(m_i, b_i)| b_i * m_i)
            .sum::<G2Projective>())
    .to_affine();

    check_bilinear_pairing(
        &sig.0.to_affine(),
        &G2Prepared::from(kappa),
        &sig.1.to_affine(),
        params.prepared_miller_g2(),
    ) && !bool::from(sig.0.is_identity())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme::keygen::keygen;
    use crate::scheme::setup::setup;
    use rand_core::OsRng;

    #[test]
    fn theta_bytes_roundtrip() {
        let rng = OsRng;

        let mut params = setup(rng, 1).unwrap();

        let keypair = keygen(&mut params);
        let r = params.random_scalar();
        let s = params.random_scalar();

        let signature = Signature(params.gen1() * r, params.gen1() * s);
        let private_attributes = params.n_random_scalars(1);

        let theta = prove_credential(
            &mut params,
            &keypair.verification_key,
            &signature,
            &private_attributes,
        )
        .unwrap();

        let bytes = theta.to_bytes();
        assert_eq!(Theta::from_bytes(&bytes).unwrap(), theta);

        let mut params = setup(rng, 4).unwrap();

        let keypair = keygen(&mut params);
        let private_attributes = params.n_random_scalars(2);

        let theta = prove_credential(
            &mut params,
            &keypair.verification_key,
            &signature,
            &private_attributes,
        )
        .unwrap();

        let bytes = theta.to_bytes();
        assert_eq!(Theta::from_bytes(&bytes).unwrap(), theta);
    }
}
