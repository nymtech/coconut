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

use std::ops::Neg;

use bls12_381::{
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Scalar,
};
use group::{Curve, Group, GroupEncoding};
use rand_core::{CryptoRng, RngCore};

use crate::error::Result;
use crate::proofs::{ProofOfS, ProofOfV};
use crate::scheme::setup::Parameters;
use crate::scheme::{SecretKey, VerificationKey};
use crate::utils::hash_g1;
use crate::{elgamal, Attribute};

// (h, s)
pub struct Signature(G1Projective, G1Projective);

impl Signature {
    // TODO: name: is it 'base'?
    pub(crate) fn base(&self) -> &G1Projective {
        &self.0
    }
}

type PartialSignature = Signature;

impl Signature {
    fn randomise<R: RngCore + CryptoRng>(&self, params: &mut Parameters<R>) -> Signature {
        let r = params.random_scalar();
        Signature(self.0 * r, self.1 * r)
    }
}

pub struct BlindedSignature(G1Projective, elgamal::Ciphertext);

impl BlindedSignature {
    pub fn unblind(self, private_key: &elgamal::PrivateKey) -> Signature {
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
    // cm
    commitment: G1Projective,
    // c
    attributes_ciphertexts: Vec<elgamal::Ciphertext>,
    // pi_s
    pi_s: ProofOfS,
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

pub fn blind_sign<R: RngCore + CryptoRng>(
    params: &mut Parameters<R>,
    secret_key: &SecretKey,
    pub_key: &elgamal::PublicKey,
    blind_sign_request: &BlindSignRequest,
    public_attributes: &[Attribute],
) -> Result<BlindedSignature> {
    let num_private = blind_sign_request.attributes_ciphertexts.len();
    let hs = params.additional_g1_generators();

    if num_private + public_attributes.len() > hs.len() {
        todo!("return an error")
    }

    if !blind_sign_request.verify_proof(params, pub_key) {
        todo!("return an error")
    }

    let h = hash_g1(blind_sign_request.commitment.to_bytes());

    // in python implementation there are n^2 G1 multiplications, let's do it with a single one instead.
    // i.e. compute h * (pub_m[0] * y[m + 1] + ... + pub_m[n] * y[n]) directly (where m is number of PRIVATE attributes)
    // rather than ((h * pub_m[0]) * y[m + 1] , (h * pub_m[1]) * y[m + 2] , ...).sum() separately
    let signed_public = h * public_attributes
        .iter()
        .zip(secret_key.ys.iter().skip(num_private))
        .map(|(attr, yi)| attr * yi)
        .sum::<Scalar>();

    // y[0] * c1[0] + ... + y[n] * c1[n]
    let sig_1 = blind_sign_request
        .attributes_ciphertexts
        .iter()
        .map(|ciphertext| ciphertext.c1())
        .zip(secret_key.ys.iter())
        .map(|(c1, yi)| c1 * yi)
        .sum();

    // x * h + y[0] * c2[0] + ... y[m] * c2[m] + h * (pub_m[0] * y[m + 1] + ... + pub_m[n] * y[n])
    let sig_2 = blind_sign_request
        .attributes_ciphertexts
        .iter()
        .map(|ciphertext| ciphertext.c2())
        .zip(secret_key.ys.iter())
        .map(|(c2, yi)| c2 * yi)
        .chain(std::iter::once(h * secret_key.x))
        .chain(std::iter::once(signed_public))
        .sum();

    Ok(BlindedSignature(h, (sig_1, sig_2).into()))
}

// Theta
pub struct Theta {
    kappa: G2Projective,
    nu: G1Projective,
    credential: Signature,
    pi_v: ProofOfV,
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
}

pub fn prove_credential<R: RngCore + CryptoRng>(
    params: &mut Parameters<R>,
    verification_key: &VerificationKey,
    signature: &Signature,
    private_attributes: &[Attribute],
) -> Theta {
    if private_attributes.is_empty() {
        todo!("return an error")
    }

    if private_attributes.len() > verification_key.beta.len() {
        todo!("return an error")
    }

    // TODO: should randomization be part of this procedure or should
    // it be up to the user?
    let signature_prime = signature.randomise(params);

    let blinding_factor = params.random_scalar();
    let kappa = params.gen2() * blinding_factor
        + verification_key.alpha
        + private_attributes
            .iter()
            .zip(verification_key.beta.iter())
            .map(|(priv_attr, beta_i)| beta_i * priv_attr)
            .sum::<G2Projective>();
    let nu = signature_prime.base() * blinding_factor;

    let pi_v = ProofOfV::construct(
        params,
        verification_key,
        &signature_prime,
        private_attributes,
        &blinding_factor,
    );

    // kappa = alpha * beta^m * g2^r
    // nu = h^r

    Theta {
        kappa,
        nu,
        credential: signature_prime,
        pi_v,
    }
}

pub fn verify_credential<R>(
    params: &Parameters<R>,
    verification_key: &VerificationKey,
    theta: &Theta,
    public_attributes: &[Attribute],
) -> bool {
    if public_attributes.len() + theta.pi_v.private_attributes() > verification_key.beta.len() {
        todo!("return an error")
    }

    if !theta.verify_proof(params, verification_key) {
        return false;
    }

    let kappa = if public_attributes.is_empty() {
        theta.kappa
    } else {
        theta.kappa
            + public_attributes
                .iter()
                .zip(
                    verification_key
                        .beta
                        .iter()
                        .skip(theta.pi_v.private_attributes()),
                )
                .map(|(pub_attr, beta_i)| beta_i * pub_attr)
                .sum::<G2Projective>()
    };

    let multi_miller = multi_miller_loop(&[
        (
            &theta.credential.0.to_affine(),
            &G2Prepared::from(kappa.to_affine()),
        ),
        (
            &(theta.credential.1 + theta.nu).neg().to_affine(),
            params.prepared_miller_g2(),
        ),
    ]);

    multi_miller.final_exponentiation().is_identity().into()
        && !bool::from(theta.credential.0.is_identity())
}

// TODO: possibly completely remove those two functions.
// They only exist to have a simpler and smaller code snippets to test
// basic functionalities.
/// Creates a Coconut Signature under a given secret key on a set of public attributes only.
fn sign<R: RngCore + CryptoRng>(
    params: &mut Parameters<R>,
    secret_key: &SecretKey,
    public_attributes: &[Attribute],
) -> Result<Signature> {
    if public_attributes.len() > secret_key.ys.len() {
        todo!("return an error")
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

fn verify<R: RngCore + CryptoRng>(
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

    let multi_miller = multi_miller_loop(&[
        (&sig.0.to_affine(), &G2Prepared::from(kappa)),
        (&sig.1.neg().to_affine(), params.prepared_miller_g2()),
    ]);

    multi_miller.final_exponentiation().is_identity().into() && !bool::from(sig.0.is_identity())
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use crate::scheme::keygen::keygen;

    use super::*;

    #[test]
    fn verification_on_two_public_attributes() {
        let rng = OsRng;

        let mut params = Parameters::new(rng, 2);
        let attributes = params.n_random_scalars(2);

        let keypair1 = keygen(&mut params).unwrap();
        let keypair2 = keygen(&mut params).unwrap();
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

        let mut params = Parameters::new(rng, 4);
        let public_attributes = params.n_random_scalars(2);
        let private_attributes = params.n_random_scalars(2);
        let elgamal_keypair = elgamal::keygen(&mut params);

        let keypair1 = keygen(&mut params).unwrap();
        let keypair2 = keygen(&mut params).unwrap();

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
        );
        let theta2 = prove_credential(
            &mut params,
            &keypair2.verification_key,
            &sig2,
            &private_attributes,
        );

        assert!(verify_credential(
            &params,
            &keypair1.verification_key,
            &theta1,
            &public_attributes
        ));

        assert!(verify_credential(
            &params,
            &keypair2.verification_key,
            &theta2,
            &public_attributes
        ));

        assert!(!verify_credential(
            &params,
            &keypair1.verification_key,
            &theta2,
            &public_attributes
        ));
    }
}
