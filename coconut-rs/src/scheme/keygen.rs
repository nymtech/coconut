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

use bls12_381::{G2Projective, Scalar};
use rand_core::{CryptoRng, RngCore};
use std::num::NonZeroU64;

// use generic_array::{ArrayLength, GenericArray};
use crate::error::Result;
use crate::scheme::setup::Parameters;
use crate::utils::evaluate_polynomial;

// TODO: some type alias to indicate number of attributes and also size of ys

pub struct SecretKey {
    x: Scalar,
    ys: Vec<Scalar>,

    /// Optional index value specifying polynomial point used during threshold key generation.
    index: Option<u64>,
}

impl SecretKey {
    pub fn verification_key<R: RngCore + CryptoRng>(
        &self,
        params: &Parameters<R>,
    ) -> VerificationKey {
        let g2 = params.gen2();
        VerificationKey {
            alpha: g2 * self.x,
            beta: self.ys.iter().map(|y| g2 * y).collect(),
            index: self.index,
        }
    }
}

pub struct VerificationKey {
    // TODO add gen2 as per the paper or imply it from the fact library is using bls381?
    alpha: G2Projective,
    beta: Vec<G2Projective>,

    /// Optional index value specifying polynomial point used during threshold key generation.
    index: Option<u64>,
}

pub struct KeyPair {
    secret_key: SecretKey,
    verification_key: VerificationKey,
}

/// Generate a single Coconut keypair ((x, y1, y2...), (g2, g2^x, g2^y1, ...)).
/// It is not suitable for threshold credentials as all subsequent calls to `keygen` generate keys
/// that are independent of each other.
pub fn keygen<R: RngCore + CryptoRng>(params: &mut Parameters<R>) -> Result<KeyPair> {
    let attributes = params.additional_g1_generators().len();
    if attributes == 0 {
        // return Err
    }

    let x = params.random_scalar();
    let ys = (0..attributes)
        .map(|_| params.random_scalar())
        .collect::<Vec<_>>();

    let alpha = params.gen2() * x;
    let beta = ys.iter().map(|y| params.gen2() * y).collect::<Vec<_>>();

    Ok(KeyPair {
        secret_key: SecretKey { x, ys, index: None },
        verification_key: VerificationKey {
            alpha,
            beta,
            index: None,
        },
    })
}

/// Generate a set of n Coconut keypairs [((x, y1, y2...), (g2, g2^x, g2^y1, ...)), ...],
/// such that they support threshold aggregation by `threshold` number of parties.
/// It is expected that this procedure is executed by a Trusted Third Party.
// TODO: let's see how NonZero types are going to work in the api here. If we find them to be annoying/inconvenient
// they should be changed to their normal variants with runtime checks to ensure they are actually non-zero
pub fn ttp_keygen<R: RngCore + CryptoRng>(
    params: &mut Parameters<R>,
    threshold: NonZeroU64,
    num_authorities: NonZeroU64,
) -> Result<Vec<KeyPair>> {
    let attributes = params.additional_g1_generators().len();
    if attributes == 0 {
        // return Err
    }

    if threshold > num_authorities {
        // return Err
    }

    // generate polynomials
    let v = params.n_random_scalars(threshold.get());
    let w = (0..num_authorities.get())
        .map(|_| params.n_random_scalars(threshold.get()))
        .collect::<Vec<_>>();

    // TODO: potentially if we had some known authority identifier we could use that instead
    // of the increasing (1,2,3,...) sequence
    let polynomial_indices = (1..=num_authorities.get()).collect::<Vec<_>>();

    // generate polynomial shares
    let x = polynomial_indices
        .iter()
        .map(|&id| evaluate_polynomial(&v, &Scalar::from(id)));
    let y = polynomial_indices.iter().map(|&id| {
        w.iter()
            .map(|w| evaluate_polynomial(&w, &Scalar::from(id)))
            .collect::<Vec<_>>()
    });

    // finally set the keys
    let secret_keys = x
        .zip(y)
        .zip(polynomial_indices.iter())
        .map(|((x, ys), index)| SecretKey {
            x,
            ys,
            index: Some(*index),
        });

    let keypairs = secret_keys
        .map(|secret_key| {
            let verification_key = secret_key.verification_key(params);
            KeyPair {
                secret_key,
                verification_key,
            }
        })
        .collect();

    Ok(keypairs)
}
