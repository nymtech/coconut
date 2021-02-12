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
use crate::scheme::SignerIndex;
use crate::utils::{Aggregatable, Polynomial};
use bls12_381::{G2Projective, Scalar};
use core::borrow::Borrow;
use core::iter::Sum;
use core::ops::{Add, Mul};
use itertools::Itertools;
use rand_core::{CryptoRng, RngCore};

#[derive(Debug)]
pub struct SecretKey {
    pub(crate) x: Scalar,
    pub(crate) ys: Vec<Scalar>,
}

impl SecretKey {
    /// Derive verification key using this secret key.
    pub fn verification_key<R: RngCore + CryptoRng>(
        &self,
        params: &Parameters<R>,
    ) -> VerificationKey {
        let g2 = params.gen2();
        VerificationKey {
            alpha: g2 * self.x,
            beta: self.ys.iter().map(|y| g2 * y).collect(),
        }
    }
}

// TODO: perhaps change points to affine representation
// to make verification slightly more efficient?
#[derive(Debug, PartialEq)]
pub struct VerificationKey {
    // TODO add gen2 as per the paper or imply it from the fact library is using bls381?
    pub(crate) alpha: G2Projective,
    pub(crate) beta: Vec<G2Projective>,
}

impl<'b> Add<&'b VerificationKey> for VerificationKey {
    type Output = VerificationKey;

    #[inline]
    fn add(self, rhs: &'b VerificationKey) -> VerificationKey {
        // If you're trying to add two keys together that were created
        // for different number of attributes, just panic as it's a
        // nonsense operation.
        assert_eq!(
            self.beta.len(),
            rhs.beta.len(),
            "trying to add verification keys generated for different number of attributes"
        );

        VerificationKey {
            alpha: self.alpha + rhs.alpha,
            beta: self
                .beta
                .iter()
                .zip(rhs.beta.iter())
                .map(|(self_beta, rhs_beta)| self_beta + rhs_beta)
                .collect(),
        }
    }
}

impl<'a> Mul<Scalar> for &'a VerificationKey {
    type Output = VerificationKey;

    #[inline]
    fn mul(self, rhs: Scalar) -> Self::Output {
        VerificationKey {
            alpha: self.alpha * rhs,
            beta: self.beta.iter().map(|b_i| b_i * rhs).collect(),
        }
    }
}

impl<T> Sum<T> for VerificationKey
where
    T: Borrow<VerificationKey>,
{
    #[inline]
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        let mut peekable = iter.peekable();
        let head_attributes = match peekable.peek() {
            Some(head) => head.borrow().beta.len(),
            None => {
                // TODO: this is a really weird edge case. You're trying to sum an EMPTY iterator
                // of VerificationKey. So should it panic here or just return some nonsense value?
                return VerificationKey::identity(0);
            }
        };

        peekable.fold(VerificationKey::identity(head_attributes), |acc, item| {
            acc + item.borrow()
        })
    }
}

impl VerificationKey {
    /// Create a (kinda) identity verification key using specified
    /// number of 'beta' elements
    fn identity(beta_size: usize) -> Self {
        VerificationKey {
            alpha: G2Projective::identity(),
            beta: vec![G2Projective::identity(); beta_size],
        }
    }
}

pub struct KeyPair {
    pub secret_key: SecretKey,
    pub verification_key: VerificationKey,

    /// Optional index value specifying polynomial point used during threshold key generation.
    pub index: Option<u64>,
}

/// Generate a single Coconut keypair ((x, y0, y1...), (g2^x, g2^y0, ...)).
/// It is not suitable for threshold credentials as all subsequent calls to `keygen` generate keys
/// that are independent of each other.
pub fn keygen<R: RngCore + CryptoRng>(params: &mut Parameters<R>) -> KeyPair {
    let attributes = params.additional_g1_generators().len();

    let x = params.random_scalar();
    let ys = params.n_random_scalars(attributes);

    let secret_key = SecretKey { x, ys };
    let verification_key = secret_key.verification_key(params);

    KeyPair {
        secret_key,
        verification_key,
        index: None,
    }
}

/// Generate a set of n Coconut keypairs [((x, y0, y1...), (g2^x, g2^y0, ...)), ...],
/// such that they support threshold aggregation by `threshold` number of parties.
/// It is expected that this procedure is executed by a Trusted Third Party.
pub fn ttp_keygen<R: RngCore + CryptoRng>(
    params: &mut Parameters<R>,
    threshold: u64,
    num_authorities: u64,
) -> Result<Vec<KeyPair>> {
    if threshold == 0 {
        todo!("return an error")
    }

    if threshold > num_authorities {
        todo!("return an error")
    }

    let attributes = params.additional_g1_generators().len();

    // generate polynomials
    let v = Polynomial::new_random(params, threshold - 1);
    let ws = (0..attributes)
        .map(|_| Polynomial::new_random(params, threshold - 1))
        .collect::<Vec<_>>();

    // TODO: potentially if we had some known authority identifier we could use that instead
    // of the increasing (1,2,3,...) sequence
    let polynomial_indices = (1..=num_authorities).collect::<Vec<_>>();

    // generate polynomial shares
    let x = polynomial_indices
        .iter()
        .map(|&id| v.evaluate(&Scalar::from(id)));
    let ys = polynomial_indices.iter().map(|&id| {
        ws.iter()
            .map(|w| w.evaluate(&Scalar::from(id)))
            .collect::<Vec<_>>()
    });

    // finally set the keys
    let secret_keys = x.zip(ys).map(|(x, ys)| SecretKey { x, ys });

    let keypairs = secret_keys
        .zip(polynomial_indices.iter())
        .map(|(secret_key, index)| {
            let verification_key = secret_key.verification_key(params);
            KeyPair {
                secret_key,
                verification_key,
                index: Some(*index),
            }
        })
        .collect();

    Ok(keypairs)
}

/// Ensures all provided verification keys were generated to verify the same number of attributes.
fn check_same_key_size(keys: &[VerificationKey]) -> bool {
    keys.iter().map(|vk| vk.beta.len()).all_equal()
}

// TODO: move to different file
pub fn aggregate_verification_keys(
    keys: &[VerificationKey],
    indices: Option<&[SignerIndex]>,
) -> Result<VerificationKey> {
    if !check_same_key_size(keys) {
        todo!("return error")
    }
    Aggregatable::aggregate(keys, indices)

    // if keys.is_empty() {
    //     todo!("return error")
    // }
    //
    // if !check_same_key_size(keys) {
    //     todo!("return error")
    // }
    //
    // if let Some(indices) = indices {
    //     if !check_unique_indices(indices) {
    //         todo!("return error")
    //     }
    //     perform_lagrangian_interpolation_at_origin(indices, keys)
    // } else {
    //     // non-threshold (unwrap is fine as we've ensured the slice is non-empty)
    //     Ok(keys.iter().sum())
    // }
}

// fn aggregate_curve_points<T: Aggregatable>(curve_points: &[T], indices: Option<&[SignerIndex]>) -> Result<T> {
//     if curve_points.is_empty() {
//         // err
//     }
//
//     if let Some(indices) = indices {
//         if !check_unique_indices(indices) {
//             todo!("return error")
//         }
//         perform_lagrangian_interpolation_at_origin(indices, curve_points)
//     } else {
//         // non-threshold (unwrap is fine as we've ensured the slice is non-empty)
//         Ok(curve_points.iter().sum())
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn key_aggregation_works_for_any_subset_of_keys() {
        let rng = OsRng;

        let mut params = Parameters::new(rng, 2).unwrap();
        let keypairs = ttp_keygen(&mut params, 3, 5).unwrap();

        let vks = keypairs
            .into_iter()
            .map(|keypair| keypair.verification_key)
            .collect::<Vec<_>>();

        let aggr_vk1 = aggregate_verification_keys(&vks[..3], Some(&[1, 2, 3])).unwrap();
        let aggr_vk2 = aggregate_verification_keys(&vks[2..], Some(&[3, 4, 5])).unwrap();

        assert_eq!(aggr_vk1, aggr_vk2);

        // TODO: should those two actually work or not?
        // aggregating threshold+1
        let aggr_more = aggregate_verification_keys(&vks[1..], Some(&[2, 3, 4, 5])).unwrap();
        assert_eq!(aggr_vk1, aggr_more);

        // aggregating all
        let aggr_all = aggregate_verification_keys(&vks, Some(&[1, 2, 3, 4, 5])).unwrap();
        assert_eq!(aggr_all, aggr_vk1);

        // not taking enough points (threshold was 3)
        let aggr_not_enough = aggregate_verification_keys(&vks[..2], Some(&[1, 2])).unwrap();
        assert_ne!(aggr_not_enough, aggr_vk1);

        // taking wrong index
        let aggr_bad = aggregate_verification_keys(&vks[2..], Some(&[42, 123, 100])).unwrap();
        assert_ne!(aggr_vk1, aggr_bad);
    }

    #[test]
    fn key_aggregation_doesnt_work_for_empty_set_of_keys() {
        let keys: Vec<VerificationKey> = vec![];
        assert!(aggregate_verification_keys(&keys, None).is_err());
    }

    #[test]
    fn key_aggregation_doesnt_work_if_indices_have_invalid_length() {
        let keys = vec![VerificationKey::identity(3)];

        assert!(aggregate_verification_keys(&keys, Some(&[])).is_err());
        assert!(aggregate_verification_keys(&keys, Some(&[1, 2])).is_err());
    }

    #[test]
    fn key_aggregation_doesnt_work_for_non_unique_indices() {
        let keys = vec![VerificationKey::identity(3), VerificationKey::identity(3)];

        assert!(aggregate_verification_keys(&keys, Some(&[1, 1])).is_err());
    }

    #[test]
    fn key_aggregation_doesnt_work_for_keys_of_different_size() {
        let keys = vec![VerificationKey::identity(3), VerificationKey::identity(1)];

        assert!(aggregate_verification_keys(&keys, None).is_err())
    }

    // TODO: test for aggregating non-threshold keys
}
