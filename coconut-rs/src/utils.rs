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
use crate::scheme::setup::Parameters;
use crate::scheme::SignerIndex;
use crate::G1HashDigest;
use bls12_381::{G1Affine, G1Projective, Scalar};
use core::iter::Sum;
use core::ops::Mul;
use digest::generic_array;
use digest::generic_array::typenum::Unsigned;
use digest::Digest;
use ff::Field;
use rand_core::{CryptoRng, RngCore};

pub struct Polynomial {
    coefficients: Vec<Scalar>,
}

impl Polynomial {
    // for polynomial of degree n, we generate n+1 values
    // (for example for degree 1, like y = x + 2, we need [2,1])
    pub(crate) fn new_random<R: RngCore + CryptoRng>(
        params: &mut Parameters<R>,
        degree: u64,
    ) -> Self {
        Polynomial {
            coefficients: params.n_random_scalars((degree + 1) as usize),
        }
    }

    /// Evaluates the polynomial at point x.
    pub(crate) fn evaluate(&self, x: &Scalar) -> Scalar {
        if self.coefficients.is_empty() {
            Scalar::zero()
        // if x is zero then we can ignore most of the expensive computation and
        // just return the last term of the polynomial
        } else if x.is_zero() {
            // we checked that coefficients are not empty so unwrap here is fine
            *self.coefficients.first().unwrap()
        } else {
            self.coefficients
                .iter()
                .enumerate()
                // coefficient[n] * x ^ n
                .map(|(i, coefficient)| coefficient * x.pow(&[i as u64, 0, 0, 0]))
                .sum()
        }
    }
}

#[inline]
fn generate_lagrangian_coefficients_at_origin(points: &[u64]) -> Vec<Scalar> {
    let x = Scalar::zero();

    points
        .iter()
        .enumerate()
        .map(|(i, point_i)| {
            let mut numerator = Scalar::one();
            let mut denominator = Scalar::one();
            let xi = Scalar::from(*point_i);

            for (j, point_j) in points.iter().enumerate() {
                if j != i {
                    let xj = Scalar::from(*point_j);

                    // numerator = (x - xs[0]) * ... * (x - xs[j]), j != i
                    numerator *= x - xj;

                    // denominator = (xs[i] - x[0]) * ... * (xs[i] - x[j]), j != i
                    denominator *= xi - xj;
                }
            }
            // numerator / denominator
            numerator * denominator.invert().unwrap()
        })
        .collect()
}

/// Performs a Lagrange interpolation at the origin for a polynomial defined by `points` and `values`.
/// It can be used for Scalars, G1 and G2 points.
pub(crate) fn perform_lagrangian_interpolation_at_origin<T>(
    points: &[SignerIndex],
    values: &[T],
) -> Result<T>
where
    T: Sum,
    for<'a> &'a T: Mul<Scalar, Output = T>,
{
    if points.is_empty() || values.is_empty() {
        return Err(Error::new(
            ErrorKind::Interpolation,
            "tried to perform lagrangian interpolation for an empty set of coordinates",
        ));
    }

    if points.len() != values.len() {
        return Err(Error::new(
            ErrorKind::Interpolation,
            "tried to perform lagrangian interpolation for an incomplete set of coordinates",
        ));
    }

    let coefficients = generate_lagrangian_coefficients_at_origin(points);

    Ok(coefficients
        .into_iter()
        .zip(values.iter())
        .map(|(coeff, val)| val * coeff)
        .sum())
}

// A temporary way of hashing particular message into G1.
// Implementation idea was taken from `threshold_crypto`:
// https://github.com/poanetwork/threshold_crypto/blob/7709462f2df487ada3bb3243060504b5881f2628/src/lib.rs#L691
// Eventually it should get replaced by, most likely, the osswu map
// method once ideally it's implemented inside the pairing crate.
pub(crate) fn hash_g1<M: AsRef<[u8]>>(msg: M) -> G1Projective {
    // _hash_g1::<G1HashDigest, G1HashPRNG, _>(msg)

    _hash_g1_increment_and_check::<G1HashDigest, _>(msg)
}

// unsafe, not constant time, temporary, etc
#[doc(hidden)]
fn _hash_g1_increment_and_check<D, M>(msg: M) -> G1Projective
where
    D: Digest,
    M: AsRef<[u8]>,
{
    // TODO: use blake2b??

    // TODO: when I'm less tired, do this at compile time
    assert_eq!(D::OutputSize::to_usize(), 48);

    let mut h = D::new();

    let mut ctr = 0u64;
    loop {
        // add the counter suffix to the message
        h.update(&msg);
        h.update(&ctr.to_le_bytes());
        ctr += 1;

        let digest = h.finalize_reset();

        // first bit must be set - otherwise it implies uncompressed form (i.e. 96 bytes)
        // second bit must not be set - otherwise it implies the point at infinity
        let compression_flag_set = ((digest[0] >> 7) & 1) == 1;
        let infinity_flag_set = ((digest[0] >> 6) & 1) == 1;

        // continue the loop as there's no point in attempting the point recovery
        if !compression_flag_set || infinity_flag_set {
            continue;
        }

        // that is actually 'safe' (relatively speaking), just not implemented by generic array directly
        // for arrays bigger than 32. Considering that 'increment and check' method
        // is not going to exist in the long run, I'd say it's ok to use 'unsafe' here
        assert_eq!(digest.len(), 48);
        let digest_array: [u8; 48] = unsafe { generic_array::transmute(digest) };

        let option: Option<G1Affine> = G1Affine::from_compressed_unchecked(&digest_array).into();
        if let Some(point) = option {
            let point_projective: G1Projective = point.into();
            return point_projective.clear_cofactor();
        }
    }
}

// #[doc(hidden)]
// fn _hash_g1_seeded_rng<D, R, M>(msg: M) -> G1Projective
// where
//     D: Digest,
//     R: RngCore + SeedableRng,
//     R::Seed: From<digest::Output<D>>,
//     M: AsRef<[u8]>,
// {
//     let mut h = D::new();
//     h.update(msg);
//     let digest = h.finalize();
//
//     let mut seeded_rng = R::from_seed(digest.into());
//
//     G1Projective::random(&mut seeded_rng)
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polynomial_evaluation() {
        // y = 42 (it should be 42 regardless of x)
        let poly = Polynomial {
            coefficients: vec![Scalar::from(42)],
        };

        assert_eq!(Scalar::from(42), poly.evaluate(&Scalar::from(1)));
        assert_eq!(Scalar::from(42), poly.evaluate(&Scalar::from(0)));
        assert_eq!(Scalar::from(42), poly.evaluate(&Scalar::from(10)));

        // y = x + 10, at x = 2 (exp: 12)
        let poly = Polynomial {
            coefficients: vec![Scalar::from(10), Scalar::from(1)],
        };

        assert_eq!(Scalar::from(12), poly.evaluate(&Scalar::from(2)));

        // y = x^4 - 5x^2 + 2x - 3, at x = 3 (exp: 39)
        let poly = Polynomial {
            coefficients: vec![
                (-Scalar::from(3)),
                Scalar::from(2),
                (-Scalar::from(5)),
                Scalar::zero(),
                Scalar::from(1),
            ],
        };

        assert_eq!(Scalar::from(39), poly.evaluate(&Scalar::from(3)));

        // empty polynomial
        let poly = Polynomial {
            coefficients: vec![],
        };

        // should always be 0
        assert_eq!(Scalar::from(0), poly.evaluate(&Scalar::from(1)));
        assert_eq!(Scalar::from(0), poly.evaluate(&Scalar::from(0)));
        assert_eq!(Scalar::from(0), poly.evaluate(&Scalar::from(10)));
    }

    #[test]
    fn performing_lagrangian_scalar_interpolation_at_origin() {
        // x^2 + 3
        // x, f(x):
        // 1, 4,
        // 2, 7,
        // 3, 12,
        let points = vec![1, 2, 3];
        let values = vec![Scalar::from(4), Scalar::from(7), Scalar::from(12)];

        assert_eq!(
            Scalar::from(3),
            perform_lagrangian_interpolation_at_origin(&points, &values).unwrap()
        );

        // x^3 + 3x^2 - 5x + 11
        // x, f(x):
        // 1, 10
        // 2, 21
        // 3, 50
        // 4, 103
        let points = vec![1, 2, 3, 4];
        let values = vec![
            Scalar::from(10),
            Scalar::from(21),
            Scalar::from(50),
            Scalar::from(103),
        ];

        assert_eq!(
            Scalar::from(11),
            perform_lagrangian_interpolation_at_origin(&points, &values).unwrap()
        );

        // more points than it is required
        // x^2 + x + 10
        // x, f(x)
        // 1, 12
        // 2, 16
        // 3, 22
        // 4, 30
        // 5, 40
        let points = vec![1, 2, 3, 4, 5];
        let values = vec![
            Scalar::from(12),
            Scalar::from(16),
            Scalar::from(22),
            Scalar::from(30),
            Scalar::from(40),
        ];

        assert_eq!(
            Scalar::from(10),
            perform_lagrangian_interpolation_at_origin(&points, &values).unwrap()
        );
    }

    #[test]
    fn hash_g1_sanity_check() {
        let mut rng = rand_core::OsRng;
        let mut msg1 = [0u8; 1024];
        rng.fill_bytes(&mut msg1);
        let mut msg2 = [0u8; 1024];
        rng.fill_bytes(&mut msg2);

        assert_eq!(hash_g1(msg1), hash_g1(msg1));
        assert_eq!(hash_g1(msg2), hash_g1(msg2));
        assert_ne!(hash_g1(msg1), hash_g1(msg2));
    }
}
