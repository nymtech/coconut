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

// use bls12_381::G1Affine;
// use digest::Update;
// use generic_array::{ArrayLength, GenericArray};

use core::iter::Sum;
use core::ops::Mul;

use bls12_381::{G1Projective, Scalar};
use digest::Digest;
use ff::Field;
use group::Group;
use rand_core::{CryptoRng, RngCore, SeedableRng};

use crate::error::Result;
use crate::scheme::setup::Parameters;
use crate::{G1HashDigest, G1HashPRNG};

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

    // pub(crate) fn interpolate_at_origin(&self) {}
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
    points: &[u64],
    values: &[T],
) -> Result<T>
where
    T: Sum,
    // first time I've had to use it, for reference it's called higher ranked trait bounds:
    // https://github.com/rust-lang/rfcs/blob/master/text/0387-higher-ranked-trait-bounds.md
    for<'a> &'a T: Mul<Scalar, Output = T>,
{
    if points.len() != values.len() {
        // return Err
        todo!("return an error here")
    }

    let coefficients = generate_lagrangian_coefficients_at_origin(points);
    Ok(coefficients
        .into_iter()
        .zip(values.iter())
        .map(|(coeff, val)| val * coeff)
        .sum())
}

pub(crate) fn perform_lagrangian_interpolation_at_origin_with_coefficients<T>(
    coefficients: &[Scalar],
    values: &[T],
) -> T
where
    T: Sum,
    for<'a, 'b> &'a T: Mul<&'b Scalar, Output = T>,
{
    coefficients
        .iter()
        .zip(values.iter())
        .map(|(coeff, val)| val * coeff)
        .sum()
}

// A temporary way of hashing particular message into G1.
// Implementation idea was taken from `threshold_crypto`:
// https://github.com/poanetwork/threshold_crypto/blob/7709462f2df487ada3bb3243060504b5881f2628/src/lib.rs#L691
// Eventually it should get replaced by, most likely, the osswu map
// method once ideally it's implemented inside the pairing crate.
pub fn hash_g1<M: AsRef<[u8]>>(msg: M) -> G1Projective {
    _hash_g1::<G1HashDigest, G1HashPRNG, _>(msg)
}

#[doc(hidden)]
fn _hash_g1<D, R, M>(msg: M) -> G1Projective
where
    D: Digest,
    R: RngCore + SeedableRng,
    R::Seed: From<digest::Output<D>>,
    M: AsRef<[u8]>,
{
    let mut h = D::new();
    h.update(msg);
    let digest = h.finalize();

    let mut seeded_rng = R::from_seed(digest.into());

    G1Projective::random(&mut seeded_rng)
}

// // TODO: very likely after some changes this can also be used to sum threshold signatures.
// // I'm not entirely sure yet what trait bounds need to be introduced, but it will be clearer once
// // we get there
// // trait SumThresholdExt: ExactSizeIterator {
// //     fn sum_threshold(self, coefficients: Vec<Scalar>) -> SumThreshold<Self>
// //     where
// //         Self: Sized,
// //     {
// //         assert_eq!(self.len(), coefficients.len());
// //
// //         SumThreshold::new(self, coefficients)
// //     }
// // }
//
// trait Threshold {
//     fn index(self) -> u64;
// }
//
// trait SumThresholdExt<T = Self>: Sized {
//     fn sum_threshold<I: Iterator<Item=T>>(iter: I) -> Self
//         where
//             I::Item: Threshold;
//     // where
//     //     Self: Sized + Threshold,
//     // {
//     //     let indices = se
//     //     // let coefficients = generate_lagrangian_coefficients_at_origin
//     //     todo!()
//     //     // assert_eq!(self.len(), coefficients.len());
//     //     //
//     //     // SumThreshold::new(self, coefficients)
//     // }
// }
//
// impl<T> SumThresholdExt for &[T]
//     where
//         T: Threshold,
// {
//     fn sum_threshold(slice: &[T]) -> Self {
//         let indices = slice.iter().map(|item| item.index());
//         let coefficients = generate_lagrangian_coefficients_at_origin(&indices);
//
//         unimplemented!()
//     }
// }
//
// pub(crate) struct SumThreshold<I>
// // where
// //     I: Iterator,
// //     I::Item: Sum,
// {
//     iter: I,
//     coefficients: Vec<Scalar>,
// }
//
// impl<I> SumThreshold<I> {
//     fn new(iter: I, coefficients: Vec<Scalar>) -> Self {
//         SumThreshold { iter, coefficients }
//     }
// }
//
// impl<I> Iterator for SumThreshold<I>
//     where
//         I: Iterator,
// {
//     type Item = ();
//
//     fn next(&mut self) -> Option<Self::Item> {
//         unimplemented!()
//     }
//
//     fn size_hint(&self) -> (usize, Option<usize>) {
//         (self.coefficients.len(), Some(self.coefficients.len()))
//     }
// }

// pub trait PointHash {
//
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
