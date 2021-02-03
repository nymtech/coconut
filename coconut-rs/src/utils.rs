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

use crate::error::Result;
use bls12_381::Scalar;

/// Evaluates a polynomial defined by the slice of coefficients at point x.
pub fn evaluate_polynomial(coefficients: &[&Scalar], x: &Scalar) -> Scalar {
    coefficients
        .iter()
        .enumerate()
        .map(|(i, &coefficient)| coefficient * x.pow(&[i as u64, 0, 0, 0])) // coefficient[n] * x ^ n
        .sum()
}


fn generate_lagrangian_coefficients_at_origin(points: &[u64]) -> Vec<Scalar> {
    let x = Scalar::zero();

    points.iter().enumerate().map(|(i, point_i)| {
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
    }).collect()
}

/// Performs a Lagrange interpolation at the origin for a polynomial defined by `points` and `values`.
pub fn perform_lagrangian_interpolation_at_origin(points: &[u64], values: &[&Scalar]) -> Result<Scalar> {
    if points.len() != values.len() {
        // return Err
    }

    let coefficients = generate_lagrangian_coefficients_at_origin(points);
    Ok(coefficients.into_iter().zip(values.iter()).map(|(coeff, &val)| coeff * val).sum())
}

// pub trait PointHash {
//
// }
//
// fn hash_to_g1<D, M>(msg: M) -> G1Affine
// where
//     D: Update,
//     D::OutputSize: ArrayLength<u8>,
//     M: AsRef<[u8]>
// {
//
//
//     todo!()
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polynomial_evaluation() {
        // y = 42 (it should be 42 regardless of x)
        let coeff = &[&Scalar::from(42)];

        assert_eq!(Scalar::from(42), evaluate_polynomial(coeff, &Scalar::from(1)));
        assert_eq!(Scalar::from(42), evaluate_polynomial(coeff, &Scalar::from(0)));
        assert_eq!(Scalar::from(42), evaluate_polynomial(coeff, &Scalar::from(10)));

        // y = x + 10, at x = 2 (exp: 12)
        let coeff = &[&Scalar::from(10), &Scalar::from(1)];

        assert_eq!(Scalar::from(12), evaluate_polynomial(coeff, &Scalar::from(2)));

        // y = x^4 - 5x^2 + 2x - 3, at x = 3 (exp: 39)
        let coeff = &[&(-Scalar::from(3)), &Scalar::from(2), &(-Scalar::from(5)), &Scalar::zero(), &Scalar::from(1)];

        assert_eq!(Scalar::from(39), evaluate_polynomial(coeff, &Scalar::from(3)));
    }

    #[test]
    fn performing_lagrangian_interpolation_at_origin() {
        // x^2 + 3
        // x, f(x):
        // 1, 4,
        // 2, 7,
        // 3, 12,
        let points = vec![1, 2, 3];
        let y1 = &Scalar::from(4);
        let y2 = &Scalar::from(7);
        let y3 = &Scalar::from(12);
        let values = vec![y1, y2, y3];

        assert_eq!(Scalar::from(3), perform_lagrangian_interpolation_at_origin(&points, &values).unwrap());

        // x^3 + 3x^2 - 5x + 11
        // x, f(x):
        // 1, 10
        // 2, 21
        // 3, 50
        // 4, 103
        let points = vec![1, 2, 3, 4];
        let y1 = &Scalar::from(10);
        let y2 = &Scalar::from(21);
        let y3 = &Scalar::from(50);
        let y4 = &Scalar::from(103);
        let values = vec![y1, y2, y3, y4];

        assert_eq!(Scalar::from(11), perform_lagrangian_interpolation_at_origin(&points, &values).unwrap());
    }
}