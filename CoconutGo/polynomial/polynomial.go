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

package polynomial

// originally I wanted to put this into utils to keep it consistent with Rust but Go hates false-positive cyclic
// dependencies ...

import (
	coconut "gitlab.nymte.ch/nym/coconut/CoconutGo"
	"math/big"
)

type Polynomial struct {
	coefficients []*big.Int
}

// for polynomial of degree n, we generate n+1 values
// (for example for degree 1, like y = x + 2, we need [2,1])
func NewRandomPolynomial(params *coconut.Parameters, degree int) (Polynomial, error) {
	coefficients, err := params.NRandomScalars(degree + 1)
	if err != nil {
		return Polynomial{}, err
	}

	return Polynomial{
		coefficients: coefficients,
	}, nil
}

func (poly *Polynomial) Evaluate(x *big.Int, modulus *big.Int) big.Int{
	if len(poly.coefficients) == 0 {
		return *big.NewInt(0)
	// if x is zero then we can ignore most of the expensive computation and
	// just return the last term of the polynomial
	} else 	if x.Cmp(big.NewInt(0)) == 0 {
		// TODO: does that do proper copy?
		return *poly.coefficients[0]
	} else {
		var result big.Int
		result.SetUint64(0)

		for i := 0; i < len(poly.coefficients); i++ {
			var tmp big.Int

			// tmp = x ^ n
			tmp.Exp(x, big.NewInt(int64(i)), modulus)

			// tmp = coefficient[n] * x ^ n
			tmp.Mul(poly.coefficients[i], &tmp)
			// TODO: DOES THIS NEED TO BE REDUCED MOD MODULUS?

			result.Add(&result, &tmp)
		}

		return result
	}
}

/*
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
 */

func GenerateLagrangianCoefficientsAtOrigin(points []uint64) []*big.Int {
	x := big.NewInt(0)

	coefficients := make([]*big.Int, len(points))

	for i := 0; i < len(points); i++ {
		numerator := big.NewInt(1)
		denominator := big.NewInt(1)

		var xi big.Int
		xi.SetUint64(points[i])

		for j := 0; j < len(points); j++ {
			if j != i {
				var xj big.Int
				xj.SetUint64(points[j])

				// tmp1 = (x - xs[j])
				var tmp1 big.Int
				tmp1.Sub(x, &xj)

				// numerator = (x - xs[0]) * ... * (x - xs[j]), j != i
				numerator.Mul(numerator, &tmp1)

				// tmp2 = (xs[i] - xs[j])
				var tmp2 big.Int
				tmp2.Sub(&xi, &xj)

				// denominator = (xs[i] - x[0]) * ... * (xs[i] - x[j]), j != i
				denominator.Mul(denominator, &tmp2)
			}
		}
		// TODO: would it be efficient to do it on fr.Element directly because it's more specific to the curve?
		// TODO: BENCH
		var res big.Int
		res.Div(numerator, denominator)

		coefficients[i] = &res
	}

	return coefficients
}


// no generics : (

// Performs a Lagrange interpolation at the origin for a polynomial defined by `points` and `values`.
func performBigIntLagrangianInterpolationAtOrigin(points []uint64, values []*big.Int)  (*big.Int, error) {
	if len(points) == 0 || len(values) == 0 {
	//	return Err(Error::new(
	//		ErrorKind::Interpolation,
	//		"tried to perform lagrangian interpolation for an empty set of coordinates",
	//));
	}

	if len(points) != len(values) {
	//	return Err(Error::new(
	//		ErrorKind::Interpolation,
	//		"tried to perform lagrangian interpolation for an incomplete set of coordinates",
	//));
	}

	coefficients := GenerateLagrangianCoefficientsAtOrigin(points)

	result := big.NewInt(0)
	for i := 0; i < len(coefficients); i++ {
		var product big.Int
		product.Mul(coefficients[i], values[i])

		result.Add(result, &product)
	}

	return result, nil
}

/*

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
}

 */