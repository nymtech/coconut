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
	"gitlab.nymte.ch/nym/coconut/coconutGo"
	"math/big"
)

type Polynomial struct {
	coefficients []*big.Int
}

// for polynomial of degree n, we generate n+1 values
// (for example for degree 1, like y = x + 2, we need [2,1])
func NewRandomPolynomial(params *coconutGo.Parameters, degree int) (Polynomial, error) {
	coefficients, err := params.NRandomScalars(degree + 1)
	if err != nil {
		return Polynomial{}, err
	}

	return Polynomial{
		coefficients: coefficients,
	}, nil
}

func (poly *Polynomial) Evaluate(x *big.Int, modulus *big.Int) big.Int {
	if len(poly.coefficients) == 0 {
		return *big.NewInt(0)
		// if x is zero then we can ignore most of the expensive computation and
		// just return the last term of the polynomial
	} else if x.Cmp(big.NewInt(0)) == 0 {
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

			result.Add(&result, &tmp)
		}

		return result
	}
}

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
func performBigIntLagrangianInterpolationAtOrigin(points []uint64, values []*big.Int) (*big.Int, error) {
	if len(points) == 0 || len(values) == 0 {
		return nil, coconutGo.ErrInterpolationEmpty
	}

	if len(points) != len(values) {
		return nil, coconutGo.ErrInterpolationIncomplete
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
