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

import (
	"github.com/consensys/gurvy/bls381/fr"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestPolynomialEvaluation(t *testing.T) {
	// y = 42 (it should be 42 regardless of x)
	poly := Polynomial{
		coefficients: []*big.Int{big.NewInt(42)},
	}

	assert.Equal(t, *big.NewInt(42), poly.Evaluate(big.NewInt(1), fr.Modulus()))
	assert.Equal(t, *big.NewInt(42), poly.Evaluate(big.NewInt(0), fr.Modulus()))
	assert.Equal(t, *big.NewInt(42), poly.Evaluate(big.NewInt(10), fr.Modulus()))

	// y = x + 10, at x = 2 (exp: 12)
	poly = Polynomial{
		coefficients: []*big.Int{big.NewInt(10), big.NewInt(1)},
	}

	assert.Equal(t, *big.NewInt(12), poly.Evaluate(big.NewInt(2), fr.Modulus()))

	// y = x^4 - 5x^2 + 2x - 3, at x = 3 (exp: 39)
	poly = Polynomial{
		coefficients: []*big.Int{
			big.NewInt(-3),
			big.NewInt(2),
			big.NewInt(-5),
			big.NewInt(0),
			big.NewInt(1),
		},
	}

	assert.Equal(t, *big.NewInt(39), poly.Evaluate(big.NewInt(3), fr.Modulus()))

	// empty polynomial
	poly = Polynomial{
		coefficients: []*big.Int{},
	}

	// should always be 0
	assert.Equal(t, *big.NewInt(0), poly.Evaluate(big.NewInt(1), fr.Modulus()))
	assert.Equal(t, *big.NewInt(0), poly.Evaluate(big.NewInt(0), fr.Modulus()))
	assert.Equal(t, *big.NewInt(0), poly.Evaluate(big.NewInt(10), fr.Modulus()))
}

func TestLagrangianBigIntInterpolationAtOrigin(t *testing.T) {
	// x^2 + 3
	// x, f(x):
	// 1, 4,
	// 2, 7,
	// 3, 12,
	points := []uint64{1, 2, 3}
	values := []*big.Int{big.NewInt(4), big.NewInt(7), big.NewInt(12)}

	result, err := performBigIntLagrangianInterpolationAtOrigin(points, values)
	if err != nil {
		panic(err)
	}

	assert.Equal(t, big.NewInt(3), result)

	// x^3 + 3x^2 - 5x + 11
	// x, f(x):
	// 1, 10
	// 2, 21
	// 3, 50
	// 4, 103
	points = []uint64{1, 2, 3, 4}
	values = []*big.Int{
		big.NewInt(10),
		big.NewInt(21),
		big.NewInt(50),
		big.NewInt(103),
	}

	result, err = performBigIntLagrangianInterpolationAtOrigin(points, values)
	if err != nil {
		panic(err)
	}

	assert.Equal(t, big.NewInt(11), result)

	// more points than it is required
	// x^2 + x + 10
	// x, f(x)
	// 1, 12
	// 2, 16
	// 3, 22
	// 4, 30
	// 5, 40
	points = []uint64{1, 2, 3, 4, 5}
	values = []*big.Int{
		big.NewInt(12),
		big.NewInt(16),
		big.NewInt(22),
		big.NewInt(30),
		big.NewInt(40),
	}

	result, err = performBigIntLagrangianInterpolationAtOrigin(points, values)
	if err != nil {
		panic(err)
	}

	assert.Equal(t, big.NewInt(10), result)
}
