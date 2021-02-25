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
	poly = Polynomial {
		coefficients: []*big.Int{big.NewInt(10), big.NewInt(1)},
	}

	assert.Equal(t, *big.NewInt(12), poly.Evaluate(big.NewInt(2), fr.Modulus()))

	// y = x^4 - 5x^2 + 2x - 3, at x = 3 (exp: 39)
	poly = Polynomial {
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
	poly = Polynomial {
		coefficients: []*big.Int{},
	}

	// should always be 0
	assert.Equal(t, *big.NewInt(0), poly.Evaluate(big.NewInt(1),fr.Modulus()))
	assert.Equal(t, *big.NewInt(0), poly.Evaluate(big.NewInt(0),fr.Modulus()))
	assert.Equal(t, *big.NewInt(0), poly.Evaluate(big.NewInt(10),fr.Modulus()))

}
