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

}

/*

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
 */