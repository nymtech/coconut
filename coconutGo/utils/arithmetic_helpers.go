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

package utils

import (
	"github.com/consensys/gurvy/bls381"
	"math/big"
)

// Takes a Scalar and a G1 element by reference and multiplies them together while allocating space for the result
func G1ScalarMul(g1 *bls381.G1Jac, scalar *big.Int) bls381.G1Jac {
	var res bls381.G1Jac
	res.ScalarMultiplication(g1, scalar)
	return res
}

func G1Sub(a *bls381.G1Jac, b *bls381.G1Jac) bls381.G1Jac {
	var res bls381.G1Jac
	res.Set(a)
	res.SubAssign(b)
	return res
}

func G1Add(a *bls381.G1Jac, b *bls381.G1Jac) bls381.G1Jac {
	var res bls381.G1Jac
	res.Set(a)
	res.AddAssign(b)
	return res
}

// Takes a Scalar and a G1 element by reference and multiplies them together while allocating space for the result
func G2ScalarMul(g2 *bls381.G2Jac, scalar *big.Int) bls381.G2Jac {
	var res bls381.G2Jac
	res.ScalarMultiplication(g2, scalar)
	return res
}

func SumScalars(scalars []*big.Int) big.Int {
	res := big.NewInt(0)
	for _, scalar := range scalars {
		res.Add(res, scalar)
	}

	return *res
}
