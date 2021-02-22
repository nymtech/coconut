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

func ToG1Affine(jac *bls381.G1Jac) bls381.G1Affine {
	var res bls381.G1Affine
	res.FromJacobian(jac)
	return res
}


// Takes a Scalar and a G1 element by reference and multiplies them together while allocating space for the result
func G2ScalarMul(g2 *bls381.G2Jac, scalar *big.Int) bls381.G2Jac {
	var res bls381.G2Jac
	res.ScalarMultiplication(g2, scalar)
	return res
}

func G2Sub(a *bls381.G2Jac, b *bls381.G2Jac) bls381.G2Jac {
	var res bls381.G2Jac
	res.Set(a)
	res.SubAssign(b)
	return res
}

func G2Add(a *bls381.G2Jac, b *bls381.G2Jac) bls381.G2Jac {
	var res bls381.G2Jac
	res.Set(a)
	res.AddAssign(b)
	return res
}

func ToG2Affine(jac *bls381.G2Jac) bls381.G2Affine {
	var res bls381.G2Affine
	res.FromJacobian(jac)
	return res
}


// that is super temporary as im not really sure whats the appropriate domain for the SWU map

// NOTE!!! THIS USES SVDW METHOD RATHER THAN SSWU FOR CURVE HASHING!!!
// IF https://github.com/ConsenSys/gurvy/issues/24 IS NOT DEALT BEFORE ZCASH DOES SSWU IN RUST
// WE SHOULD SWITCH TO https://github.com/kilic/bls12-381

var dst = []byte("COCONUT_BLS381_G1_SVDW_TMP")

func HashToG1(msg []byte) (bls381.G1Affine, error) {
	//
	//
	// NOTE!!! THIS USES SVDW METHOD RATHER THAN SSWU FOR CURVE HASHING!!!
	// IF https://github.com/ConsenSys/gurvy/issues/24 IS NOT DEALT BEFORE ZCASH DOES SSWU IN RUST
	// WE SHOULD SWITCH TO https://github.com/kilic/bls12-381
	//
	//
	return bls381.HashToCurveG1Svdw(msg, dst)
}

func SumScalars(scalars []*big.Int) big.Int {
	res := big.NewInt(0)
	for _, scalar := range scalars {
		res.Add(res, scalar)
	}

	return *res
}

func ReverseBytes(bytes []byte) []byte {
	bytesNew := make([]byte, len(bytes))
	for i := 0; i < len(bytes)/2; i++ {
		j := len(bytes) - i - 1
		bytesNew[i], bytesNew[j] = bytes[j], bytes[i]
	}
	return bytesNew
}
