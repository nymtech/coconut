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

package coconut

import (
	"github.com/consensys/gurvy/bls381"
	"gitlab.nymte.ch/nym/coconut/CoconutGo/utils"
	"math/big"
)

type Signature struct {
	sig1 bls381.G1Jac
	sig2 bls381.G1Jac
}

func Sign(params *Parameters, secretKey *SecretKey, publicAttributes []*Attribute) (Signature, error){
	if len(publicAttributes) > len(*secretKey.Ys()) {
		// TODO: RETURN ERROR HERE!
	}

	// TODO: why in the python implementation this hash onto the curve is present
	// while it's not used in the paper? the paper uses random exponent instead.
	// (the python implementation hashes string representation of all attributes onto the curve,
	// but I think the same can be achieved by just summing the attributes thus avoiding the unnecessary
	// transformation. If I'm wrong, please correct me.)
	attributesSum := utils.SumScalars(publicAttributes)
	baseRawJac := utils.G1ScalarMul(params.Gen1(), &attributesSum)
	baseRawAff := utils.ToG1Affine(&baseRawJac)
	baseRawBytesCompressed := baseRawAff.Bytes()
	h, err := utils.HashToG1(baseRawBytesCompressed[:])
	if err != nil {
		return Signature{}, err
	}

	var K big.Int
	K.Set(&secretKey.x) // K = x
	for i := 0; i < len(publicAttributes); i++ {
		var tmp big.Int

		// TODO REDUCE ORDER p?

		tmp.Mul(&secretKey.ys[i], publicAttributes[i]) // (ai * yi)
		K.Add(&K, &tmp) // K = x + (a0 * y0) + ...
	}

	// convert h from jacobian to affine (TODO: figure out which representation is actually more efficient)
	var hJac bls381.G1Jac
	hJac.FromAffine(&h)

	sig2 := utils.G1ScalarMul(&hJac, &K)

	return Signature{
		sig1: hJac,
		sig2: sig2,
	}, nil

}

func Verify(params *Parameters, verificationKey *VerificationKey, publicAttributes []*Attribute, sig *Signature) bool {
	if len(publicAttributes) > len(verificationKey.beta) {
		return false
	}

	var K bls381.G2Jac
	K.Set(verificationKey.Alpha()) // K = X
	for i := 0; i < len(publicAttributes); i++ {
		tmp := utils.G2ScalarMul(&verificationKey.beta[i], publicAttributes[i]) // (ai * Yi)
		K.AddAssign(&tmp) // K = X + (a1 * Y1) + ...
	}

	var sig2Neg bls381.G1Affine
	sig2Neg.FromJacobian(&sig.sig2)
	sig2Neg.Neg(&sig2Neg)

	pairCheck, err := bls381.PairingCheck(
		[]bls381.G1Affine{utils.ToG1Affine(&sig.sig1), sig2Neg},
		[]bls381.G2Affine{utils.ToG2Affine(&K), *params.Gen2Affine()},
	)

	if err != nil {
		return false
	}

	return !sig.sig1.Z.IsZero() && pairCheck
}

