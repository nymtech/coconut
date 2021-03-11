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
	"github.com/consensys/gurvy/bls381/fr"
	"gitlab.nymte.ch/nym/coconut/coconutGo"
	"gitlab.nymte.ch/nym/coconut/coconutGo/polynomial"
	"gitlab.nymte.ch/nym/coconut/coconutGo/utils"
)

func checkUniqueIndices(indices []SignerIndex) bool {
	seen := make(map[SignerIndex]bool)
	for i := 0; i < len(indices); i++ {
		if _, ok := seen[indices[i]]; ok {
			return false
		}
		seen[indices[i]] = true
	}
	return true
}

func performVerificationKeyLagrangianInterpolationAtOrigin(points []uint64, values []*VerificationKey) (VerificationKey, error) {
	if len(points) == 0 || len(values) == 0 {
		return VerificationKey{}, coconutGo.ErrInterpolationEmpty
	}

	if len(points) != len(values) {
		return VerificationKey{}, coconutGo.ErrInterpolationIncomplete
	}

	coefficients := polynomial.GenerateLagrangianCoefficientsAtOrigin(points, fr.Modulus())

	result := VerificationKey{
		alpha: bls381.G2Jac{},
		beta:  make([]*bls381.G2Jac, len(values[0].beta)),
	}

	// set result to be the same as the first key provided multiplied by the first coefficient
	result.alpha = utils.G2ScalarMul(&values[0].alpha, coefficients[0])
	for i := 0; i < len(values[0].beta); i++ {
		betai := utils.G2ScalarMul(values[0].beta[i], coefficients[0])
		result.beta[i] = &betai
	}

	// continue adding key * coefficient to the result
	for i := 1; i < len(values); i++ {
		tmpAlpha := utils.G2ScalarMul(values[i].Alpha(), coefficients[i])
		result.alpha.AddAssign(&tmpAlpha)
		for j := 0; j < len(values[0].beta); j++ {
			tmpBetaJ := utils.G2ScalarMul(values[i].beta[j], coefficients[i])
			result.beta[j].AddAssign(&tmpBetaJ)
		}
	}

	return result, nil
}

//func SumG2JacobianPoints(points []*bls381.G2Jac) bls381.G2Jac {
//	var sum bls381.G2Jac
//	if len(points) == 0 {
//		return sum
//	}
//	sum.Set(points[0])
//	for i := 1; i < len(points); i++ {
//		sum.AddAssign(points[i])
//	}
//	return sum
//}

func checkSameKeySize(keys []*VerificationKey) bool {
	len0 := len(keys[0].beta)
	for i := 1; i < len(keys); i++ {
		if len(keys[i].beta) != len0 {
			return false
		}
	}

	return true
}

// no generics : (
func AggregateVerificationKeys(keys []*VerificationKey, indices []SignerIndex) (VerificationKey, error) {
	if len(keys) == 0 {
		return VerificationKey{}, coconutGo.ErrAggregationEmpty
	}

	if !checkSameKeySize(keys) {
		return VerificationKey{}, coconutGo.ErrDifferentSizeKeyAggregation
	}

	if indices != nil {
		if !checkUniqueIndices(indices) {
			return VerificationKey{}, coconutGo.ErrAggregationNonUniqueIndices
		}
		return performVerificationKeyLagrangianInterpolationAtOrigin(indices, keys)
	} else {
		aggregate := VerificationKey{
			alpha: bls381.G2Jac{},
			beta:  make([]*bls381.G2Jac, len(keys[0].beta)),
		}
		// set aggregate to be the same as the first key provided
		aggregate.alpha.Set(keys[0].Alpha())
		for i := 0; i < len(keys[0].beta); i++ {
			aggregate.beta[i].Set(keys[0].beta[i])
		}

		for i := 1; i < len(keys); i++ {
			aggregate.alpha.AddAssign(keys[i].Alpha())
			for j := 0; i < len(keys[0].beta); j++ {
				aggregate.beta[j].AddAssign(keys[i].beta[j])
			}
		}

		return aggregate, nil
	}
}

func performSignatureLagrangianInterpolationAtOrigin(points []uint64, values []*Signature) (Signature, error) {
	if len(points) == 0 || len(values) == 0 {
		return Signature{}, coconutGo.ErrInterpolationEmpty
	}

	if len(points) != len(values) {
		return Signature{}, coconutGo.ErrInterpolationIncomplete
	}

	coefficients := polynomial.GenerateLagrangianCoefficientsAtOrigin(points, fr.Modulus())

	// set result to be the same as the first signature provided multiplied by the first coefficient
	var sig1 bls381.G1Jac
	sig1.Set(&values[0].sig1)
	sig2 := utils.G1ScalarMul(&values[0].sig2, coefficients[0])
	result := Signature{
		sig1: sig1,
		sig2: sig2,
	}

	for i := 1; i < len(values); i++ {
		tmpSig2 := utils.G1ScalarMul(&values[i].sig2, coefficients[i])
		result.sig2.AddAssign(&tmpSig2)
	}

	return result, nil
}

func AggregateSignatures(sigs []*PartialSignature, indices []SignerIndex) (Signature, error) {
	if len(sigs) == 0 {
		return Signature{}, coconutGo.ErrAggregationEmpty
	}

	if indices != nil {
		if !checkUniqueIndices(indices) {
			return Signature{}, coconutGo.ErrAggregationNonUniqueIndices
		}
		return performSignatureLagrangianInterpolationAtOrigin(indices, sigs)
	} else {
		// set aggregate to be the same as the first signature provided
		aggregate := Signature{
			sig1: sigs[0].sig1,
			sig2: sigs[0].sig2,
		}

		for i := 1; i < len(sigs); i++ {
			aggregate.sig2.AddAssign(&sigs[i].sig2)
		}

		return aggregate, nil
	}

}

func AggregateSignatureShares(shares []*SignatureShare) (Signature, error) {
	signatures := make([]*Signature, len(shares))
	indices := make([]SignerIndex, len(shares))
	for i := 0; i < len(shares); i++ {
		signatures[i] = shares[i].Signature()
		indices[i] = shares[i].Index()
	}

	return AggregateSignatures(signatures, indices)
}
