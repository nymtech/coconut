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
	"errors"
	"fmt"
	"github.com/consensys/gurvy/bls381"
	"gitlab.nymte.ch/nym/coconut/coconutGo"
	"gitlab.nymte.ch/nym/coconut/coconutGo/utils"
)

// Theta
type Theta struct {
	// kappa
	kappa bls381.G2Jac
	// nu
	nu bls381.G1Jac
	// sigma
	credential Signature
	// pi_v
	piV ProofKappaNu
}

func (theta *Theta) verifyProof(params *coconutGo.Parameters, verificationKey *VerificationKey) bool {
	return theta.piV.verify(params, verificationKey, &theta.credential, &theta.kappa, &theta.nu)
}

// kappa || nu || credential || pi_v
// TODO: subject to change once serde implementation in place in rust's version and whether
// it's 1:1 compatible with bincode (maybe len(pi_v) is needed?)
func (theta *Theta) Bytes() []byte {
	kappaBytes := utils.G2JacobianToByteSlice(&theta.kappa)
	nuBytes := utils.G1JacobianToByteSlice(&theta.nu)
	credentialBytes := theta.credential.Bytes()
	proofBytes := theta.piV.Bytes()

	b := append(kappaBytes, nuBytes...)
	b = append(b, credentialBytes[:]...)
	b = append(b, proofBytes...)

	return b
}

func ThetaFromBytes(b []byte) (Theta, error) {
	if len(b) < 240 {
		return Theta{}, errors.New("tried to deserialize theta with insufficient number of bytes")
	}

	kappa, err := utils.G2JacobianFromBytes(b[:96])
	if err != nil {
		return Theta{}, err
	}

	nu, err := utils.G1JacobianFromBytes(b[96:144])
	if err != nil {
		return Theta{}, err
	}

	var credentialBytes [2 * bls381.SizeOfG1AffineCompressed]byte
	copy(credentialBytes[:], b[144:240])

	credential, err := SignatureFromBytes(credentialBytes)
	if err != nil {
		return Theta{}, err
	}

	piV, err := ProofKappaNuFromBytes(b[240:])
	if err != nil {
		return Theta{}, err
	}

	return Theta{
		kappa:      kappa,
		nu:         nu,
		credential: credential,
		piV:        piV,
	}, nil
}

func ProveCredential(
	params *coconutGo.Parameters,
	verificationKey *VerificationKey,
	signature *Signature,
	privateAttributes []*coconutGo.Attribute,
) (Theta, error) {
	if len(privateAttributes) == 0 {
		return Theta{}, coconutGo.ErrProveNoPrivate
	}

	if len(privateAttributes) > len(verificationKey.beta) {
		return Theta{}, coconutGo.ErrProveTooManyAttributes
	}

	// TODO: should randomization be part of this procedure or should
	// it be up to the user?
	signaturePrime, err := signature.Randomise(params)
	if err != nil {
		return Theta{}, err
	}

	blindingFactor, err := params.RandomScalar()
	if err != nil {
		return Theta{}, err
	}

	kappa := utils.G2ScalarMul(params.Gen2(), &blindingFactor) // kappa = g2 ^ r
	kappa.AddAssign(&verificationKey.alpha)                    // kappa = g2 ^ r * alpha
	for i := 0; i < len(privateAttributes); i++ {
		tmp := utils.G2ScalarMul(verificationKey.beta[i], privateAttributes[i]) // tmp = beta[i] ^ priv[i]
		kappa.AddAssign(&tmp)                                                   // kappa = g2 ^ r * alpha * beta[0] ^ priv[0] * ... * beta[m] ^ priv[m]
	}

	nu := utils.G1ScalarMul(&signaturePrime.sig1, &blindingFactor) // nu = h^r

	piV, err := constructProofKappaNu(params, verificationKey, &signaturePrime, privateAttributes, &blindingFactor)
	if err != nil {
		return Theta{}, err
	}

	return Theta{
		kappa:      kappa,
		nu:         nu,
		credential: signaturePrime,
		piV:        piV,
	}, nil
}

/// Checks whether e(P, Q) * e(-R, S) == id
func checkBillinearPairing(p *bls381.G1Jac, q bls381.G2Affine, r *bls381.G1Jac, s bls381.G2Affine) bool {
	var rNeg bls381.G1Affine
	rNeg.FromJacobian(r)
	rNeg.Neg(&rNeg)

	pairCheck, err := bls381.PairingCheck(
		[]bls381.G1Affine{utils.ToG1Affine(p), rNeg},
		[]bls381.G2Affine{q, s},
	)

	if err != nil {
		return false
	}

	println(fmt.Sprintf("pair res: %v", pairCheck))
	return pairCheck
}

func VerifyCredential(
	params *coconutGo.Parameters,
	verificationKey *VerificationKey,
	theta *Theta,
	publicAttributes []*coconutGo.Attribute,
) bool {
	numPrivate := len(theta.piV.responseAttributes)

	if len(publicAttributes)+numPrivate > len(verificationKey.beta) {
		return false
	}

	if !theta.verifyProof(params, verificationKey) {
		return false
	}

	var kappa bls381.G2Jac
	kappa.Set(&theta.kappa)

	if len(publicAttributes) > 0 {
		for i := 0; i < len(publicAttributes); i++ {
			tmp := utils.G2ScalarMul(verificationKey.beta[i+numPrivate], publicAttributes[i]) // tmp = beta[m + i] ^ pubAttr[i]
			kappa.AddAssign(&tmp)
		}
	}

	var r bls381.G1Jac
	r.Set(&theta.credential.sig2)
	r.AddAssign(&theta.nu)
	return checkBillinearPairing(&theta.credential.sig1, utils.ToG2Affine(&kappa), &r, *params.Gen2Affine()) && !theta.credential.sig1.Z.IsZero()
}

func Verify(params *coconutGo.Parameters, verificationKey *VerificationKey, publicAttributes []*coconutGo.Attribute, sig *Signature) bool {
	if len(publicAttributes) > len(verificationKey.beta) {
		return false
	}

	var kappa bls381.G2Jac
	kappa.Set(verificationKey.Alpha()) // kappa = X
	for i := 0; i < len(publicAttributes); i++ {
		tmp := utils.G2ScalarMul(verificationKey.beta[i], publicAttributes[i]) // (ai * Yi)
		kappa.AddAssign(&tmp)                                                  // kappa = X + (a1 * Y1) + ...
	}

	return checkBillinearPairing(&sig.sig1, utils.ToG2Affine(&kappa), &sig.sig2, *params.Gen2Affine()) && !sig.sig1.Z.IsZero()
}
