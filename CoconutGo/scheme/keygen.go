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
	. "gitlab.nymte.ch/nym/coconut/CoconutGo"
	"gitlab.nymte.ch/nym/coconut/CoconutGo/polynomial"
	"gitlab.nymte.ch/nym/coconut/CoconutGo/utils"
	"math/big"
)



// SecretKey represents secret key of a Coconut signing authority.
type SecretKey struct {
	// TODO: big.Int or Fp.Element?
	x  big.Int
	ys []big.Int
}

func (sk *SecretKey) X() *big.Int {
	return &sk.x
}

func (sk *SecretKey) Ys() *[]big.Int {
	return &sk.ys
}

// Derive verification key using this secret key.
func (sk *SecretKey) VerificationKey(params *Parameters) VerificationKey {
	g2 := params.Gen2()

	alpha := utils.G2ScalarMul(g2, &sk.x)
	beta := make([]*bls381.G2Jac, len(sk.ys))
	for i, y := range sk.ys {
		betai := utils.G2ScalarMul(g2, &y)
		beta[i] = &betai
	}

	return VerificationKey{
		alpha: alpha,
		beta:  beta,
	}
}

// VerificationKey represents verification key of a Coconut signing authority.
type VerificationKey struct {
	alpha bls381.G2Jac
	beta  []*bls381.G2Jac
}

// Alpha returns appropriate part of the the verification key
func (vk *VerificationKey) Alpha() *bls381.G2Jac {
	return &vk.alpha
}

// Beta returns appropriate part of the the verification key
func (vk *VerificationKey) Beta() []*bls381.G2Jac {
	return vk.beta
}

func (vk *VerificationKey) Equal(other *VerificationKey) bool {
	if len(vk.beta) != len(other.beta) {
		return false
	}

	if !utils.G2JacobianEqual(&vk.alpha, &other.alpha) {
		return false
	}

	for i := 0; i < len(vk.beta); i++ {
		if !utils.G2JacobianEqual(vk.beta[i], other.beta[i]) {
			return false
		}
	}
	return true
}

type KeyPair struct {
	secretKey       SecretKey
	verificationKey VerificationKey

	// Optional index value specifying polynomial point used during threshold key generation.
	index *SignerIndex
}

// Generate a single Coconut keypair ((x, y0, y1...), (g2^x, g2^y0, ...)).
// It is not suitable for threshold credentials as all subsequent calls to `keygen` generate keys
// that are independent of each other.
func Keygen(params *Parameters) (KeyPair, error) {
	attributes := len(params.Hs())
	x, err := params.RandomScalar()
	if err != nil {
		return KeyPair{}, err
	}
	ys := make([]big.Int, attributes)
	for i := range ys {
		ys[i], err = params.RandomScalar()
		if err != nil {
			return KeyPair{}, err
		}
	}

	secretKey := SecretKey{
		x:  x,
		ys: ys,
	}

	return KeyPair{
		secretKey:       secretKey,
		verificationKey: secretKey.VerificationKey(params),
	}, nil
}

// Generate a set of n Coconut keypairs [((x, y0, y1...), (g2^x, g2^y0, ...)), ...],
// such that they support threshold aggregation by `threshold` number of parties.
// It is expected that this procedure is executed by a Trusted Third Party.
func TTPKeygen(params *Parameters, threshold uint64, numAuthorities uint64) ([]KeyPair, error) {
	if threshold == 0 {
		return nil, ErrZeroThreshold
	}

	if threshold > numAuthorities {
		return nil, ErrInvalidThreshold
	}

	attributes := len(params.Hs())

	// generate polynomials
	v, err := polynomial.NewRandomPolynomial(params, int(threshold-1))
	if err != nil {
		return nil, err
	}

	ws := make([]polynomial.Polynomial, attributes)
	for i := 0; i < attributes; i++ {
		w, err := polynomial.NewRandomPolynomial(params, int(threshold-1))
		if err != nil {
			return nil, err
		}
		ws[i] = w
	}

	// TODO: potentially if we had some known authority identifier we could use that instead
	// of the increasing (1,2,3,...) sequence
	//polynomialIndices := make([]uint64, numAuthorities)

	secretKeys := make([]SecretKey, numAuthorities)

	// generate polynomial shares
	for i := 0; i < int(numAuthorities); i++ {
		index := big.NewInt(int64(i + 1))

		x := v.Evaluate(index, fr.Modulus())

		ys := make([]big.Int, attributes)
		for j := 0; j < len(ws); j++ {
			ys[j] = ws[j].Evaluate(index, fr.Modulus())
		}

		secretKeys[i] = SecretKey{
			x:  x,
			ys: ys,
		}
	}

	keypairs := make([]KeyPair, numAuthorities)
	for i := 0; i < int(numAuthorities); i++ {
		verificationKey := secretKeys[i].VerificationKey(params)
		index := uint64(i + 1)
		keypairs[i] = KeyPair{
			secretKey:       secretKeys[i],
			verificationKey: verificationKey,
			index:           &index,
		}
	}

	return keypairs, nil
}
