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
	"github.com/consensys/gurvy/bls381/fr"
	"github.com/stretchr/testify/assert"
	"gitlab.nymte.ch/nym/coconut/coconutGo"
	"gitlab.nymte.ch/nym/coconut/coconutGo/elgamal"
	"gitlab.nymte.ch/nym/coconut/coconutGo/utils"
	"testing"
)

// this is only a test function used to compare literal proof values as
// during normal procedure this would be implicit
func (proof *ProofCmCs) reduceModOrder() {
	mod := fr.Modulus()
	proof.challenge.Mod(&proof.challenge, mod)
	proof.responseRandom.Mod(&proof.responseRandom, mod)
	for i := range proof.responseKeys {
		proof.responseKeys[i].Mod(&proof.responseKeys[i], mod)
	}
	for i := range proof.responseAttributes {
		proof.responseAttributes[i].Mod(&proof.responseAttributes[i], mod)
	}
}

func (proof *ProofKappaNu) reduceModOrder() {
	mod := fr.Modulus()
	proof.challenge.Mod(&proof.challenge, mod)
	proof.responseBlinder.Mod(&proof.responseBlinder, mod)
	for i := range proof.responseAttributes {
		proof.responseAttributes[i].Mod(&proof.responseAttributes[i], mod)
	}
}

func TestConstructChallengeCompatibility(t *testing.T) {
	d1 := []byte{1, 2, 3, 4, 5}
	d2 := []byte{6, 7, 8, 9, 10}

	c := constructChallenge([][]byte{d1, d2})

	expectedLimbs := fr.Element{
		10790667672525378426,
		6565959884967702960,
		9400796567542708905,
		343472932236831220,
	}

	expectedBytes := []byte{228, 108, 36, 126, 221, 208, 240, 82, 214, 56, 6, 110, 97, 209, 115, 20, 205, 249, 151, 130, 250, 205, 25, 150, 11, 218, 221, 236, 33, 191, 115, 59}
	expectedValue := "26890964627037673471376439057946573449888477562608308267871220359518717504740"

	assert.Equal(t, expectedValue, c.String())

	var frScalar fr.Element
	frScalar.SetBigInt(&c)

	frScalarBytes := frScalar.Bytes()

	assert.Equal(t, expectedBytes, utils.ReverseBytes(frScalarBytes[:]))
	assert.Equal(t, expectedLimbs, frScalar)
}

func TestProofCmCsBytesRoundtrip(t *testing.T) {
	// 0 public 1 private
	params, err := coconutGo.Setup(1)
	assert.Nil(t, err)

	publicAttributes, err := params.NRandomScalars(0)
	assert.Nil(t, err)

	privateAttributes, err := params.NRandomScalars(1)
	assert.Nil(t, err)

	elgamalKeypair, err := elgamal.Keygen(params)
	assert.Nil(t, err)

	// we don't care about 'correctness' of the proof. only whether we can correctly recover it from bytes
	randomScalar, err := params.RandomScalar()
	assert.Nil(t, err)
	cm := utils.G1ScalarMul(params.Gen1(), &randomScalar)

	r, err := params.RandomScalar()
	assert.Nil(t, err)

	ephemeralKeys, err := params.NRandomScalars(1)
	assert.Nil(t, err)

	piS, err := constructProofCmCs(
		params,
		elgamalKeypair.PublicKey(),
		ephemeralKeys,
		&cm,
		&r,
		privateAttributes,
		publicAttributes,
	)
	assert.Nil(t, err)

	bytes := piS.Bytes()

	recovered, err := ProofCmCsFromBytes(bytes)
	assert.Nil(t, err)

	piS.reduceModOrder()
	recovered.reduceModOrder()
	assert.Equal(t, piS, recovered)

	// 2 public 2 private
	params, err = coconutGo.Setup(4)
	assert.Nil(t, err)

	publicAttributes, err = params.NRandomScalars(2)
	assert.Nil(t, err)

	privateAttributes, err = params.NRandomScalars(2)
	assert.Nil(t, err)

	elgamalKeypair, err = elgamal.Keygen(params)
	assert.Nil(t, err)

	// we don't care about 'correctness' of the proof. only whether we can correctly recover it from bytes
	randomScalar, err = params.RandomScalar()
	assert.Nil(t, err)
	cm = utils.G1ScalarMul(params.Gen1(), &randomScalar)

	r, err = params.RandomScalar()
	assert.Nil(t, err)

	ephemeralKeys, err = params.NRandomScalars(2)
	assert.Nil(t, err)

	piS, err = constructProofCmCs(
		params,
		elgamalKeypair.PublicKey(),
		ephemeralKeys,
		&cm,
		&r,
		privateAttributes,
		publicAttributes,
	)
	assert.Nil(t, err)

	bytes = piS.Bytes()

	recovered, err = ProofCmCsFromBytes(bytes)
	assert.Nil(t, err)

	piS.reduceModOrder()
	recovered.reduceModOrder()
	assert.Equal(t, piS, recovered)

}

func TestProofKappaNuBytesRoundtrip(t *testing.T) {
	// 0 public 1 private
	params, err := coconutGo.Setup(1)
	assert.Nil(t, err)

	keypair, err := Keygen(params)
	assert.Nil(t, err)

	// we don't care about 'correctness' of the proof. only whether we can correctly recover it from bytes
	r, err := params.RandomScalar()
	assert.Nil(t, err)
	s, err := params.RandomScalar()
	assert.Nil(t, err)

	sig := Signature{
		sig1: utils.G1ScalarMul(params.Gen1(), &r),
		sig2: utils.G1ScalarMul(params.Gen1(), &s),
	}

	privateAttributes, err := params.NRandomScalars(1)
	assert.Nil(t, err)

	r, err = params.RandomScalar()
	assert.Nil(t, err)

	piV, err := constructProofKappaNu(
		params,
		&keypair.VerificationKey,
		&sig,
		privateAttributes,
		&r,
	)
	assert.Nil(t, err)

	bytes := piV.Bytes()

	recovered, err := ProofKappaNuFromBytes(bytes)
	assert.Nil(t, err)

	piV.reduceModOrder()
	recovered.reduceModOrder()
	assert.Equal(t, piV, recovered)

	// 2 public 2 private
	params, err = coconutGo.Setup(4)
	assert.Nil(t, err)

	keypair, err = Keygen(params)
	assert.Nil(t, err)

	// we don't care about 'correctness' of the proof. only whether we can correctly recover it from bytes
	r, err = params.RandomScalar()
	assert.Nil(t, err)
	s, err = params.RandomScalar()
	assert.Nil(t, err)

	sig = Signature{
		sig1: utils.G1ScalarMul(params.Gen1(), &r),
		sig2: utils.G1ScalarMul(params.Gen1(), &s),
	}

	privateAttributes, err = params.NRandomScalars(2)
	assert.Nil(t, err)

	r, err = params.RandomScalar()
	assert.Nil(t, err)

	piV, err = constructProofKappaNu(
		params,
		&keypair.VerificationKey,
		&sig,
		privateAttributes,
		&r,
	)
	assert.Nil(t, err)

	bytes = piV.Bytes()

	recovered, err = ProofKappaNuFromBytes(bytes)
	assert.Nil(t, err)

	piV.reduceModOrder()
	recovered.reduceModOrder()
	assert.Equal(t, piV, recovered)
}