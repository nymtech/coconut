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
	"github.com/stretchr/testify/assert"
	"gitlab.nymte.ch/nym/coconut/coconutGo"
	"gitlab.nymte.ch/nym/coconut/coconutGo/elgamal"
	"gitlab.nymte.ch/nym/coconut/coconutGo/utils"
	"testing"
)

func TestVerificationOnTwoPublicAttributes(t *testing.T) {
	params, err := coconutGo.Setup(2)
	unwrapError(err)

	attributes, err := params.NRandomScalars(2)
	unwrapError(err)

	keypair1, err := Keygen(params)
	unwrapError(err)

	keypair2, err := Keygen(params)
	unwrapError(err)

	sig1, err := Sign(params, &keypair1.secretKey, attributes)
	unwrapError(err)

	sig2, err := Sign(params, &keypair2.secretKey, attributes)
	unwrapError(err)

	assert.True(t, Verify(params, &keypair1.verificationKey, attributes, &sig1))
	assert.False(t, Verify(params, &keypair2.verificationKey, attributes, &sig1))
	assert.False(t, Verify(params, &keypair1.verificationKey, attributes, &sig2))
}

func TestVerificationOnTwoPublicAndTwoPrivateAttributes(t *testing.T) {
	params, err := coconutGo.Setup(4)
	unwrapError(err)

	publicAttributes, err := params.NRandomScalars(2)
	unwrapError(err)

	privateAttributes, err := params.NRandomScalars(2)
	unwrapError(err)

	elgamalKeypair, err := elgamal.Keygen(params)
	unwrapError(err)

	keypair1, err := Keygen(params)
	unwrapError(err)

	keypair2, err := Keygen(params)
	unwrapError(err)

	lambda, err := PrepareBlindSign(params, elgamalKeypair.PublicKey(), privateAttributes, publicAttributes)
	unwrapError(err)

	sig1B, err := BlindSign(params, &keypair1.secretKey, elgamalKeypair.PublicKey(), &lambda, publicAttributes)
	unwrapError(err)
	sig1 := sig1B.Unblind(elgamalKeypair.PrivateKey())

	sig2B, err := BlindSign(params, &keypair2.secretKey, elgamalKeypair.PublicKey(), &lambda, publicAttributes)
	unwrapError(err)
	sig2 := sig2B.Unblind(elgamalKeypair.PrivateKey())

	theta1, err := ProveCredential(params, &keypair1.verificationKey, &sig1, privateAttributes)
	unwrapError(err)

	theta2, err := ProveCredential(params, &keypair2.verificationKey, &sig2, privateAttributes)
	unwrapError(err)

	assert.True(t, VerifyCredential(params, &keypair1.verificationKey, &theta1, publicAttributes))
	assert.True(t, VerifyCredential(params, &keypair2.verificationKey, &theta2, publicAttributes))
	assert.False(t, VerifyCredential(params, &keypair1.verificationKey, &theta2, publicAttributes))
}

func TestVerificationOnTwoPublicAndTwoPrivateAttributesFromTwoSigners(t *testing.T) {
	params, err := coconutGo.Setup(4)
	unwrapError(err)

	publicAttributes, err := params.NRandomScalars(2)
	unwrapError(err)

	privateAttributes, err := params.NRandomScalars(2)
	unwrapError(err)

	elgamalKeypair, err := elgamal.Keygen(params)
	unwrapError(err)

	keypairs, err := TTPKeygen(params, 2, 3)
	unwrapError(err)

	lambda, err := PrepareBlindSign(params, elgamalKeypair.PublicKey(), privateAttributes, publicAttributes)
	unwrapError(err)

	sigs := make([]*Signature, 3)
	for i := 0; i < 3; i++ {
		blindedSig, err := BlindSign(params, &keypairs[i].secretKey, elgamalKeypair.PublicKey(), &lambda, publicAttributes)
		unwrapError(err)
		sig := blindedSig.Unblind(elgamalKeypair.PrivateKey())
		sigs[i] = &sig
	}

	verificationKeys := make([]*VerificationKey, 3)
	for i := 0; i < 3; i++ {
		verificationKeys[i] = &keypairs[i].verificationKey
	}

	aggrVk, err := AggregateVerificationKeys(verificationKeys[:2], []uint64{1, 2})
	unwrapError(err)

	aggrSig, err := AggregateSignatures(sigs[:2], []uint64{1, 2})
	unwrapError(err)

	theta, err := ProveCredential(params, &aggrVk, &aggrSig, privateAttributes)
	unwrapError(err)

	assert.True(t, VerifyCredential(params, &aggrVk, &theta, publicAttributes))

	// taking different subset of keys and credentials
	aggrVk, err = AggregateVerificationKeys(verificationKeys[1:], []uint64{2, 3})
	unwrapError(err)

	aggrSig, err = AggregateSignatures(sigs[1:], []uint64{2, 3})
	unwrapError(err)

	theta, err = ProveCredential(params, &aggrVk, &aggrSig, privateAttributes)
	unwrapError(err)

	assert.True(t, VerifyCredential(params, &aggrVk, &theta, publicAttributes))
}

func TestThetaBytesRoundtrip(t *testing.T) {
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

	theta, err := ProveCredential(params, &keypair.verificationKey, &sig, privateAttributes)
	assert.Nil(t, err)

	bytes := theta.Bytes()

	recovered, err := ThetaFromBytes(bytes)
	assert.Nil(t, err)

	theta.piV.reduceModOrder()
	recovered.piV.reduceModOrder()
	assert.True(t, theta.kappa.Equal(&recovered.kappa))
	assert.True(t, theta.nu.Equal(&recovered.nu))
	assert.True(t, theta.credential.Equal(&recovered.credential))
	assert.Equal(t, theta.piV, recovered.piV)

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

	theta, err = ProveCredential(params, &keypair.verificationKey, &sig, privateAttributes)
	assert.Nil(t, err)

	bytes = theta.Bytes()

	recovered, err = ThetaFromBytes(bytes)
	assert.Nil(t, err)

	theta.piV.reduceModOrder()
	recovered.piV.reduceModOrder()
	assert.True(t, theta.kappa.Equal(&recovered.kappa))
	assert.True(t, theta.nu.Equal(&recovered.nu))
	assert.True(t, theta.credential.Equal(&recovered.credential))
	assert.Equal(t, theta.piV, recovered.piV)
}