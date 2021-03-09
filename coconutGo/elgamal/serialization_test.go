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

package elgamal

import (
	"github.com/stretchr/testify/assert"
	"gitlab.nymte.ch/nym/coconut/coconutGo"
	"gitlab.nymte.ch/nym/coconut/coconutGo/utils"
	"testing"
)

func TestPrivateKeyBytesRoundtrip(t *testing.T) {
	params, err := coconutGo.Setup(1)
	assert.Nil(t, err)

	keypair, err := Keygen(params)
	assert.Nil(t, err)

	bytes := keypair.privateKey.Bytes()
	assert.Equal(t, utils.ScalarToLittleEndian(&keypair.privateKey.d), bytes)

	recovered, err := PrivateKeyFromBytes(bytes)
	assert.Nil(t, err)

	assert.Equal(t, keypair.privateKey, recovered)
}

func TestPublicKeyBytesRoundtrip(t *testing.T) {
	params, err := coconutGo.Setup(1)
	assert.Nil(t, err)

	keypair, err := Keygen(params)
	assert.Nil(t, err)

	bytes := keypair.publicKey.Bytes()
	assert.Equal(t, utils.G1JacobianToByteSlice(&keypair.publicKey.gamma), bytes[:])

	recovered, err := PublicKeyFromBytes(bytes)
	assert.Nil(t, err)

	assert.True(t, keypair.publicKey.gamma.Equal(&recovered.gamma))
}

func TestCiphertextKeyBytesRoundtrip(t *testing.T) {
	params, err := coconutGo.Setup(1)
	assert.Nil(t, err)

	r, err := params.RandomScalar()
	assert.Nil(t, err)

	s, err := params.RandomScalar()
	assert.Nil(t, err)

	ciphertext := CiphertextFromRaw(utils.G1ScalarMul(params.Gen1(), &r), utils.G1ScalarMul(params.Gen1(), &s))
	bytes := ciphertext.Bytes()

	var expectedBytes [96]byte
	copy(expectedBytes[:48], utils.G1JacobianToByteSlice(ciphertext.C1()))
	copy(expectedBytes[48:], utils.G1JacobianToByteSlice(ciphertext.C2()))

	assert.Equal(t, expectedBytes, bytes)
	recovered, err := CiphertextFromBytes(bytes)
	assert.Nil(t, err)

	assert.True(t, ciphertext.c1.Equal(&recovered.c1))
	assert.True(t, ciphertext.c2.Equal(&recovered.c2))
}
