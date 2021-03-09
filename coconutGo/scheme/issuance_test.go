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

func TestBlindSignRequestBytesRoundtrip(t *testing.T) {
	// 1 private, 0 public
	params, err := coconutGo.Setup(1)
	assert.Nil(t, err)

	publicAttributes, err := params.NRandomScalars(0)
	assert.Nil(t, err)

	privateAttributes, err := params.NRandomScalars(1)
	assert.Nil(t, err)

	elgamalKeypair, err := elgamal.Keygen(params)
	assert.Nil(t, err)

	lambda, err := PrepareBlindSign(params, elgamalKeypair.PublicKey(), privateAttributes, publicAttributes)
	assert.Nil(t, err)

	bytes := lambda.Bytes()

	recovered, err := BlindSignRequestFromBytes(bytes)
	assert.Nil(t, err)

	lambda.piS.reduceModOrder()
	recovered.piS.reduceModOrder()

	assert.True(t, lambda.commitment.Equal(&recovered.commitment))
	for i := range lambda.attributesCiphertexts {
		assert.True(t, lambda.attributesCiphertexts[i].Equal(recovered.attributesCiphertexts[i]))
	}
	assert.Equal(t, lambda.piS, recovered.piS)
	assert.Equal(t, utils.G1JacobianToByteSlice(&lambda.commitment), utils.G1JacobianToByteSlice(&recovered.commitment))


	// 2 private, 2 public
	params, err = coconutGo.Setup(4)
	assert.Nil(t, err)

	publicAttributes, err = params.NRandomScalars(2)
	assert.Nil(t, err)

	privateAttributes, err = params.NRandomScalars(2)
	assert.Nil(t, err)

	elgamalKeypair, err = elgamal.Keygen(params)
	assert.Nil(t, err)

	lambda, err = PrepareBlindSign(params, elgamalKeypair.PublicKey(), privateAttributes, publicAttributes)
	assert.Nil(t, err)

	bytes = lambda.Bytes()

	recovered, err = BlindSignRequestFromBytes(bytes)
	assert.Nil(t, err)

	lambda.piS.reduceModOrder()
	recovered.piS.reduceModOrder()

	assert.True(t, lambda.commitment.Equal(&recovered.commitment))
	for i := range lambda.attributesCiphertexts {
		assert.True(t, lambda.attributesCiphertexts[i].Equal(recovered.attributesCiphertexts[i]))
	}
	assert.Equal(t, lambda.piS, recovered.piS)
	assert.Equal(t, utils.G1JacobianToByteSlice(&lambda.commitment), utils.G1JacobianToByteSlice(&recovered.commitment))

}
