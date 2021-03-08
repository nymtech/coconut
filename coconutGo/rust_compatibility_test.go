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

package coconutGo

import (
	"github.com/consensys/gurvy/bls381/fr"
	"github.com/stretchr/testify/assert"
	"gitlab.nymte.ch/nym/coconut/coconutGo/utils"
	"math/big"
	"testing"
)

func TestScalarSerialization(t *testing.T) {
	// test value, limbs and byte representation
	scalar := big.NewInt(42)

	expectedLimbs := fr.Element{
		395136991140,
		16706400699492528220,
		10895998725622488597,
		6239700025071827469,
	}

	expectedBytes := []byte{42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	expectedValue := "42"

	assert.Equal(t, expectedValue, scalar.String())

	var frScalar fr.Element
	frScalar.SetBigInt(scalar)

	frScalarBytes := frScalar.Bytes()

	assert.Equal(t, expectedBytes, utils.ReverseBytes(frScalarBytes[:]))
	assert.Equal(t, expectedLimbs, frScalar)

	// some exponentiation
	scalar512 := big.NewInt(512)
	var res big.Int

	// 42^512 mod o
	res.Exp(scalar, scalar512, fr.Modulus())

	expectedLimbs = fr.Element{
		12744553619634797806,
		2812099285984544638,
		10023149335646001754,
		7871652299959646057,
	}
	expectedBytes = []byte{249, 153, 114, 33, 163, 49, 188, 167, 110, 39, 174, 124, 246, 13, 60, 19, 170, 123, 111, 95, 160, 195, 40, 158, 97, 19, 159, 91, 117, 144, 195, 112}
	expectedValue = "51004571234394176832463279876548201369249893565884470427882439455118619482617"

	assert.Equal(t, expectedValue, res.String())

	var frRes fr.Element
	frRes.SetBigInt(&res)

	frResBytes := frRes.Bytes()

	assert.Equal(t, expectedLimbs, frRes)
	assert.Equal(t, expectedBytes, utils.ReverseBytes(frResBytes[:]))
}

func TestG1Hash(t *testing.T) {
	input := []byte{1, 2, 3}
	expectedBytes := [48]byte{167, 116, 154, 132, 171, 11, 168, 246, 2, 48, 63, 183, 112, 250, 29, 9, 53, 168, 21, 147, 197, 245, 208, 230, 149, 99, 171, 184, 252, 137, 47, 178, 99, 222, 124, 159, 80, 170, 84, 57, 170, 35, 98, 222, 174, 29, 243, 233}

	hashRes := utils.HashToG1(input)
	assert.Equal(t, expectedBytes, hashRes.Bytes())
}

func TestParams(t *testing.T) {
	expectedHsBytes := [][48]byte{
		{152, 164, 8, 208, 169, 249, 69, 204, 104, 89, 97, 219, 170, 48, 100, 105, 241, 206, 243, 173, 70, 15, 205, 59, 255, 190, 158, 22, 150, 234, 210, 22, 235, 239, 186, 67, 111, 46, 3, 32, 71, 207, 249, 22, 220, 29, 67, 194},
		{143, 56, 14, 10, 113, 227, 11, 0, 21, 114, 29, 21, 232, 185, 128, 246, 221, 98, 82, 81, 232, 106, 107, 249, 227, 149, 242, 71, 42, 149, 236, 234, 129, 173, 70, 18, 76, 24, 54, 99, 188, 121, 27, 134, 16, 141, 213, 199},
		{177, 237, 139, 64, 161, 198, 214, 239, 255, 123, 246, 225, 18, 172, 109, 32, 21, 27, 102, 164, 189, 254, 51, 35, 111, 34, 115, 208, 164, 191, 193, 199, 221, 211, 119, 231, 139, 56, 26, 60, 69, 202, 92, 189, 189, 190, 92, 165},
		{128, 84, 117, 247, 19, 212, 52, 33, 30, 139, 139, 22, 64, 98, 69, 81, 40, 133, 132, 155, 164, 194, 254, 196, 174, 219, 194, 107, 122, 9, 254, 9, 152, 68, 160, 71, 54, 133, 59, 53, 106, 187, 247, 64, 2, 114, 200, 34},
		{149, 70, 148, 244, 92, 36, 5, 205, 96, 67, 221, 87, 43, 35, 230, 156, 0, 101, 120, 165, 193, 96, 226, 168, 120, 67, 96, 1, 190, 52, 55, 26, 230, 114, 194, 217, 108, 220, 213, 254, 60, 82, 92, 92, 70, 72, 41, 60},
	}

	params, err := Setup(5)
	if err != nil {
		panic(err)
	}

	hs := params.Hs()
	for i := 0; i < 5; i++ {
		hsiBytes := hs[i].Bytes()
		assert.Equal(t, expectedHsBytes[i], hsiBytes)
	}
}
