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
	"github.com/consensys/gurvy/bls381/fr"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestScalarFromBytesWide(t *testing.T) {
	// [1,2,3,4,0,0,0,...,0]
	var bytes [64]byte
	bytes[0] = 1
	bytes[1] = 2
	bytes[2] = 3
	bytes[3] = 4

	scalar := ScalarFromBytesWide(bytes)

	expectedLimbs := fr.Element{
		638357424232995150,
		18318482137387888306,
		6522133161251861171,
		2520726223698683018,
	}

	expectedBytes := []byte{1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	expectedValue := "67305985"

	assert.Equal(t, expectedValue, scalar.String())

	var frScalar fr.Element
	frScalar.SetBigInt(&scalar)

	frScalarBytes := frScalar.Bytes()

	assert.Equal(t, expectedBytes, ReverseBytes(frScalarBytes[:]))
	assert.Equal(t, expectedLimbs, frScalar)

	// [0,0,0,....1,2,3,4]
	var bytes2 [64]byte
	bytes2[60] = 1
	bytes2[61] = 2
	bytes2[62] = 3
	bytes2[63] = 4

	scalar = ScalarFromBytesWide(bytes2)

	expectedLimbs = fr.Element{
		8296047984791007455,
		6749167863319126124,
		990660411030559962,
		3728100482992396851,
	}

	expectedBytes = []byte{48, 40, 98, 96, 151, 178, 153, 124, 62, 43, 26, 188, 204, 223, 246, 103, 194, 210, 177, 140, 32, 195, 75, 10, 188, 234, 92, 118, 32, 17, 118, 71}
	expectedValue = "32322818407927025939359778789648808124910768125310499785920609756176927828016"

	assert.Equal(t, expectedValue, scalar.String())

	var frScalar2 fr.Element
	frScalar2.SetBigInt(&scalar)

	frScalarBytes = frScalar2.Bytes()

	assert.Equal(t, expectedBytes, ReverseBytes(frScalarBytes[:]))
	assert.Equal(t, expectedLimbs, frScalar2)

	// [1,2,3,4,0,0,0,...0,0,1,2,3,4]
	var bytes3 [64]byte
	bytes3[0] = 1
	bytes3[1] = 2
	bytes3[2] = 3
	bytes3[3] = 4

	bytes3[60] = 1
	bytes3[61] = 2
	bytes3[62] = 3
	bytes3[63] = 4

	scalar = ScalarFromBytesWide(bytes3)

	expectedLimbs = fr.Element{
		8934405409024002605,
		6620905926997462814,
		7512793572282421134,
		6248826706691079869,
	}

	expectedBytes = []byte{49, 42, 101, 100, 151, 178, 153, 124, 62, 43, 26, 188, 204, 223, 246, 103, 194, 210, 177, 140, 32, 195, 75, 10, 188, 234, 92, 118, 32, 17, 118, 71}
	expectedValue = "32322818407927025939359778789648808124910768125310499785920609756176995134001"

	assert.Equal(t, expectedValue, scalar.String())

	var frScalar3 fr.Element
	frScalar3.SetBigInt(&scalar)

	frScalarBytes = frScalar3.Bytes()

	assert.Equal(t, expectedBytes, ReverseBytes(frScalarBytes[:]))
	assert.Equal(t, expectedLimbs, frScalar3)
}
