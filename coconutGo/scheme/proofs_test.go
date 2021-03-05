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
	"gitlab.nymte.ch/nym/coconut/coconutGo/utils"
	"testing"
)

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
