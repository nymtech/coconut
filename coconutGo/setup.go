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

// this can't go into the `scheme` directory because Go is extremely stupid about cyclic dependencies
// because you either import entire module or nothing at all...

import (
	"errors"
	"fmt"
	"github.com/consensys/gurvy/bls381"
	"github.com/consensys/gurvy/bls381/fr"
	"gitlab.nymte.ch/nym/coconut/coconutGo/utils"
	"math/big"
)

type Parameters struct {
	// TODO: figure out if we want Jacobian or affine coordinates
	g1aff bls381.G1Affine
	g1jac bls381.G1Jac
	hs    []*bls381.G1Affine
	g2aff bls381.G2Affine
	g2jac bls381.G2Jac
}

func Setup(numAttributes uint32) (*Parameters, error) {
	if numAttributes == 0 {
		return nil, errors.New("tried to setup the scheme for 0 attributes")
	}
	g1jac, g2jac, g1aff, g2aff := bls381.Generators()

	hs := make([]*bls381.G1Affine, numAttributes)
	for i := 1; i <= int(numAttributes); i++ {
		hi := utils.HashToG1([]byte(fmt.Sprintf("h%v", i)))
		hs[i-1] = &hi
	}

	return &Parameters{
		g1aff: g1aff,
		hs:    hs,
		g2aff: g2aff,
		g1jac: g1jac,
		g2jac: g2jac,
	}, nil
}

func (params *Parameters) Gen1() *bls381.G1Jac {
	return &params.g1jac
}

func (params *Parameters) Gen2() *bls381.G2Jac {
	return &params.g2jac
}

func (params *Parameters) Gen2Affine() *bls381.G2Affine {
	return &params.g2aff
}

func (params *Parameters) Hs() []*bls381.G1Affine {
	return params.hs
}

// or return Fr.Element directly?
func (params *Parameters) RandomScalar() (big.Int, error) {
	var r fr.Element
	_, err := r.SetRandom()
	if err != nil {
		return big.Int{}, err
	}

	var res big.Int
	r.ToBigInt(&res)
	return res, nil
}

func (params *Parameters) NRandomScalars(n int) ([]*big.Int, error) {
	scalars := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		scalar, err := params.RandomScalar()
		if err != nil {
			return nil, err
		}
		scalars[i] = &scalar
	}
	return scalars, nil
}
