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

package scheme

import (
	"fmt"
	"github.com/consensys/gurvy/bls381"
	"github.com/consensys/gurvy/bls381/fp"
	"math/big"
)

type Parameters struct {
	// TODO: figure out if we want jacobian or affine coordinaates
	g1aff bls381.G1Affine
	hs []bls381.G1Affine
	g2aff bls381.G2Affine
	g1jac bls381.G1Jac
}

// that is super temporary as im not really sure whats the appropriate domain for the SWU map

// NOTE!!! THIS USES SVDW METHOD RATHER THAN SSWU FOR CURVE HASHING!!!
// IF https://github.com/ConsenSys/gurvy/issues/24 IS NOT DEALT BEFORE ZCASH DOES SSWU IN RUST
// WE SHOULD SWITCH TO https://github.com/kilic/bls12-381

var dst = []byte("COCONUT_BLS381_G1_SVDW_TMP")

func Setup(num_attributes uint32) (*Parameters, error) {
	g1jac, _, g1aff, g2aff := bls381.Generators()

	hs := make([]bls381.G1Affine, num_attributes)
	for i := 1; i <= int(num_attributes); i++ {
		//
		//
		// NOTE!!! THIS USES SVDW METHOD RATHER THAN SSWU FOR CURVE HASHING!!!
		// IF https://github.com/ConsenSys/gurvy/issues/24 IS NOT DEALT BEFORE ZCASH DOES SSWU IN RUST
		// WE SHOULD SWITCH TO https://github.com/kilic/bls12-381
		//
		//
		hi, err := bls381.HashToCurveG1Svdw([]byte(fmt.Sprintf("h%v", i)), dst)
		if err != nil {
			return nil, err
		}
		hs[i-1] = hi
	}

	return &Parameters{
		g1aff: g1aff,
		hs:    nil,
		g2aff: g2aff,
		g1jac: g1jac,
	}, nil
}

func (params *Parameters) G1() *bls381.G1Jac {
	return &params.g1jac
}

// or return Fp.Element directly?
func (params *Parameters) RandomScalar() (*big.Int, error) {
	var r fp.Element
	_, err := r.SetRandom()
	if err != nil {
		return nil, err
	}

	var res big.Int
	r.ToBigInt(&res)
	return &res, nil
}

/*

pub struct Parameters<R> {
    g1: G1Affine,
    hs: Vec<G1Affine>,
    g2: G2Affine,
    _g2_prepared_miller: G2Prepared,
    rng: R,
}

impl<R> Parameters<R> {
    pub fn new(rng: R, num_attributes: u32) -> Result<Parameters<R>> {
        if num_attributes == 0 {
            return Err(Error::new(
                ErrorKind::Setup,
                "tried to setup the scheme for 0 attributes",
            ));
        }

        let hs = (1..=num_attributes)
            .map(|i| hash_g1(format!("h{}", i)).to_affine())
            .collect();

        Ok(Parameters {
            g1: G1Affine::generator(),
            hs,
            g2: G2Affine::generator(),
            _g2_prepared_miller: G2Prepared::from(G2Affine::generator()),
            rng,
        })
    }

    pub(crate) fn gen1(&self) -> &G1Affine {
        &self.g1
    }

    pub(crate) fn gen2(&self) -> &G2Affine {
        &self.g2
    }

    pub(crate) fn prepared_miller_g2(&self) -> &G2Prepared {
        &self._g2_prepared_miller
    }

    // TODO NAMING:
    pub(crate) fn additional_g1_generators(&self) -> &[G1Affine] {
        &self.hs
    }

    pub(crate) fn random_scalar(&mut self) -> Scalar
    where
        R: RngCore + CryptoRng,
    {
        Scalar::random(&mut self.rng)
    }

    pub(crate) fn n_random_scalars(&mut self, n: usize) -> Vec<Scalar>
    where
        R: RngCore + CryptoRng,
    {
        (0..n).map(|_| self.random_scalar()).collect()
    }
}

// for ease of use in tests requiring params
// TODO: not sure if this will have to go away when tests require some specific number of generators
#[cfg(test)]
impl Default for Parameters<rand_core::OsRng> {
    fn default() -> Self {
        Parameters {
            g1: G1Affine::generator(),
            hs: Vec::new(),
            g2: G2Affine::generator(),
            _g2_prepared_miller: G2Prepared::from(G2Affine::generator()),
            rng: rand_core::OsRng,
        }
    }
}

*/
