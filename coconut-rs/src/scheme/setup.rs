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

use crate::error::{Error, ErrorKind, Result};
use crate::utils::hash_g1;
use bls12_381::{G1Affine, G2Affine, G2Prepared, Scalar};
use ff::Field;
use group::Curve;
use rand_core::{CryptoRng, RngCore};

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

    // TODO: rename
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
