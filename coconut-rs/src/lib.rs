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

use bls12_381::Scalar;
use lazy_static::lazy_static;
use rand_core::OsRng;
use sha3::Sha3_384;

pub mod elgamal;
pub mod error;
pub mod proofs;
pub mod scheme;
pub mod utils;

pub type Attribute = Scalar;

// reason for sha3 384 is for the 48 bytes output and it's a good enough solution
// for the temporary use it has
pub(crate) type G1HashDigest = Sha3_384;

lazy_static! {
    static ref RNG: OsRng = OsRng;
}
