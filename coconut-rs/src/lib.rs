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
use sha3::Sha3_384;

pub mod elgamal;
mod error;
mod proofs;
mod scheme;
#[cfg(test)]
mod tests;
mod utils;

pub use elgamal::elgamal_keygen;
pub use elgamal::ElGamalKeyPair;
pub use error::CoconutError;
pub use scheme::aggregation::aggregate_signature_shares;
pub use scheme::aggregation::aggregate_verification_keys;
pub use scheme::issuance::blind_sign;
pub use scheme::issuance::prepare_blind_sign;
pub use scheme::issuance::BlindSignRequest;
pub use scheme::keygen::ttp_keygen;
pub use scheme::keygen::KeyPair;
pub use scheme::keygen::VerificationKey;
pub use scheme::setup::setup;
pub use scheme::setup::Parameters;
pub use scheme::verification::prove_credential;
pub use scheme::verification::verify_credential;
pub use scheme::BlindedSignature;
pub use scheme::Signature;
pub use scheme::SignatureShare;

pub type Attribute = Scalar;

// reason for sha3 384 is for the 48 bytes output and it's a good enough solution
// for the temporary use it has
type G1HashDigest = Sha3_384;

#[cfg(doctest)]
mod doctest {
    use doc_comment::doctest;

    doctest!("../README.md");
}
