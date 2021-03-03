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

// TODO: implement https://crates.io/crates/signature traits?

pub use keygen::{SecretKey, VerificationKey};

pub mod aggregation;
pub mod keygen;
pub mod setup;
pub mod signature;

pub type SignerIndex = u64;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elgamal;
    use crate::scheme::setup::Parameters;
    use crate::scheme::signature::{
        blind_sign, prepare_blind_sign, prove_credential, sign, verify, verify_credential,
    };
    use group::GroupEncoding;
    use rand_core::OsRng;

    // #[test]
    // fn foo() {
    //     let mut params = Parameters::new(OsRng, 4).unwrap();
    //     let keypair = keygen::keygen(&mut params);
    //
    //     println!(
    //         "x: {:?},\n y1: {:?},\n y2: {:?}\n y3: {:?}\ny4:{:?}",
    //         keypair.secret_key.x.to_bytes(),
    //         keypair.secret_key.ys[0].to_bytes(),
    //         keypair.secret_key.ys[1].to_bytes(),
    //         keypair.secret_key.ys[2].to_bytes(),
    //         keypair.secret_key.ys[3].to_bytes(),
    //     );
    //
    //     let attrs_pub = params.n_random_scalars(2);
    //     let attrs_priv = params.n_random_scalars(2);
    //
    //     println!(
    //         "PUB attr1: {:?}, attr2: {:?}",
    //         attrs_pub[0].to_bytes(),
    //         attrs_pub[1].to_bytes()
    //     );
    //
    //     println!(
    //         "PRIV attr1: {:?}, attr2: {:?}",
    //         attrs_priv[0].to_bytes(),
    //         attrs_priv[1].to_bytes()
    //     );
    //
    //     let elgamal = elgamal::keygen(&mut params);
    //
    //     println!(
    //         "ELGAMAL priv: {:?}, pub: {:?}",
    //         elgamal.private_key().0.to_bytes(),
    //         elgamal.public_key().0.to_bytes()
    //     );
    //
    //     let lambda =
    //         prepare_blind_sign(&mut params, elgamal.public_key(), &attrs_priv, &attrs_pub).unwrap();
    //
    //     let blinded_sig = blind_sign(
    //         &mut params,
    //         &keypair.secret_key,
    //         elgamal.public_key(),
    //         &lambda,
    //         &attrs_pub,
    //     )
    //     .unwrap();
    //
    //     println!(
    //         "h: {:?}, sig1: {:?}, sig2: {:?}",
    //         blinded_sig.0.to_bytes(),
    //         blinded_sig.1 .0.to_bytes(),
    //         blinded_sig.1 .1.to_bytes()
    //     );
    //
    //     let sig = blinded_sig.unblind(elgamal.private_key());
    //
    //     println!(
    //         "sig1: {:?}, sig2: {:?}",
    //         sig.sig1().to_bytes(),
    //         sig.sig2().to_bytes()
    //     );
    //
    //     let theta =
    //         prove_credential(&mut params, &keypair.verification_key, &sig, &attrs_priv).unwrap();
    //
    //     assert!(verify_credential(
    //         &params,
    //         &keypair.verification_key,
    //         &theta,
    //         &attrs_pub
    //     ))
    // }
}
