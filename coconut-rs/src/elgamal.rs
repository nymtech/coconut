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

use crate::scheme::setup::Parameters;
use bls12_381::{G1Projective, Scalar};
use core::ops::{Deref, Mul};
use rand_core::{CryptoRng, RngCore};

pub type EphemeralKey = Scalar;

pub struct Ciphertext(pub G1Projective, pub G1Projective);
// pub struct Ciphertext(G1Projective, G1Projective);

impl Ciphertext {
    // TODO NAMING:
    pub(crate) fn c1(&self) -> &G1Projective {
        &self.0
    }

    // TODO NAMING:
    pub(crate) fn c2(&self) -> &G1Projective {
        &self.1
    }
}

impl From<(G1Projective, G1Projective)> for Ciphertext {
    fn from(raw: (G1Projective, G1Projective)) -> Self {
        Ciphertext(raw.0, raw.1)
    }
}

pub struct PrivateKey(pub(crate) Scalar);

impl PrivateKey {
    /// Decrypt takes the ElGamal encryption of a message and returns a point on the G1 curve
    /// that represents original h^m.
    pub fn decrypt(&self, ciphertext: &Ciphertext) -> G1Projective {
        let (c1, c2) = &(ciphertext.0, ciphertext.1);

        // (gamma^k * h^m) / (g1^{d * k})   |   note: gamma = g1^d
        c2 - c1 * self.0
    }

    pub fn public_key<R: RngCore + CryptoRng>(&self, params: &Parameters<R>) -> PublicKey {
        PublicKey(params.gen1() * self.0)
    }
}

// TODO: perhaps be more explicit and apart from gamma also store generator and group order?
pub struct PublicKey(pub(crate) G1Projective);

impl PublicKey {
    /// Encrypt encrypts the given message in the form of h^m,
    /// where h is a point on the G1 curve using the given public key.
    /// The random k is returned alongside the encryption
    /// as it is required by the Coconut Scheme to create proofs of knowledge.
    pub fn encrypt<R: RngCore + CryptoRng>(
        &self,
        params: &mut Parameters<R>,
        // TODO NAMING: 'h'
        h: &G1Projective,
        msg: &Scalar,
    ) -> (Ciphertext, EphemeralKey) {
        let k = params.random_scalar();
        // c1 = g1^k
        let c1 = params.gen1() * k;
        // c2 = gamma^k * h^m
        let c2 = self.0 * k + h * msg;

        (Ciphertext(c1, c2), k)
    }
}

impl Deref for PublicKey {
    type Target = G1Projective;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a, 'b> Mul<&'b Scalar> for &'a PublicKey {
    type Output = G1Projective;

    fn mul(self, rhs: &'b Scalar) -> Self::Output {
        self.0 * rhs
    }
}

pub struct KeyPair {
    private_key: PrivateKey,
    public_key: PublicKey,
}

impl KeyPair {
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }
}

pub fn keygen<R: RngCore + CryptoRng>(params: &mut Parameters<R>) -> KeyPair {
    let private_key = params.random_scalar();
    let gamma = params.gen1() * private_key;

    KeyPair {
        private_key: PrivateKey(private_key),
        public_key: PublicKey(gamma),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen() {
        let mut params = Parameters::default();
        let keypair = super::keygen(&mut params);

        let expected = params.gen1() * keypair.private_key.0;
        let gamma = keypair.public_key.0;
        assert_eq!(
            expected, gamma,
            "Public key, gamma, should be equal to g1^d, where d is the private key"
        );
    }

    #[test]
    fn encryption() {
        let mut params = Parameters::default();
        let keypair = super::keygen(&mut params);

        let r = params.random_scalar();
        let h = params.gen1() * r;
        let m = params.random_scalar();

        let (ciphertext, ephemeral_key) = keypair.public_key.encrypt(&mut params, &h, &m);

        let expected_c1 = params.gen1() * ephemeral_key;
        assert_eq!(expected_c1, ciphertext.0, "c1 should be equal to g1^k");

        let expected_c2 = keypair.public_key.0 * ephemeral_key + h * m;
        assert_eq!(
            expected_c2, ciphertext.1,
            "c2 should be equal to gamma^k * h^m"
        );
    }

    #[test]
    fn decryption() {
        let mut params = Parameters::default();
        let keypair = super::keygen(&mut params);

        let r = params.random_scalar();
        let h = params.gen1() * r;
        let m = params.random_scalar();

        let (ciphertext, _) = keypair.public_key.encrypt(&mut params, &h, &m);
        let dec = keypair.private_key.decrypt(&ciphertext);

        let expected = h * m;
        assert_eq!(
            expected, dec,
            "after ElGamal decryption, original h^m should be obtained"
        );
    }
}
