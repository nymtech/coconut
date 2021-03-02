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
use bls12_381::{G1Affine, G1Projective, Scalar};
use core::ops::{Deref, Mul};
use rand_core::{CryptoRng, RngCore};

/// Type alias for the ephemeral key generated during ElGamal encryption
pub type EphemeralKey = Scalar;

/// Two G1 points representing ElGamal ciphertext
pub struct Ciphertext(G1Projective, G1Projective);

impl Ciphertext {
    pub(crate) fn c1(&self) -> &G1Projective {
        &self.0
    }

    pub(crate) fn c2(&self) -> &G1Projective {
        &self.1
    }
}

impl From<(G1Projective, G1Projective)> for Ciphertext {
    fn from(raw: (G1Projective, G1Projective)) -> Self {
        Ciphertext(raw.0, raw.1)
    }
}

/// PrivateKey used in the ElGamal encryption scheme to recover the plaintext
pub struct PrivateKey(Scalar);

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
/// PublicKey used in the ElGamal encryption scheme to produce the ciphertext
pub struct PublicKey(G1Projective);

impl PublicKey {
    /// Encrypt encrypts the given message in the form of h^m,
    /// where h is a point on the G1 curve using the given public key.
    /// The random k is returned alongside the encryption
    /// as it is required by the Coconut Scheme to create proofs of knowledge.
    pub fn encrypt<R: RngCore + CryptoRng>(
        &self,
        params: &mut Parameters<R>,
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

/// A convenient wrapper for both keys of the ElGamal keypair
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

/// Generate a fresh ElGamal keypair using the group generator specified by the provided [Parameters]
pub fn keygen<R: RngCore + CryptoRng>(params: &mut Parameters<R>) -> KeyPair {
    let private_key = params.random_scalar();
    let gamma = params.gen1() * private_key;

    KeyPair {
        private_key: PrivateKey(private_key),
        public_key: PublicKey(gamma),
    }
}

use group::Curve;
#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

#[cfg(feature = "serde")]
impl Serialize for PrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeTuple;
        let mut tup = serializer.serialize_tuple(32)?;
        for byte in self.0.to_bytes().iter() {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for PrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PrivateKeyVisitor;

        impl<'de> Visitor<'de> for PrivateKeyVisitor {
            type Value = PrivateKey;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a 32-byte ElGamal private key on BLS12_381 curve")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<PrivateKey, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = [0u8; 32];
                // I think this way makes it way more readable than the iterator approach
                #[allow(clippy::needless_range_loop)]
                for i in 0..32 {
                    bytes[i] = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &"expected 32 bytes"))?;
                }

                Into::<Option<_>>::into(Scalar::from_bytes(&bytes))
                    .ok_or_else(|| {
                        serde::de::Error::custom(&"private key scalar was not canonically encoded")
                    })
                    .map(PrivateKey)
            }
        }

        deserializer.deserialize_tuple(32, PrivateKeyVisitor)
    }
}

#[cfg(feature = "serde")]
impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeTuple;
        let mut tup = serializer.serialize_tuple(48)?;
        for byte in self.to_affine().to_compressed().as_ref().iter() {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PublicKeyVisitor;

        impl<'de> Visitor<'de> for PublicKeyVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a 48-byte compressed ElGamal public key on BLS12_381 curve")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<PublicKey, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = [0u8; 48];
                // I think this way makes it way more readable than the iterator approach
                #[allow(clippy::needless_range_loop)]
                for i in 0..48 {
                    bytes[i] = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &"expected 48 bytes"))?;
                }

                Into::<Option<G1Affine>>::into(G1Affine::from_compressed(&bytes))
                    .ok_or_else(|| {
                        serde::de::Error::custom(
                            &"public key G1 curve point was not canonically encoded",
                        )
                    })
                    .map(|point_affine| PublicKey(G1Projective::from(point_affine)))
            }
        }

        deserializer.deserialize_tuple(48, PublicKeyVisitor)
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

    #[test]
    #[cfg(feature = "serde")]
    fn serde_bincode_private_key_roundtrip() {
        use super::*;

        let mut params = Parameters::default();
        let keypair = keygen(&mut params);

        let encoded = bincode::serialize(keypair.private_key()).unwrap();
        let decoded: PrivateKey = bincode::deserialize(&encoded).unwrap();

        assert_eq!(encoded.len(), 32);
        // their raw bytes are the same
        assert_eq!(decoded.0.to_bytes(), keypair.private_key.0.to_bytes());

        // it can also be deserialized directly from the raw bytes
        let raw_bytes = keypair.private_key.0.to_bytes();
        let decoded_raw: PrivateKey = bincode::deserialize(&raw_bytes).unwrap();
        assert_eq!(decoded_raw.0.to_bytes(), keypair.private_key.0.to_bytes());
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_bincode_public_key_roundtrip() {
        use super::*;

        let mut params = Parameters::default();
        let keypair = keygen(&mut params);

        let encoded = bincode::serialize(keypair.public_key()).unwrap();
        let decoded: PublicKey = bincode::deserialize(&encoded).unwrap();

        assert_eq!(encoded.len(), 48);
        assert_eq!(decoded.0, keypair.public_key.0);

        // it can also be deserialized directly from the raw bytes
        let raw_bytes = keypair.public_key.0.to_affine().to_compressed();
        let decoded_raw: PublicKey = bincode::deserialize(&raw_bytes).unwrap();
        assert_eq!(decoded_raw.0, keypair.public_key.0);
    }
}
