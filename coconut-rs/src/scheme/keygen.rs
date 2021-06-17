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

use crate::error::{CoconutError, Result};
use crate::scheme::aggregation::aggregate_verification_keys;
use crate::scheme::setup::Parameters;
use crate::scheme::SignerIndex;
use crate::utils::{
    try_deserialize_g2_projective, try_deserialize_scalar, try_deserialize_scalar_vec, Polynomial,
};
use bls12_381::{G2Projective, Scalar};
use core::borrow::Borrow;
use core::iter::Sum;
use core::ops::{Add, Mul};
use group::Curve;
use std::convert::TryFrom;
use std::convert::TryInto;

#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

// #[cfg(feature = "serde")]
// use crate::utils::ScalarDef;

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
// #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecretKey {
    // #[cfg_attr(feature = "serde", serde(with = "ScalarSerdeHelper"))]
    pub(crate) x: Scalar,
    pub(crate) ys: Vec<Scalar>,
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = CoconutError;

    fn try_from(bytes: &[u8]) -> Result<SecretKey> {
        if bytes.len() < 32 * 2 + 8 || (bytes.len() - 8) % 32 != 0 {
            return Err(CoconutError::DeserializationInvalidLength {
                actual: bytes.len(),
                modulus_target: bytes.len() - 8,
                target: 32 * 2 + 8,
                modulus: 32,
                object: "secret key".to_string(),
            });
        }

        // this conversion will not fail as we are taking the same length of data
        let x_bytes: [u8; 32] = bytes[..32].try_into().unwrap();
        let ys_len = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
        let actual_ys_len = (bytes.len() - 40) / 32;

        if ys_len as usize != actual_ys_len {
            return Err(CoconutError::Deserialization(format!(
                "Tried to deserialize secret key with inconsistent ys len (expected {}, got {})",
                ys_len, actual_ys_len
            )));
        }

        let x = try_deserialize_scalar(
            &x_bytes,
            CoconutError::Deserialization("Failed to deserialize secret key scalar".to_string()),
        )?;
        let ys = try_deserialize_scalar_vec(
            ys_len,
            &bytes[40..],
            CoconutError::Deserialization("Failed to deserialize secret key scalars".to_string()),
        )?;

        Ok(SecretKey { x, ys })
    }
}

impl SecretKey {
    /// Derive verification key using this secret key.
    pub fn verification_key(&self, params: &Parameters) -> VerificationKey {
        let g2 = params.gen2();
        VerificationKey {
            alpha: g2 * self.x,
            beta: self.ys.iter().map(|y| g2 * y).collect(),
        }
    }

    // x || ys.len() || ys
    pub fn to_bytes(&self) -> Vec<u8> {
        let ys_len = self.ys.len() as u64;
        let mut bytes = Vec::with_capacity(8 + (ys_len + 1) as usize * 32);

        bytes.extend_from_slice(&self.x.to_bytes());
        bytes.extend_from_slice(&ys_len.to_le_bytes());
        for y in self.ys.iter() {
            bytes.extend_from_slice(&y.to_bytes())
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey> {
        SecretKey::try_from(bytes)
    }
}

// TODO: perhaps change points to affine representation
// to make verification slightly more efficient?
#[derive(Debug, PartialEq, Clone)]
pub struct VerificationKey {
    // TODO add gen2 as per the paper or imply it from the fact library is using bls381?
    pub(crate) alpha: G2Projective,
    pub(crate) beta: Vec<G2Projective>,
}

impl TryFrom<&[u8]> for VerificationKey {
    type Error = CoconutError;

    fn try_from(bytes: &[u8]) -> Result<VerificationKey> {
        if bytes.len() < 96 * 2 + 8 || (bytes.len() - 8) % 96 != 0 {
            return Err(CoconutError::DeserializationInvalidLength {
                actual: bytes.len(),
                modulus_target: bytes.len() - 8,
                target: 96 * 2 + 8,
                modulus: 96,
                object: "secret key".to_string(),
            });
        }

        // this conversion will not fail as we are taking the same length of data
        let alpha_bytes: [u8; 96] = bytes[..96].try_into().unwrap();
        let beta_len = u64::from_le_bytes(bytes[96..104].try_into().unwrap());
        let actual_beta_len = (bytes.len() - 104) / 96;

        if beta_len as usize != actual_beta_len {
            return Err(
                CoconutError::Deserialization(
                format!("Tried to deserialize verification key with inconsistent beta len (expected {}, got {})",
                        beta_len, actual_beta_len
                )));
        }

        let alpha = try_deserialize_g2_projective(
            &alpha_bytes,
            CoconutError::Deserialization(
                "Failed to deserialize verification key G2 point (alpha)".to_string(),
            ),
        )?;

        let mut beta = Vec::with_capacity(actual_beta_len);
        for i in 0..actual_beta_len {
            let start = 104 + i * 96;
            let end = start + 96;
            let beta_i_bytes = bytes[start..end].try_into().unwrap();
            let beta_i = try_deserialize_g2_projective(
                &beta_i_bytes,
                CoconutError::Deserialization(
                    "Failed to deserialize verification key G2 point (beta)".to_string(),
                ),
            )?;

            beta.push(beta_i)
        }

        Ok(VerificationKey { alpha, beta })
    }
}

impl<'b> Add<&'b VerificationKey> for VerificationKey {
    type Output = VerificationKey;

    #[inline]
    fn add(self, rhs: &'b VerificationKey) -> VerificationKey {
        // If you're trying to add two keys together that were created
        // for different number of attributes, just panic as it's a
        // nonsense operation.
        assert_eq!(
            self.beta.len(),
            rhs.beta.len(),
            "trying to add verification keys generated for different number of attributes"
        );

        VerificationKey {
            alpha: self.alpha + rhs.alpha,
            beta: self
                .beta
                .iter()
                .zip(rhs.beta.iter())
                .map(|(self_beta, rhs_beta)| self_beta + rhs_beta)
                .collect(),
        }
    }
}

impl<'a> Mul<Scalar> for &'a VerificationKey {
    type Output = VerificationKey;

    #[inline]
    fn mul(self, rhs: Scalar) -> Self::Output {
        VerificationKey {
            alpha: self.alpha * rhs,
            beta: self.beta.iter().map(|b_i| b_i * rhs).collect(),
        }
    }
}

impl<T> Sum<T> for VerificationKey
where
    T: Borrow<VerificationKey>,
{
    #[inline]
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        let mut peekable = iter.peekable();
        let head_attributes = match peekable.peek() {
            Some(head) => head.borrow().beta.len(),
            None => {
                // TODO: this is a really weird edge case. You're trying to sum an EMPTY iterator
                // of VerificationKey. So should it panic here or just return some nonsense value?
                return VerificationKey::identity(0);
            }
        };

        peekable.fold(VerificationKey::identity(head_attributes), |acc, item| {
            acc + item.borrow()
        })
    }
}

impl VerificationKey {
    /// Create a (kinda) identity verification key using specified
    /// number of 'beta' elements
    pub(crate) fn identity(beta_size: usize) -> Self {
        VerificationKey {
            alpha: G2Projective::identity(),
            beta: vec![G2Projective::identity(); beta_size],
        }
    }

    pub fn aggregate(sigs: &[Self], indices: Option<&[SignerIndex]>) -> Result<Self> {
        aggregate_verification_keys(sigs, indices)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let beta_len = self.beta.len() as u64;
        let mut bytes = Vec::with_capacity(8 + (beta_len + 1) as usize * 96);

        bytes.extend_from_slice(&self.alpha.to_affine().to_compressed());
        bytes.extend_from_slice(&beta_len.to_le_bytes());
        for beta in self.beta.iter() {
            bytes.extend_from_slice(&beta.to_affine().to_compressed())
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<VerificationKey> {
        VerificationKey::try_from(bytes)
    }
}

pub struct KeyPair {
    pub secret_key: SecretKey,
    pub verification_key: VerificationKey,

    /// Optional index value specifying polynomial point used during threshold key generation.
    pub index: Option<SignerIndex>,
}

// #[cfg(feature = "serde")]
// impl Serialize for SecretKey {
//     fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         use serde::ser::SerializeStruct;
//         use serde::ser::SerializeTuple;
//
//         let mut state = serializer.serialize_struct("SecretKey", 2)?;
//
//         state.serialize_field("x", &self.x);
//         state.serialize_field("ys", &self.ys);
//
//         // state.serialize_field("x")
//
//         // let mut tup = serializer.serialize_tuple(32)?;
//         // for byte in self.to_bytes().iter() {
//         //     tup.serialize_element(byte)?;
//         // }
//         state.end()
//     }
// }
//
// #[cfg(feature = "serde")]
// impl<'de> Deserialize<'de> for SecretKey {
//     fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         #[derive(Deserialize)]
//         #[serde(field_identifier, rename_all = "lowercase")]
//         enum Field {
//             X,
//             Ys,
//         }
//
//         struct SecretKeyVisitor;
//
//         impl<'de> Visitor<'de> for SecretKeyVisitor {
//             type Value = SecretKey;
//
//             fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
//                 formatter.write_str("a 32-byte ElGamal private key on BLS12_381 curve")
//             }
//
//             fn visit_seq<A>(self, mut seq: A) -> core::result::Result<SecretKey, A::Error>
//             where
//                 A: serde::de::SeqAccess<'de>,
//             {
//                 let mut bytes = [0u8; 32];
//                 // I think this way makes it way more readable than the iterator approach
//                 #[allow(clippy::needless_range_loop)]
//                 for i in 0..32 {
//                     bytes[i] = seq
//                         .next_element()?
//                         .ok_or_else(|| serde::de::Error::invalid_length(i, &"expected 32 bytes"))?;
//                 }
//
//                 SecretKey::from_bytes(&bytes).ok_or_else(|| {
//                     serde::de::Error::custom(&"private key scalar was not canonically encoded")
//                 })
//             }
//         }
//
//         deserializer.deserialize_tuple(32, SecretKeyVisitor)
//     }
// }
//
// #[cfg(feature = "serde")]
// impl Serialize for VerificationKey {
//     fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         use serde::ser::SerializeTuple;
//         let mut tup = serializer.serialize_tuple(48)?;
//         for byte in self.to_bytes().iter() {
//             tup.serialize_element(byte)?;
//         }
//         tup.end()
//     }
// }
//
// #[cfg(feature = "serde")]
// impl<'de> Deserialize<'de> for VerificationKey {
//     fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         struct VerificationKeyVisitor;
//
//         impl<'de> Visitor<'de> for VerificationKeyVisitor {
//             type Value = VerificationKey;
//
//             fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
//                 formatter.write_str("a 48-byte compressed ElGamal public key on BLS12_381 curve")
//             }
//
//             fn visit_seq<A>(self, mut seq: A) -> core::result::Result<VerificationKey, A::Error>
//             where
//                 A: serde::de::SeqAccess<'de>,
//             {
//                 let mut bytes = [0u8; 48];
//                 // I think this way makes it way more readable than the iterator approach
//                 #[allow(clippy::needless_range_loop)]
//                 for i in 0..48 {
//                     bytes[i] = seq
//                         .next_element()?
//                         .ok_or_else(|| serde::de::Error::invalid_length(i, &"expected 48 bytes"))?;
//                 }
//
//                 VerificationKey::from_bytes(&bytes).ok_or_else(|| {
//                     serde::de::Error::custom(
//                         &"public key G1 curve point was not canonically encoded",
//                     )
//                 })
//             }
//         }
//
//         deserializer.deserialize_tuple(48, VerificationKeyVisitor)
//     }
// }

/// Generate a single Coconut keypair ((x, y0, y1...), (g2^x, g2^y0, ...)).
/// It is not suitable for threshold credentials as all subsequent calls to `keygen` generate keys
/// that are independent of each other.
pub fn keygen(params: &Parameters) -> KeyPair {
    let attributes = params.gen_hs().len();

    let x = params.random_scalar();
    let ys = params.n_random_scalars(attributes);

    let secret_key = SecretKey { x, ys };
    let verification_key = secret_key.verification_key(params);

    KeyPair {
        secret_key,
        verification_key,
        index: None,
    }
}

/// Generate a set of n Coconut keypairs [((x, y0, y1...), (g2^x, g2^y0, ...)), ...],
/// such that they support threshold aggregation by `threshold` number of parties.
/// It is expected that this procedure is executed by a Trusted Third Party.
pub fn ttp_keygen(
    params: &mut Parameters,
    threshold: u64,
    num_authorities: u64,
) -> Result<Vec<KeyPair>> {
    if threshold == 0 {
        return Err(CoconutError::Setup(
            "Tried to generate threshold keys with a 0 threshold value".to_string(),
        ));
    }

    if threshold > num_authorities {
        return Err(
            CoconutError::Setup(
            "Tried to generate threshold keys for threshold value being higher than number of the signing authorities".to_string(),
        ));
    }

    let attributes = params.gen_hs().len();

    // generate polynomials
    let v = Polynomial::new_random(params, threshold - 1);
    let ws = (0..attributes)
        .map(|_| Polynomial::new_random(params, threshold - 1))
        .collect::<Vec<_>>();

    // TODO: potentially if we had some known authority identifier we could use that instead
    // of the increasing (1,2,3,...) sequence
    let polynomial_indices = (1..=num_authorities).collect::<Vec<_>>();

    // generate polynomial shares
    let x = polynomial_indices
        .iter()
        .map(|&id| v.evaluate(&Scalar::from(id)));
    let ys = polynomial_indices.iter().map(|&id| {
        ws.iter()
            .map(|w| w.evaluate(&Scalar::from(id)))
            .collect::<Vec<_>>()
    });

    // finally set the keys
    let secret_keys = x.zip(ys).map(|(x, ys)| SecretKey { x, ys });

    let keypairs = secret_keys
        .zip(polynomial_indices.iter())
        .map(|(secret_key, index)| {
            let verification_key = secret_key.verification_key(params);
            KeyPair {
                secret_key,
                verification_key,
                index: Some(*index),
            }
        })
        .collect();

    Ok(keypairs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme::setup::setup;

    #[test]
    fn secret_key_bytes_roundtrip() {
        let mut params1 = setup(1).unwrap();
        let mut params5 = setup(5).unwrap();

        let keypair1 = keygen(&mut params1);
        let keypair5 = keygen(&mut params5);

        let bytes1 = keypair1.secret_key.to_bytes();
        let bytes5 = keypair5.secret_key.to_bytes();

        assert_eq!(SecretKey::from_bytes(&bytes1).unwrap(), keypair1.secret_key);
        assert_eq!(SecretKey::from_bytes(&bytes5).unwrap(), keypair5.secret_key);
    }

    #[test]
    fn verification_key_bytes_roundtrip() {
        let mut params1 = setup(1).unwrap();
        let mut params5 = setup(5).unwrap();

        let keypair1 = &keygen(&mut params1);
        let keypair5 = &keygen(&mut params5);

        let bytes1: Vec<u8> = keypair1.verification_key.to_bytes();
        let bytes5: Vec<u8> = keypair5.verification_key.to_bytes();

        assert_eq!(
            VerificationKey::try_from(bytes1.as_slice()).unwrap(),
            keypair1.verification_key
        );
        assert_eq!(
            VerificationKey::try_from(bytes5.as_slice()).unwrap(),
            keypair5.verification_key
        );
    }
}
