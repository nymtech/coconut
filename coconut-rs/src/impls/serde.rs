use crate::elgamal::PrivateKey;
use crate::scheme::SecretKey;
use crate::{Base58, BlindSignRequest, BlindedSignature, PublicKey, Signature, VerificationKey};
use serde::de::Unexpected;
use serde::{de::Error, de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

macro_rules! impl_serde {
    ($struct:ident) => {
        gensym::gensym! { _impl_serde!{ $struct } }
    };
}

macro_rules! _impl_serde {
    ($gensym:ident, $struct:ident) => {
        pub struct $gensym {}

        impl Serialize for $struct {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_bs58())
            }
        }

        impl<'de> Visitor<'de> for $gensym {
            type Value = $struct;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "A base58 encoded struct")
            }

            fn visit_str<E: Error>(self, s: &str) -> Result<Self::Value, E> {
                match $struct::try_from_bs58(s) {
                    Ok(x) => Ok(x),
                    Err(_) => Err(Error::invalid_value(Unexpected::Str(s), &self)),
                }
            }
        }

        impl<'de> Deserialize<'de> for $struct {
            fn deserialize<D>(deserializer: D) -> Result<$struct, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer.deserialize_str($gensym {})
            }
        }
    };
}

impl_serde!(SecretKey);
impl_serde!(VerificationKey);
impl_serde!(PublicKey);
impl_serde!(PrivateKey);
impl_serde!(BlindSignRequest);
impl_serde!(BlindedSignature);
impl_serde!(Signature);
