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

use std::fmt::{self, Display, Formatter};

/// A `Result` alias where the `Err` case is `coconut_rs::Error`.
pub type Result<T> = std::result::Result<T, Error>;

/// Possible Coconut errors
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    error: Box<dyn std::error::Error + Send + Sync>,
}

impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ErrorKind {
    /// Error originating from the 'setup' phase of the protocol.
    Setup,

    /// Error originating from the 'keygen' phase of the protocol.
    Keygen,

    /// Error originating from the 'issuance' phase of the protocol.
    Issuance,

    /// Error originating from the 'interpolation' phase of the protocol.
    Interpolation,

    /// Error originating from the 'aggregation' phase of the protocol.
    Aggregation,

    /// Error originating from the 'verification' phase of the protocol.
    Verification,

    /// Error originating from deserialization of elements.
    Deserialization,
}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::Setup => write!(f, "encountered error during setup"),
            ErrorKind::Keygen => write!(f, "encountered error during keygen"),
            ErrorKind::Issuance => write!(f, "encountered error during signature issuance"),
            ErrorKind::Interpolation => {
                write!(f, "encountered error during lagrange interpolation")
            }
            ErrorKind::Aggregation => write!(f, "encountered error during aggregation"),
            ErrorKind::Verification => write!(f, "encountered error during verification"),
            ErrorKind::Deserialization => write!(f, "encountered error during deserialization"),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} - {}", self.kind, self.error)
    }
}

impl Error {
    pub fn new<E>(kind: ErrorKind, error: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Error {
            kind,
            error: error.into(),
        }
    }
}
