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
// for time being let's define it as an enum. If we find it lacking, we could go with sphinx/std::io
// approach and create a struct with a representation

#[derive(Debug, Clone)]
pub enum Error {}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            _ => Ok(())
        }
    }
}

