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
use crate::scheme::signature::{PartialSignature, Signature};
use crate::scheme::SignerIndex;
use crate::utils::perform_lagrangian_interpolation_at_origin;
use bls12_381::Scalar;
use core::iter::Sum;
use core::ops::Mul;
use itertools::Itertools;

pub(crate) trait Aggregatable: Sized {
    fn aggregate(aggretable: &[Self], indices: Option<&[SignerIndex]>) -> Result<Self>;

    fn check_unique_indices(indices: &[SignerIndex]) -> bool {
        // if aggregation is a threshold one, all indices should be unique
        indices.iter().unique_by(|&index| index).count() == indices.len()
    }
}

// includes `VerificationKey`
impl<T> Aggregatable for T
where
    T: Sum,
    for<'a> T: Sum<&'a T>,
    for<'a> &'a T: Mul<Scalar, Output = T>,
{
    fn aggregate(aggretable: &[T], indices: Option<&[u64]>) -> Result<T> {
        if aggretable.is_empty() {
            return Err(Error::new(
                ErrorKind::Aggregation,
                "tried to perform aggregation of an empty set of values",
            ));
        }

        if let Some(indices) = indices {
            if !Self::check_unique_indices(indices) {
                return Err(Error::new(
                    ErrorKind::Aggregation,
                    "tried to perform aggregation on a set of non-unique indices",
                ));
            }
            perform_lagrangian_interpolation_at_origin(indices, aggretable)
        } else {
            // non-threshold
            Ok(aggretable.iter().sum())
        }
    }
}

impl Aggregatable for PartialSignature {
    fn aggregate(sigs: &[PartialSignature], indices: Option<&[u64]>) -> Result<Signature> {
        let h = sigs
            .get(0)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Aggregation,
                    "tried to aggregate empty set of signatures",
                )
            })?
            .sig1();

        // TODO: is it possible to avoid this allocation?
        let sigmas = sigs.iter().map(|sig| *sig.sig2()).collect::<Vec<_>>();
        let aggr_sigma = Aggregatable::aggregate(&sigmas, indices)?;

        Ok(Signature(*h, aggr_sigma))
    }
}
