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
use crate::scheme::{PartialSignature, Signature, SignatureShare, SignerIndex, VerificationKey};
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

/// Ensures all provided verification keys were generated to verify the same number of attributes.
fn check_same_key_size(keys: &[VerificationKey]) -> bool {
    keys.iter().map(|vk| vk.beta.len()).all_equal()
}

pub fn aggregate_verification_keys(
    keys: &[VerificationKey],
    indices: Option<&[SignerIndex]>,
) -> Result<VerificationKey> {
    if !check_same_key_size(keys) {
        return Err(Error::new(
            ErrorKind::Aggregation,
            "tried to aggregate verification keys of different sizes",
        ));
    }
    Aggregatable::aggregate(keys, indices)
}

pub fn aggregate_signatures(
    sigs: &[PartialSignature],
    indices: Option<&[SignerIndex]>,
) -> Result<Signature> {
    Aggregatable::aggregate(sigs, indices)
}

pub fn aggregate_signature_shares(shares: &[SignatureShare]) -> Result<Signature> {
    let (signatures, indices): (Vec<_>, Vec<_>) = shares
        .iter()
        .map(|share| (*share.signature(), share.index()))
        .unzip();

    aggregate_signatures(&signatures, Some(&indices))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme::issuance::sign;
    use crate::scheme::keygen::ttp_keygen;
    use crate::scheme::setup::Parameters;
    use crate::scheme::verification::verify;
    use bls12_381::G1Projective;
    use group::Group;
    use rand_core::OsRng;

    #[test]
    fn key_aggregation_works_for_any_subset_of_keys() {
        let rng = OsRng;

        let mut params = Parameters::new(rng, 2).unwrap();
        let keypairs = ttp_keygen(&mut params, 3, 5).unwrap();

        let vks = keypairs
            .into_iter()
            .map(|keypair| keypair.verification_key)
            .collect::<Vec<_>>();

        let aggr_vk1 = aggregate_verification_keys(&vks[..3], Some(&[1, 2, 3])).unwrap();
        let aggr_vk2 = aggregate_verification_keys(&vks[2..], Some(&[3, 4, 5])).unwrap();

        assert_eq!(aggr_vk1, aggr_vk2);

        // TODO: should those two actually work or not?
        // aggregating threshold+1
        let aggr_more = aggregate_verification_keys(&vks[1..], Some(&[2, 3, 4, 5])).unwrap();
        assert_eq!(aggr_vk1, aggr_more);

        // aggregating all
        let aggr_all = aggregate_verification_keys(&vks, Some(&[1, 2, 3, 4, 5])).unwrap();
        assert_eq!(aggr_all, aggr_vk1);

        // not taking enough points (threshold was 3)
        let aggr_not_enough = aggregate_verification_keys(&vks[..2], Some(&[1, 2])).unwrap();
        assert_ne!(aggr_not_enough, aggr_vk1);

        // taking wrong index
        let aggr_bad = aggregate_verification_keys(&vks[2..], Some(&[42, 123, 100])).unwrap();
        assert_ne!(aggr_vk1, aggr_bad);
    }

    #[test]
    fn key_aggregation_doesnt_work_for_empty_set_of_keys() {
        let keys: Vec<VerificationKey> = vec![];
        assert!(aggregate_verification_keys(&keys, None).is_err());
    }

    #[test]
    fn key_aggregation_doesnt_work_if_indices_have_invalid_length() {
        let keys = vec![VerificationKey::identity(3)];

        assert!(aggregate_verification_keys(&keys, Some(&[])).is_err());
        assert!(aggregate_verification_keys(&keys, Some(&[1, 2])).is_err());
    }

    #[test]
    fn key_aggregation_doesnt_work_for_non_unique_indices() {
        let keys = vec![VerificationKey::identity(3), VerificationKey::identity(3)];

        assert!(aggregate_verification_keys(&keys, Some(&[1, 1])).is_err());
    }

    #[test]
    fn key_aggregation_doesnt_work_for_keys_of_different_size() {
        let keys = vec![VerificationKey::identity(3), VerificationKey::identity(1)];

        assert!(aggregate_verification_keys(&keys, None).is_err())
    }

    #[test]
    fn signature_aggregation_works_for_any_subset_of_signatures() {
        let rng = OsRng;

        let mut params = Parameters::new(rng, 2).unwrap();
        let attributes = params.n_random_scalars(2);

        let keypairs = ttp_keygen(&mut params, 3, 5).unwrap();

        let (sks, vks): (Vec<_>, Vec<_>) = keypairs
            .into_iter()
            .map(|keypair| (keypair.secret_key, keypair.verification_key))
            .unzip();

        let sigs = sks
            .iter()
            .map(|sk| sign(&mut params, sk, &attributes).unwrap())
            .collect::<Vec<_>>();

        let aggr_sig1 = aggregate_signatures(&sigs[..3], Some(&[1, 2, 3])).unwrap();
        let aggr_sig2 = aggregate_signatures(&sigs[2..], Some(&[3, 4, 5])).unwrap();
        assert_eq!(aggr_sig1, aggr_sig2);

        // verify credential for good measure
        let aggr_vk = aggregate_verification_keys(&vks[..3], Some(&[1, 2, 3])).unwrap();
        assert!(verify(&params, &aggr_vk, &attributes, &aggr_sig1));

        // TODO: should those two actually work or not?
        // aggregating threshold+1
        let aggr_more = aggregate_signatures(&sigs[1..], Some(&[2, 3, 4, 5])).unwrap();
        assert_eq!(aggr_sig1, aggr_more);

        // aggregating all
        let aggr_all = aggregate_signatures(&sigs, Some(&[1, 2, 3, 4, 5])).unwrap();
        assert_eq!(aggr_all, aggr_sig1);

        // not taking enough points (threshold was 3)
        let aggr_not_enough = aggregate_signatures(&sigs[..2], Some(&[1, 2])).unwrap();
        assert_ne!(aggr_not_enough, aggr_sig1);

        // taking wrong index
        let aggr_bad = aggregate_signatures(&sigs[2..], Some(&[42, 123, 100])).unwrap();
        assert_ne!(aggr_sig1, aggr_bad);
    }

    fn random_signature() -> Signature {
        let mut rng = OsRng;
        Signature(
            G1Projective::random(&mut rng),
            G1Projective::random(&mut rng),
        )
    }

    #[test]
    fn signature_aggregation_doesnt_work_for_empty_set_of_signatures() {
        let signatures: Vec<Signature> = vec![];
        assert!(aggregate_signatures(&signatures, None).is_err());
    }

    #[test]
    fn signature_aggregation_doesnt_work_if_indices_have_invalid_length() {
        let signatures = vec![random_signature()];

        assert!(aggregate_signatures(&signatures, Some(&[])).is_err());
        assert!(aggregate_signatures(&signatures, Some(&[1, 2])).is_err());
    }

    #[test]
    fn signature_aggregation_doesnt_work_for_non_unique_indices() {
        let signatures = vec![random_signature(), random_signature()];

        assert!(aggregate_signatures(&signatures, Some(&[1, 1])).is_err());
    }

    // TODO: test for aggregating non-threshold keys
}
