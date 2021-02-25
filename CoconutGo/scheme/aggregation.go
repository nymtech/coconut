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

package coconut

import (
	"github.com/consensys/gurvy/bls381"
	"gitlab.nymte.ch/nym/coconut/CoconutGo/polynomial"
	"gitlab.nymte.ch/nym/coconut/CoconutGo/utils"
)

func checkUniqueIndices(indices []SignerIndex) bool {
	seen := make(map[SignerIndex]bool)
	for i := 0; i < len(indices); i++ {
		if _, ok := seen[indices[i]]; ok {
			return false
		}
		seen[indices[i]] = true
	}
	return true
}


func performVerificationKeyLagrangianInterpolationAtOrigin(points []uint64, values []*VerificationKey)  (VerificationKey, error) {
	if len(points) == 0 || len(values) == 0 {
		//	return Err(Error::new(
		//		ErrorKind::Interpolation,
		//		"tried to perform lagrangian interpolation for an empty set of coordinates",
		//));
	}

	if len(points) != len(values) {
		//	return Err(Error::new(
		//		ErrorKind::Interpolation,
		//		"tried to perform lagrangian interpolation for an incomplete set of coordinates",
		//));
	}

	coefficients := polynomial.GenerateLagrangianCoefficientsAtOrigin(points)

	result := VerificationKey{
		alpha: bls381.G2Jac{},
		beta:  make([]*bls381.G2Jac, len(values[0].beta)),
	}

	// set result to be the same as the first key provided multiplied by the first coefficient
	result.alpha = utils.G2ScalarMul(&values[0].alpha, coefficients[0])
	for i := 0; i < len(values[0].beta); i++ {
		betai := utils.G2ScalarMul(values[0].beta[i], coefficients[0])
		result.beta[i] = &betai
	}

	// continue adding key * coefficient to the result
	for i := 1; i < len(values); i++ {
		tmpAlpha := utils.G2ScalarMul(values[i].Alpha(), coefficients[i])
		result.alpha.AddAssign(&tmpAlpha)
		for j := 0; j < len(values[0].beta); j++ {
			tmpBetaJ := utils.G2ScalarMul(values[i].beta[j], coefficients[i])
			result.beta[j].AddAssign(&tmpBetaJ)
		}
	}

	return result, nil
}

//func SumG2JacobianPoints(points []*bls381.G2Jac) bls381.G2Jac {
//	var sum bls381.G2Jac
//	if len(points) == 0 {
//		return sum
//	}
//	sum.Set(points[0])
//	for i := 1; i < len(points); i++ {
//		sum.AddAssign(points[i])
//	}
//	return sum
//}


func checkSameKeySize(keys []*VerificationKey) bool {
	len0 := len(keys[0].beta)
	for i := 1; i < len(keys); i++ {
		if len(keys[i].beta) != len0 {
			return false
		}
	}

	return false
}

// no generics : (
func AggregateVerificationKeys(keys []*VerificationKey, indices []SignerIndex) (VerificationKey, error) {
	if len(keys) == 0 {
	//	return Err(Error::new(
	//		ErrorKind::Aggregation,
	//		"tried to perform aggregation of an empty set of values",
	//));
	}

	if !checkSameKeySize(keys) {
	//	return Err(Error::new(
	//		ErrorKind::Aggregation,
	//		"tried to aggregate verification keys of different sizes",
	//));
	}
	if len(indices) > 0 {
		if !checkUniqueIndices(indices) {
		//	return Err(Error::new(
		//		ErrorKind::Aggregation,
		//		"tried to perform aggregation on a set of non-unique indices",
		//));
		}
		return performVerificationKeyLagrangianInterpolationAtOrigin(indices, keys)
	} else {
		aggregate := VerificationKey{
			alpha: bls381.G2Jac{},
			beta:  make([]*bls381.G2Jac, len(keys[0].beta)),
		}
		// set aggregate to be the same as the first key provided
		aggregate.alpha.Set(keys[0].Alpha())
		for i := 0; i  < len(keys[0].beta); i++ {
			aggregate.beta[i].Set(keys[0].beta[i])
		}

		for i := 1; i < len(keys); i++ {
			aggregate.alpha.AddAssign(keys[i].Alpha())
			for j := 0; i < len(keys[0].beta); j++ {
				aggregate.beta[j].AddAssign(keys[i].beta[j])
			}
		}

		return aggregate, nil
	}
}



func performSignatureLagrangianInterpolationAtOrigin(points []uint64, values []*Signature)  (Signature, error) {
	if len(points) == 0 || len(values) == 0 {
		//	return Err(Error::new(
		//		ErrorKind::Interpolation,
		//		"tried to perform lagrangian interpolation for an empty set of coordinates",
		//));
	}

	if len(points) != len(values) {
		//	return Err(Error::new(
		//		ErrorKind::Interpolation,
		//		"tried to perform lagrangian interpolation for an incomplete set of coordinates",
		//));
	}

	coefficients := polynomial.GenerateLagrangianCoefficientsAtOrigin(points)

	// set result to be the same as the first signature provided multiplied by the first coefficient
	var sig1 bls381.G1Jac
	sig1.Set(&values[0].sig1)
	sig2 := utils.G1ScalarMul(&values[0].sig2, coefficients[0])
	result := Signature{
		sig1: sig1,
		sig2: sig2,
	}

	for i := 1; i < len(values); i++{
		tmpSig2 := utils.G1ScalarMul(&values[i].sig2, coefficients[i])
		result.sig2.AddAssign(&tmpSig2)
	}

	return result, nil
}


func AggregateSignatures(sigs []*PartialSignature, indices []SignerIndex) (Signature, error) {
	if len(sigs) == 0 {
	//Error::new(
	//		ErrorKind::Aggregation,
	//		"tried to aggregate empty set of signatures",
	//)
	}

	if len(indices) > 0 {
		if !checkUniqueIndices(indices) {
			//	return Err(Error::new(
			//		ErrorKind::Aggregation,
			//		"tried to perform aggregation on a set of non-unique indices",
			//));
		}
		return performSignatureLagrangianInterpolationAtOrigin(indices, sigs)
	} else {
		// set aggregate to be the same as the first signature provided
		aggregate := Signature{
			sig1: sigs[0].sig1,
			sig2: sigs[0].sig2,
		}

		for i := 1; i < len(sigs); i++ {
			aggregate.sig2.AddAssign(&sigs[i].sig2)
		}

		return aggregate, nil
	}

}

func AggregateSignatureShares(shares []*SignatureShare) (Signature, error) {

	return Signature{}, nil

}

/*

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
    use crate::scheme::keygen::ttp_keygen;
    use crate::scheme::setup::Parameters;
    use crate::scheme::signature::{sign, verify};
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

 */