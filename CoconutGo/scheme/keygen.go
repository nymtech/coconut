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
	. "gitlab.nymte.ch/nym/coconut/CoconutGo"
	"gitlab.nymte.ch/nym/coconut/CoconutGo/utils"
	"math/big"
)

// SecretKey represents secret key of a Coconut signing authority.
type SecretKey struct {
	// TODO: big.Int or Fp.Element?
	x  big.Int
	ys []big.Int
}

func (sk *SecretKey) X() *big.Int {
	return &sk.x
}

func (sk *SecretKey) Ys() *[]big.Int {
	return &sk.ys
}

// Derive verification key using this secret key.
func (sk *SecretKey) VerificationKey(params *Parameters) VerificationKey {
	g2 := params.Gen2()

	alpha := utils.G2ScalarMul(g2, &sk.x)
	beta := make([]*bls381.G2Jac, len(sk.ys))
	for i, y := range sk.ys {
		betai := utils.G2ScalarMul(g2, &y)
		beta[i] = &betai
	}

	return VerificationKey{
		alpha: alpha,
		beta:  beta,
	}
}

// VerificationKey represents verification key of a Coconut signing authority.
type VerificationKey struct {
	alpha bls381.G2Jac
	beta  []*bls381.G2Jac
}

// Alpha returns appropriate part of the the verification key
func (vk *VerificationKey) Alpha() *bls381.G2Jac {
	return &vk.alpha
}

// Beta returns appropriate part of the the verification key
func (vk *VerificationKey) Beta() []*bls381.G2Jac {
	return vk.beta
}

type KeyPair struct {
	secretKey       SecretKey
	verificationKey VerificationKey

	// Optional index value specifying polynomial point used during threshold key generation.
	index *uint64
}

// Generate a single Coconut keypair ((x, y0, y1...), (g2^x, g2^y0, ...)).
// It is not suitable for threshold credentials as all subsequent calls to `keygen` generate keys
// that are independent of each other.
func Keygen(params *Parameters) (KeyPair, error) {
	attributes := len(params.Hs())
	x, err := params.RandomScalar()
	if err != nil {
		return KeyPair{}, err
	}
	ys := make([]big.Int, attributes)
	for i := range ys {
		ys[i], err = params.RandomScalar()
		if err != nil {
			return KeyPair{}, err
		}
	}

	secretKey := SecretKey{
		x:  x,
		ys: ys,
	}

	return KeyPair{
		secretKey:       secretKey,
		verificationKey: secretKey.VerificationKey(params),
	}, nil
}

/*

// Generate a single Coconut keypair ((x, y0, y1...), (g2^x, g2^y0, ...)).
// It is not suitable for threshold credentials as all subsequent calls to `keygen` generate keys
// that are independent of each other.
pub fn keygen<R: RngCore + CryptoRng>(params: &mut Parameters<R>) -> KeyPair {
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
pub fn ttp_keygen<R: RngCore + CryptoRng>(
    params: &mut Parameters<R>,
    threshold: u64,
    num_authorities: u64,
) -> Result<Vec<KeyPair>> {
    if threshold == 0 {
        return Err(Error::new(
            ErrorKind::Setup,
            "tried to generate threshold keys with a 0 threshold value",
        ));
    }

    if threshold > num_authorities {
        return Err(Error::new(
            ErrorKind::Setup,
            "tried to generate threshold keys for threshold value being higher than number of the signingn authorities",
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

*/
