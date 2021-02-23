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
	"gitlab.nymte.ch/nym/coconut/CoconutGo/elgamal"
	"gitlab.nymte.ch/nym/coconut/CoconutGo/proofs"
	"gitlab.nymte.ch/nym/coconut/CoconutGo/utils"
	"math/big"
)

type Signature struct {
	sig1 bls381.G1Jac
	sig2 bls381.G1Jac
}

// Lambda
type BlindSignRequest struct {
	// cm
	commitment bls381.G1Jac
	// c
	attributesCiphertexts []*elgamal.Ciphertext
	// pi_s
	piS proofs.ProofCmCs
}

func (blindSignRequest *BlindSignRequest) verifyProof(params *Parameters, pubKey *elgamal.PublicKey) bool {
	return blindSignRequest.piS.Verify(params, pubKey, &blindSignRequest.commitment, blindSignRequest.attributesCiphertexts)
}

func PrepareBlindSign(
	params *Parameters,
	publicKey *elgamal.PublicKey,
	privateAttributes []*Attribute,
	publicAttributes []*Attribute,
) (BlindSignRequest, error) {
	if len(privateAttributes) == 0 {
		//	return Err(Error::new(
		//		ErrorKind::Issuance,
		//		"tried to prepare blind sign request for an empty set of private attributes",
		//));
	}

	hs := params.Hs()

	if len(privateAttributes)+len(publicAttributes) > len(hs) {
		//return Err(Error::new(
		//	ErrorKind::Issuance,
		//	format!("tried to prepare blind sign request for higher than specified in setup number of attributes (max: {}, requested: {})",
		//	hs.len(),
		//	private_attributes.len() + public_attributes.len()
		//)));
	}

	// prepare commitment
	// Produces h0 ^ m0 * h1^m1 * .... * hn^mn
	blinder, err := params.RandomScalar()
	if err != nil {
		return BlindSignRequest{}, err
	}

	commitment := utils.G1ScalarMul(params.Gen1(), &blinder) // cm = g1^r
	for i, attr := range append(privateAttributes, publicAttributes...) {
		hsIJac := utils.ToG1Jacobian(hs[i])
		tmp := utils.G1ScalarMul(&hsIJac, attr) // tmp = (h[i] ^ attr[i])
		commitment.AddAssign(&tmp)              // cm = g1^r * h0 ^ m0 * h1^m1 * .... * hn^mn
	}

	cmBytes := utils.G1JacobianToByteSlice(&commitment)
	h, err := utils.HashToG1(cmBytes[:])
	if err != nil {
		return BlindSignRequest{}, err
	}
	hJac := utils.ToG1Jacobian(&h)

	ciphertexts := make([]*elgamal.Ciphertext, len(privateAttributes))
	ephemeralKeys := make([]*elgamal.EphemeralKey, len(privateAttributes))

	for i := range privateAttributes {
		ciphertext, ephemeralKey, err := publicKey.Encrypt(params, &hJac, privateAttributes[i])
		if err != nil {
			return BlindSignRequest{}, err
		}
		ciphertexts[i] = &ciphertext
		ephemeralKeys[i] = &ephemeralKey
	}

	piS, err := proofs.ConstructProofCmCs(params, publicKey, ephemeralKeys, &commitment, &blinder, privateAttributes, publicAttributes)
	if err != nil {
		return BlindSignRequest{}, err
	}

	return BlindSignRequest{
		commitment:            commitment,
		attributesCiphertexts: ciphertexts,
		piS:                   piS,
	}, nil
}

/*

/// Builds cryptographic material required for blind sign.
pub fn prepare_blind_sign<R: RngCore + CryptoRng>(
    params: &mut Parameters<R>,
    pub_key: &elgamal::PublicKey,
    private_attributes: &[Attribute],
    public_attributes: &[Attribute],
) -> Result<BlindSignRequest> {

    // prepare commitment
    // Produces h0 ^ m0 * h1^m1 * .... * hn^mn
    let attr_cm = private_attributes
        .iter()
        .chain(public_attributes.iter())
        .zip(hs)
        .map(|(&m, h)| h * m)
        .sum::<G1Projective>();
    let blinder = params.random_scalar();
    // g1^r * h0 ^ m0 * h1^m1 * .... * hn^mn
    let commitment = params.gen1() * blinder + attr_cm;

    // build ElGamal encryption
    let commitment_hash = hash_g1(commitment.to_bytes());
    let (attributes_ciphertexts, ephemeral_keys): (Vec<_>, Vec<_>) = private_attributes
        .iter()
        .map(|m| pub_key.encrypt(params, &commitment_hash, m))
        .unzip();

    let pi_s = ProofCmCs::construct(
        params,
        pub_key,
        &ephemeral_keys,
        &commitment,
        &blinder,
        private_attributes,
        public_attributes,
    );

    Ok(BlindSignRequest {
        commitment,
        attributes_ciphertexts,
        pi_s,
    })
}

pub fn blind_sign<R: RngCore + CryptoRng>(
    params: &mut Parameters<R>,
    secret_key: &SecretKey,
    pub_key: &elgamal::PublicKey,
    blind_sign_request: &BlindSignRequest,
    public_attributes: &[Attribute],
) -> Result<BlindedSignature> {
    let num_private = blind_sign_request.attributes_ciphertexts.len();
    let hs = params.gen_hs();

    if num_private + public_attributes.len() > hs.len() {
        return Err(Error::new(
            ErrorKind::Issuance,
            format!("tried to perform blind sign for higher than specified in setup number of attributes (max: {}, requested: {})",
                    hs.len(),
                    num_private + public_attributes.len()
            )));
    }

    if !blind_sign_request.verify_proof(params, pub_key) {
        return Err(Error::new(
            ErrorKind::Issuance,
            "failed to verify the proof of knowledge",
        ));
    }

    let h = hash_g1(blind_sign_request.commitment.to_bytes());

    // in python implementation there are n^2 G1 multiplications, let's do it with a single one instead.
    // i.e. compute h * (pub_m[0] * y[m + 1] + ... + pub_m[n] * y[n]) directly (where m is number of PRIVATE attributes)
    // rather than ((h * pub_m[0]) * y[m + 1] , (h * pub_m[1]) * y[m + 2] , ...).sum() separately
    let signed_public = h * public_attributes
        .iter()
        .zip(secret_key.ys.iter().skip(num_private))
        .map(|(attr, yi)| attr * yi)
        .sum::<Scalar>();

    // y[0] * c1[0] + ... + y[n] * c1[n]
    let sig_1 = blind_sign_request
        .attributes_ciphertexts
        .iter()
        .map(|ciphertext| ciphertext.c1())
        .zip(secret_key.ys.iter())
        .map(|(c1, yi)| c1 * yi)
        .sum();

    // x * h + y[0] * c2[0] + ... y[m] * c2[m] + h * (pub_m[0] * y[m + 1] + ... + pub_m[n] * y[n])
    let sig_2 = blind_sign_request
        .attributes_ciphertexts
        .iter()
        .map(|ciphertext| ciphertext.c2())
        .zip(secret_key.ys.iter())
        .map(|(c2, yi)| c2 * yi)
        .chain(std::iter::once(h * secret_key.x))
        .chain(std::iter::once(signed_public))
        .sum();

    Ok(BlindedSignature(h, (sig_1, sig_2).into()))
}

*/

func Sign(params *Parameters, secretKey *SecretKey, publicAttributes []*Attribute) (Signature, error) {
	if len(publicAttributes) > len(*secretKey.Ys()) {
		// TODO: RETURN ERROR HERE!
	}

	// TODO: why in the python implementation this hash onto the curve is present
	// while it's not used in the paper? the paper uses random exponent instead.
	// (the python implementation hashes string representation of all attributes onto the curve,
	// but I think the same can be achieved by just summing the attributes thus avoiding the unnecessary
	// transformation. If I'm wrong, please correct me.)
	attributesSum := utils.SumScalars(publicAttributes)
	baseRawJac := utils.G1ScalarMul(params.Gen1(), &attributesSum)
	baseRawAff := utils.ToG1Affine(&baseRawJac)
	baseRawBytesCompressed := baseRawAff.Bytes()
	h, err := utils.HashToG1(baseRawBytesCompressed[:])
	if err != nil {
		return Signature{}, err
	}

	var K big.Int
	K.Set(&secretKey.x) // K = x
	for i := 0; i < len(publicAttributes); i++ {
		var tmp big.Int

		// TODO REDUCE ORDER p?

		tmp.Mul(&secretKey.ys[i], publicAttributes[i]) // (ai * yi)
		K.Add(&K, &tmp)                                // K = x + (a0 * y0) + ...
	}

	// convert h from jacobian to affine (TODO: figure out which representation is actually more efficient)
	var hJac bls381.G1Jac
	hJac.FromAffine(&h)

	sig2 := utils.G1ScalarMul(&hJac, &K)

	return Signature{
		sig1: hJac,
		sig2: sig2,
	}, nil

}

func Verify(params *Parameters, verificationKey *VerificationKey, publicAttributes []*Attribute, sig *Signature) bool {
	if len(publicAttributes) > len(verificationKey.beta) {
		return false
	}

	var K bls381.G2Jac
	K.Set(verificationKey.Alpha()) // K = X
	for i := 0; i < len(publicAttributes); i++ {
		tmp := utils.G2ScalarMul(&verificationKey.beta[i], publicAttributes[i]) // (ai * Yi)
		K.AddAssign(&tmp)                                                       // K = X + (a1 * Y1) + ...
	}

	var sig2Neg bls381.G1Affine
	sig2Neg.FromJacobian(&sig.sig2)
	sig2Neg.Neg(&sig2Neg)

	pairCheck, err := bls381.PairingCheck(
		[]bls381.G1Affine{utils.ToG1Affine(&sig.sig1), sig2Neg},
		[]bls381.G2Affine{utils.ToG2Affine(&K), *params.Gen2Affine()},
	)

	if err != nil {
		return false
	}

	return !sig.sig1.Z.IsZero() && pairCheck
}
