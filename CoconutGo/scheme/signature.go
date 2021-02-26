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
	"gitlab.nymte.ch/nym/coconut/CoconutGo/elgamal"
	"gitlab.nymte.ch/nym/coconut/CoconutGo/utils"
	"math/big"
)

type Signature struct {
	sig1 bls381.G1Jac
	sig2 bls381.G1Jac
}

func (sig *Signature) Equal(other *Signature) bool {
	return utils.G1JacobianEqual(&sig.sig1, &other.sig1) && utils.G1JacobianEqual(&sig.sig2, &other.sig2)
}

type PartialSignature = Signature;
type SignerIndex = uint64

type SignatureShare struct {
	signature Signature
	index SignerIndex
}

func NewSignatureShare(signature Signature, index SignerIndex) SignatureShare {
	return SignatureShare{signature: signature, index: index}
}

func (sigShare *SignatureShare) Signature() *Signature {
	return &sigShare.signature
}

func (sigShare *SignatureShare) Index() SignerIndex {
	return sigShare.index
}

func (sig *Signature) Randomise(params *Parameters) (Signature, error) {
	r, err := params.RandomScalar()
	if err != nil {
		return Signature{}, err
	}

	sig1 := utils.G1ScalarMul(&sig.sig1, &r)
	sig2 := utils.G1ScalarMul(&sig.sig2, &r)

	return Signature{
		sig1: sig1,
		sig2: sig2,
	}, nil
}

type BlindedSignature struct {
	sig1 bls381.G1Jac
	sig2 elgamal.Ciphertext
}

func (blindedSig *BlindedSignature) Unblind(privateKey *elgamal.PrivateKey) Signature {
	return Signature{
		sig1: blindedSig.sig1,
		sig2: privateKey.Decrypt(&blindedSig.sig2),
	}
}

// Lambda
type BlindSignRequest struct {
	// cm
	commitment bls381.G1Jac
	// c
	attributesCiphertexts []*elgamal.Ciphertext
	// pi_s
	piS ProofCmCs
}

func (blindSignRequest *BlindSignRequest) verifyProof(params *Parameters, pubKey *elgamal.PublicKey) bool {
	return blindSignRequest.piS.verify(params, pubKey, &blindSignRequest.commitment, blindSignRequest.attributesCiphertexts)
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

	piS, err := constructProofCmCs(params, publicKey, ephemeralKeys, &commitment, &blinder, privateAttributes, publicAttributes)
	if err != nil {
		return BlindSignRequest{}, err
	}

	return BlindSignRequest{
		commitment:            commitment,
		attributesCiphertexts: ciphertexts,
		piS:                   piS,
	}, nil
}

func BlindSign(
	params *Parameters,
	secretKey *SecretKey,
	publicKey *elgamal.PublicKey,
	blindSignRequest *BlindSignRequest,
	publicAttributes []*Attribute,
) (BlindedSignature, error) {
	numPrivate := len(blindSignRequest.attributesCiphertexts)
	hs := params.Hs()

	if numPrivate+len(publicAttributes) > len(hs) {
		//return Err(Error::new(
		//	ErrorKind::Issuance,
		//	format!("tried to perform blind sign for higher than specified in setup number of attributes (max: {}, requested: {})",
		//	hs.len(),
		//	num_private + public_attributes.len()
		//)));
	}

	if !blindSignRequest.verifyProof(params, publicKey) {
		//	return Err(Error::new(
		//		ErrorKind::Issuance,
		//		"failed to verify the proof of knowledge",
		//));
	}

	cmBytes := utils.G1JacobianToByteSlice(&blindSignRequest.commitment)
	h, err := utils.HashToG1(cmBytes[:])
	if err != nil {
		return BlindedSignature{}, err
	}
	hJac := utils.ToG1Jacobian(&h)

	// sign public attributes

	// in python implementation there are n^2 G1 multiplications, let's do it with a single one instead.
	// i.e. compute h * (pub_m[0] * y[m + 1] + ... + pub_m[n] * y[m + n]) directly (where m is number of PRIVATE attributes)
	// rather than ((h * pub_m[0]) * y[m + 1] , (h * pub_m[1]) * y[m + 2] , ...).sum() separately

	// products contain [pub_m[0] * y[m + 1], ..., pub_m[n] * y[m + n]]
	products := make([]*big.Int, len(publicAttributes))
	for i := 0; i < len(publicAttributes); i++ {
		var product big.Int
		product.Mul(publicAttributes[i], &secretKey.ys[i+numPrivate])
		products[i] = &product
	}

	publicProduct := utils.SumScalars(products)

	// h ^ (pub_m[0] * y[m + 1] + ... + pub_m[n] * y[m + n])
	signedPublic := utils.G1ScalarMul(&hJac, &publicProduct)

	// productsTilde1 contain [c1[0] ^ y[0] , ..., c1[m] ^ y[m]]
	productsTilde1 := make([]bls381.G1Jac, len(blindSignRequest.attributesCiphertexts))

	// productsTilde1 contain [c2[0] ^ y[0] , ..., c2[m] ^ y[m]]
	productsTilde2 := make([]bls381.G1Jac, len(blindSignRequest.attributesCiphertexts))

	for i := 0; i < len(blindSignRequest.attributesCiphertexts); i++ {
		c1 := blindSignRequest.attributesCiphertexts[i].C1()
		c2 := blindSignRequest.attributesCiphertexts[i].C2()

		productsTilde1[i] = utils.G1ScalarMul(c1, &secretKey.ys[i])
		productsTilde2[i] = utils.G1ScalarMul(c2, &secretKey.ys[i])
	}

	// c1[0] ^ y[0] * ... * c1[m] ^ y[m]
	var sigTilde1 bls381.G1Jac
	sigTilde1.Set(&productsTilde1[0])
	for i := 1; i < len(productsTilde1); i++ {
		sigTilde1.AddAssign(&productsTilde1[i])
	}

	sigTilde2 := utils.G1ScalarMul(&hJac, &secretKey.x) // sigTilde2 = h ^ x
	for i := 0; i < len(productsTilde2); i++ {
		sigTilde2.AddAssign(&productsTilde2[i]) // sigTilde2 = h ^ x + c2[0] ^ y[0] + ... c2[m] ^ y[m]
	}

	sigTilde2.AddAssign(&signedPublic) // sigTilde2 = h ^ x + c2[0] ^ y[0] + ... c2[m] ^ y[m] + h ^ (pub_m[0] * y[m + 1] + ... + pub_m[n] * y[m + n])

	return BlindedSignature{
		sig1: hJac,
		sig2: elgamal.CiphertextFromRaw(sigTilde1, sigTilde2),
	}, nil
}

// TODO NAMING: this whole thing
// Theta
type Theta struct {
	// kappa
	kappa bls381.G2Jac
	// nu
	nu bls381.G1Jac
	// sigma
	credential Signature
	// pi_v
	piV ProofKappaNu
}

func (theta *Theta) verifyProof(params *Parameters, verificationKey *VerificationKey) bool {
	return theta.piV.verify(params, verificationKey, &theta.credential, &theta.kappa, &theta.nu)
}

func ProveCredential(
	params *Parameters,
	verificationKey *VerificationKey,
	signature *Signature,
	privateAttributes []*Attribute,
) (Theta, error) {
	if len(privateAttributes) == 0 {
		//	        return Err(Error::new(
		//            ErrorKind::Verification,
		//            "tried to prove a credential with an empty set of private attributes",
		//        ));
	}

	if len(privateAttributes) > len(verificationKey.beta) {
		//return Err(Error::new(
		//	ErrorKind::Verification,
		//	format!("tried to prove a credential for higher than supported by the provided verification key number of attributes (max: {}, requested: {})",
		//	verification_key.beta.len(),
		//	private_attributes.len()
		//)));
	}

	// TODO: should randomization be part of this procedure or should
	// it be up to the user?
	signaturePrime, err := signature.Randomise(params)
	if err != nil {
		return Theta{}, err
	}

	blindingFactor, err := params.RandomScalar()
	if err != nil {
		return Theta{}, err
	}

	kappa := utils.G2ScalarMul(params.Gen2(), &blindingFactor) // kappa = g2 ^ r
	kappa.AddAssign(&verificationKey.alpha)                    // kappa = g2 ^ r * alpha
	for i := 0; i < len(privateAttributes); i++ {
		tmp := utils.G2ScalarMul(verificationKey.beta[i], privateAttributes[i]) // tmp = beta[i] ^ priv[i]
		kappa.AddAssign(&tmp)                                                   // kappa = g2 ^ r * alpha * beta[0] ^ priv[0] * ... * beta[m] ^ priv[m]
	}

	nu := utils.G1ScalarMul(&signaturePrime.sig1, &blindingFactor) // nu = h^r

	piV, err := constructProofKappaNu(params, verificationKey, &signaturePrime, privateAttributes, &blindingFactor)
	if err != nil {
		return Theta{}, err
	}

	return Theta{
		kappa:      kappa,
		nu:         nu,
		credential: signaturePrime,
		piV:        piV,
	}, nil
}

/// Checks whether e(P, Q) * e(-R, S) == id
func checkBillinearPairing(p *bls381.G1Jac, q bls381.G2Affine, r *bls381.G1Jac, s bls381.G2Affine) bool {
	var rNeg bls381.G1Affine
	rNeg.FromJacobian(r)
	rNeg.Neg(&rNeg)

	pairCheck, err := bls381.PairingCheck(
		[]bls381.G1Affine{utils.ToG1Affine(p), rNeg},
		[]bls381.G2Affine{q, s},
	)

	if err != nil {
		return false
	}

	return pairCheck
}

func VerifyCredential(
	params *Parameters,
	verificationKey *VerificationKey,
	theta *Theta,
	publicAttributes []*Attribute,
) bool {
	numPrivate := len(theta.piV.responseAttributes)

	if len(publicAttributes)+numPrivate > len(verificationKey.beta) {
		return false
	}

	if !theta.verifyProof(params, verificationKey) {
		return false
	}

	var kappa bls381.G2Jac
	kappa.Set(&theta.kappa)

	if len(publicAttributes) > 0 {
		for i := 0; i < len(publicAttributes); i++ {
			tmp := utils.G2ScalarMul(verificationKey.beta[i+numPrivate], publicAttributes[i]) // tmp = beta[m + i] ^ pubAttr[i]
			kappa.AddAssign(&tmp)
		}
	}

	var r bls381.G1Jac
	r.Set(&theta.credential.sig2)
	r.AddAssign(&theta.nu)

	return checkBillinearPairing(&theta.credential.sig1, utils.ToG2Affine(&kappa), &r, *params.Gen2Affine()) && !theta.credential.sig1.Z.IsZero()
}

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

	var kappa bls381.G2Jac
	kappa.Set(verificationKey.Alpha()) // kappa = X
	for i := 0; i < len(publicAttributes); i++ {
		tmp := utils.G2ScalarMul(verificationKey.beta[i], publicAttributes[i]) // (ai * Yi)
		kappa.AddAssign(&tmp)                                                  // kappa = X + (a1 * Y1) + ...
	}

	return checkBillinearPairing(&sig.sig1, utils.ToG2Affine(&kappa), &sig.sig2, *params.Gen2Affine()) && !sig.sig1.Z.IsZero()
}
