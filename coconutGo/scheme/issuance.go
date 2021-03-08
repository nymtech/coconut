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
	"encoding/binary"
	"errors"
	"github.com/consensys/gurvy/bls381"
	"gitlab.nymte.ch/nym/coconut/coconutGo"
	"gitlab.nymte.ch/nym/coconut/coconutGo/elgamal"
	"gitlab.nymte.ch/nym/coconut/coconutGo/utils"
	"math/big"
)

// Lambda
type BlindSignRequest struct {
	// cm
	commitment bls381.G1Jac
	// c
	attributesCiphertexts []*elgamal.Ciphertext
	// pi_s
	piS ProofCmCs
}

func (blindSignRequest *BlindSignRequest) verifyProof(params *coconutGo.Parameters, pubKey *elgamal.PublicKey) bool {
	return blindSignRequest.piS.verify(params, pubKey, &blindSignRequest.commitment, blindSignRequest.attributesCiphertexts)
}

// cm || c.len() || c || pi_s
// TODO: subject to change once serde implementation in place in rust's version and whether
// it's 1:1 compatible with bincode (maybe len(pi_s) is needed?)
func (blindSignRequest *BlindSignRequest) Bytes() []byte {
	cmBytes := utils.G1JacobianToByteSlice(&blindSignRequest.commitment)

	cLenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(cLenBytes, uint64(len(blindSignRequest.attributesCiphertexts)))

	proofBytes := blindSignRequest.piS.Bytes()

	b := append(cmBytes, cLenBytes...)
	for _, c := range blindSignRequest.attributesCiphertexts {
		cBytes := c.Bytes()
		b = append(b, cBytes[:]...)
	}
	b = append(b, proofBytes...)

	return b
}

func BlindSignRequestFromBytes(b []byte) (BlindSignRequest, error) {
	if len(b) < 48+8+96 {
		return BlindSignRequest{}, errors.New("tried to deserialize blind sign request with insufficient number of bytes")
	}

	commitment, err := utils.G1JacobianFromBytes(b[:48])
	if err != nil {
		return BlindSignRequest{}, err
	}

	cLen := binary.LittleEndian.Uint64(b[48:56])
	if len(b[56:]) < int(cLen)*96 {
		return BlindSignRequest{}, errors.New("tried to deserialize blind sign request with insufficient number of bytes")
	}

	attributesCiphertexts := make([]*elgamal.Ciphertext, cLen)
	for i := 0; i < int(cLen); i++ {
		start := 56 + i*96
		end := start + 96
		var cBytes [2 * bls381.SizeOfG1AffineCompressed]byte
		copy(cBytes[:], b[start:end])
		ciphertext, err := elgamal.CiphertextFromBytes(cBytes)
		if err != nil {
			return BlindSignRequest{}, err
		}
		attributesCiphertexts[i] = &ciphertext
	}

	piS, err := ProofCmCsFromBytes(b[56+int(cLen)*96:])
	if err != nil {
		return BlindSignRequest{}, err
	}

	return BlindSignRequest{
		commitment:            commitment,
		attributesCiphertexts: attributesCiphertexts,
		piS:                   piS,
	}, nil
}

func PrepareBlindSign(
	params *coconutGo.Parameters,
	publicKey *elgamal.PublicKey,
	privateAttributes []*coconutGo.Attribute,
	publicAttributes []*coconutGo.Attribute,
) (BlindSignRequest, error) {
	if len(privateAttributes) == 0 {
		return BlindSignRequest{}, coconutGo.ErrPrepareBlindSignNoPrivate
	}

	hs := params.Hs()

	if len(privateAttributes)+len(publicAttributes) > len(hs) {
		return BlindSignRequest{}, coconutGo.ErrPrepareBlindSignTooManyAttributes
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
	h := utils.HashToG1(cmBytes[:])
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
	params *coconutGo.Parameters,
	secretKey *SecretKey,
	publicKey *elgamal.PublicKey,
	blindSignRequest *BlindSignRequest,
	publicAttributes []*coconutGo.Attribute,
) (BlindedSignature, error) {
	numPrivate := len(blindSignRequest.attributesCiphertexts)
	hs := params.Hs()

	if numPrivate+len(publicAttributes) > len(hs) {
		return BlindedSignature{}, coconutGo.ErrBlindSignTooManyAttributes
	}

	if !blindSignRequest.verifyProof(params, publicKey) {
		return BlindedSignature{}, coconutGo.ErrBlindSignProof
	}

	cmBytes := utils.G1JacobianToByteSlice(&blindSignRequest.commitment)
	h := utils.HashToG1(cmBytes[:])
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

func Sign(params *coconutGo.Parameters, secretKey *SecretKey, publicAttributes []*coconutGo.Attribute) (Signature, error) {
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
	h := utils.HashToG1(baseRawBytesCompressed[:])

	var K big.Int
	K.Set(&secretKey.x) // K = x
	for i := 0; i < len(publicAttributes); i++ {
		var tmp big.Int

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
