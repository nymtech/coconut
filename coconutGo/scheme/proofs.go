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
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"github.com/consensys/gurvy/bls381"
	"gitlab.nymte.ch/nym/coconut/coconutGo"
	"gitlab.nymte.ch/nym/coconut/coconutGo/elgamal"
	"gitlab.nymte.ch/nym/coconut/coconutGo/utils"
	"math/big"
)

// ConstructChallenge construct a scalar challenge by hashing a number of elliptic curve points.
// note: this is slightly different from the reference python implementation
// as we omit the unnecessary string conversion. Instead we concatenate byte
// representations together and hash that.
// note2: G1 and G2 elements are using their compressed representations
// and as per the bls12-381 library all elements are using big-endian form
func constructChallenge(pointRepresentations [][]byte) big.Int {
	h := sha256.New()
	for _, pointRepresentation := range pointRepresentations {
		h.Write(pointRepresentation)
	}
	digest := h.Sum([]byte{})

	// TODO: this is only introduced for the initial compatibility with the rust library and
	// zcash's method for `from_bytes_wide` that does not seem to have a failing case.
	// In the future it should be replaced with something simpler that is implemented in both languages
	padSize := 64 - h.Size()
	var bytes [64]byte
	copy(bytes[64-padSize:], digest)

	return utils.ScalarFromBytesWide(bytes)
}

// Produce witness - challenge * secret
func produceResponse(witness, challenge, secret *big.Int) big.Int {
	var tmp big.Int
	tmp.Mul(challenge, secret)

	var res big.Int
	res.Sub(witness, &tmp)

	return res
}

// note: it's caller's responsibility to ensure len(witnesses) = len(secrets)
func produceResponses(witnesses []*big.Int, challenge *big.Int, secrets []*big.Int) []big.Int {
	responses := make([]big.Int, len(witnesses))
	for i := 0; i < len(witnesses); i++ {
		responses[i] = produceResponse(witnesses[i], challenge, secrets[i])
	}
	return responses
}

type ProofCmCs struct {
	challenge big.Int
	// rr
	responseRandom big.Int
	// rk
	responseKeys []big.Int
	// rm
	responseAttributes []big.Int
}

// challenge || rr || rk.len() || rk || rm.len() || rm
func (proof *ProofCmCs) Bytes() []byte {
	challengeBytes := utils.ScalarToLittleEndian(&proof.challenge)
	rrBytes := utils.ScalarToLittleEndian(&proof.responseRandom)

	keysLenBytes := make([]byte, 8)
	attributesLenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(keysLenBytes, uint64(len(proof.responseKeys)))
	binary.LittleEndian.PutUint64(attributesLenBytes, uint64(len(proof.responseAttributes)))

	b := append(challengeBytes[:], rrBytes[:]...)
	b = append(b, keysLenBytes...)
	for _, rk := range proof.responseKeys {
		rkBytes := utils.ScalarToLittleEndian(&rk)
		b = append(b, rkBytes[:]...)
	}
	b = append(b, attributesLenBytes...)
	for _, rm := range proof.responseAttributes {
		rmBytes := utils.ScalarToLittleEndian(&rm)
		b = append(b, rmBytes[:]...)
	}

	return b
}

func ProofCmCsFromBytes(b []byte) (ProofCmCs, error) {
	// at the very minimum there must be a single attribute being proven
	if len(b) < 32*4+16 || (len(b)-16)%32 != 0 {
		return ProofCmCs{}, errors.New("tried to deserialize proof of ciphertexts and commitment with bytes of invalid length")
	}

	challenge := utils.ScalarFromLittleEndian(b[:32])
	responseRandom := utils.ScalarFromLittleEndian(b[32:64])

	rkLen := binary.LittleEndian.Uint64(b[64:72])
	if len(b[72:]) < int(rkLen)*32+8 {
		return ProofCmCs{}, errors.New("tried to deserialize proof of ciphertexts and commitment with insufficient number of bytes provided")
	}

	rkEnd := 72 + int(rkLen) * 32
	responseKeys, err := utils.DeserializeScalarVec(rkLen, b[72:rkEnd])
	if err != nil {
		return ProofCmCs{}, err
	}

	rmLen := binary.LittleEndian.Uint64(b[rkEnd : rkEnd+8])
	responseAttributes, err := utils.DeserializeScalarVec(rmLen, b[rkEnd+8:])
	if err != nil {
		return ProofCmCs{}, err
	}

	return ProofCmCs{
		challenge:          challenge,
		responseRandom:     responseRandom,
		responseKeys:       responseKeys,
		responseAttributes: responseAttributes,
	}, nil
}

// constructProofCmCs non-interactive zero-knowledge proof of correctness of the ciphertexts and the commitment.
func constructProofCmCs(
	params *coconutGo.Parameters,
	publicKey *elgamal.PublicKey,
	ephemeralKeys []*elgamal.EphemeralKey,
	commitment *bls381.G1Jac,
	blindingFactor *big.Int,
	privateAttributes []*coconutGo.Attribute,
	publicAttributes []*coconutGo.Attribute,
) (ProofCmCs, error) {
	// note: this is only called from `prepare_blind_sign` that already checks
	// whether private attributes are non-empty and whether we don't have too many
	// attributes in total to sign.
	// we also know, due to the single call place, that ephemeralKeys.len() == privateAttributes.len()

	// witness creation
	witnessBlinder, err := params.RandomScalar()
	if err != nil {
		return ProofCmCs{}, err
	}
	witnessKeys, err := params.NRandomScalars(len(ephemeralKeys))
	if err != nil {
		return ProofCmCs{}, err
	}
	witnessAttributes, err := params.NRandomScalars(len(privateAttributes) + len(publicAttributes))
	if err != nil {
		return ProofCmCs{}, err
	}

	cmBytes := utils.G1JacobianToByteSlice(commitment)
	h := utils.HashToG1(cmBytes[:])
	hJac := utils.ToG1Jacobian(&h)

	// witnesses commitments
	g1 := params.Gen1()

	AwBytes := make([][]byte, len(witnessKeys))
	BwBytes := make([][]byte, len(witnessKeys))

	for i := range witnessKeys {
		AwI := utils.G1ScalarMul(g1, witnessKeys[i]) // Aw[i] = (wk[i] * g1)
		AwBytes[i] = utils.G1JacobianToByteSlice(&AwI)

		BwI := utils.G1ScalarMul(&hJac, witnessAttributes[i])       // Bw[i] = (wm[i] * h)
		tmp := utils.G1ScalarMul(publicKey.Gamma(), witnessKeys[i]) // tmp = wk[i] * gamma
		BwI.AddAssign(&tmp)                                         // Bw[i] = (wm[i] * h) + (wk[i] * gamma)
		BwBytes[i] = utils.G1JacobianToByteSlice(&BwI)
	}

	hs := params.Hs()
	Cw := utils.G1ScalarMul(g1, &witnessBlinder)
	for i := range witnessAttributes {
		hsIJac := utils.ToG1Jacobian(hs[i])
		tmp := utils.G1ScalarMul(&hsIJac, witnessAttributes[i]) // tmp = (wm[i] * hs[i])
		Cw.AddAssign(&tmp)                                      // Cw = (wr * g1) + (wm[0] * hs[0]) + ... + (wm[i] * hs[i])
	}
	CwBytes := utils.G1JacobianToByteSlice(&Cw)

	// challenge ([g1, g2, cm, h, Cw]+hs+Aw+Bw)
	challengeComponents := [][]byte{
		utils.G1JacobianToByteSlice(g1),
		utils.G2JacobianToByteSlice(params.Gen2()),
		cmBytes,
		utils.G1AffineToByteSlice(&h),
		CwBytes,
	}

	for _, hsi := range hs {
		challengeComponents = append(challengeComponents, utils.G1AffineToByteSlice(hsi))
	}

	challengeComponents = append(challengeComponents, AwBytes...)
	challengeComponents = append(challengeComponents, BwBytes...)

	challenge := constructChallenge(challengeComponents)

	// responses
	responseRandom := produceResponse(&witnessBlinder, &challenge, blindingFactor)
	responseKeys := produceResponses(witnessKeys, &challenge, ephemeralKeys)
	responseAttributes := produceResponses(witnessAttributes, &challenge, append(privateAttributes, publicAttributes...))

	return ProofCmCs{
		challenge:          challenge,
		responseRandom:     responseRandom,
		responseKeys:       responseKeys,
		responseAttributes: responseAttributes,
	}, nil
}

// Verify verifies non-interactive zero-knowledge proof of correctness of the ciphertexts and the commitment.
func (proof *ProofCmCs) verify(
	params *coconutGo.Parameters,
	publicKey *elgamal.PublicKey,
	commitment *bls381.G1Jac,
	attributesCiphertexts []*elgamal.Ciphertext,
) bool {
	if len(attributesCiphertexts) != len(proof.responseKeys) {
		return false
	}

	// recompute h
	cmBytes := utils.G1JacobianToByteSlice(commitment)
	h := utils.HashToG1(cmBytes[:])
	hJac := utils.ToG1Jacobian(&h)

	g1 := params.Gen1()

	// recompute witnesses commitments
	AwBytes := make([][]byte, len(attributesCiphertexts))
	BwBytes := make([][]byte, len(attributesCiphertexts))

	for i := range attributesCiphertexts {
		AwI := utils.G1ScalarMul(attributesCiphertexts[i].C1(), &proof.challenge) // Aw[i] = (c * c1[i])
		tmp := utils.G1ScalarMul(g1, &proof.responseKeys[i])                      // tmp = (rk[i] * g1)
		AwI.AddAssign(&tmp)                                                       // (c * c1[i]) + (rk[i] * g1)
		AwBytes[i] = utils.G1JacobianToByteSlice(&AwI)

		BwI := utils.G1ScalarMul(attributesCiphertexts[i].C2(), &proof.challenge) // Bw[i] = (c * c2[i])
		tmp = utils.G1ScalarMul(publicKey.Gamma(), &proof.responseKeys[i])        // tmp = (rk[i] * gamma)
		BwI.AddAssign(&tmp)                                                       // Bw[i] = (c * c2[i]) + (rk[i] * gamma)
		tmp = utils.G1ScalarMul(&hJac, &proof.responseAttributes[i])              // tmp = (rm[i] * h)
		BwI.AddAssign(&tmp)                                                       // Bw[i] = (c * c2[i]) + (rk[i] * gamma) + (rm[i] * h)
		BwBytes[i] = utils.G1JacobianToByteSlice(&BwI)
	}

	hs := params.Hs()
	Cw := utils.G1ScalarMul(commitment, &proof.challenge) // Cw = (cm * c)
	tmp := utils.G1ScalarMul(g1, &proof.responseRandom)   // tmp = (rr * g1)
	Cw.AddAssign(&tmp)                                    // Cw = (cm * c) + (rr * g1)
	for i := range proof.responseAttributes {
		hsIJac := utils.ToG1Jacobian(hs[i])
		tmp := utils.G1ScalarMul(&hsIJac, &proof.responseAttributes[i]) // tmp = (rm[i] * hs[i])
		Cw.AddAssign(&tmp)                                              // Cw = (cm * c) + (rr * g1) + (rm[0] * hs[0]) + ... + (rm[i] * hs[i])
	}
	CwBytes := utils.G1JacobianToByteSlice(&Cw)

	// challenge ([g1, g2, cm, h, Cw]+hs+Aw+Bw)
	challengeComponents := [][]byte{
		utils.G1JacobianToByteSlice(g1),
		utils.G2JacobianToByteSlice(params.Gen2()),
		cmBytes,
		utils.G1AffineToByteSlice(&h),
		CwBytes,
	}

	for _, hsi := range hs {
		challengeComponents = append(challengeComponents, utils.G1AffineToByteSlice(hsi))
	}

	challengeComponents = append(challengeComponents, AwBytes...)
	challengeComponents = append(challengeComponents, BwBytes...)

	challenge := constructChallenge(challengeComponents)

	return challenge.Cmp(&proof.challenge) == 0
}

type ProofKappaNu struct {
	// c
	challenge big.Int

	// rm
	responseAttributes []big.Int

	// rt
	responseBlinder big.Int
}

// challenge || rm.len() || rm || rt
func (proof *ProofKappaNu) Bytes() []byte {
	challengeBytes := utils.ScalarToLittleEndian(&proof.challenge)

	attributesLenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(attributesLenBytes, uint64(len(proof.responseAttributes)))

	b := challengeBytes[:]
	b = append(b, attributesLenBytes...)
	for _, rm := range proof.responseAttributes {
		rmBytes := utils.ScalarToLittleEndian(&rm)
		b = append(b, rmBytes[:]...)
	}

	rtBytes := utils.ScalarToLittleEndian(&proof.responseBlinder)
	b = append(b, rtBytes[:]...)
	return b
}

func ProofKappaNuFromBytes(b []byte) (ProofKappaNu, error) {
	// at the very minimum there must be a single attribute being proven
	if len(b) < 32*3+8 || (len(b)-8)%32 != 0 {
		return ProofKappaNu{}, errors.New("tried to deserialize proof of kappa and nu with bytes of invalid length")
	}

	challenge := utils.ScalarFromLittleEndian(b[:32])
	rmLen := binary.LittleEndian.Uint64(b[32:40])
	if len(b[40:]) != int(rmLen+1)*32 {
		return ProofKappaNu{}, errors.New("tried to deserialize proof of kappa and nu with insufficient number of bytes provided")
	}

	rmEnd := 40 + int(rmLen)*32
	responseAttributes, err := utils.DeserializeScalarVec(rmLen, b[40:rmEnd])
	if err != nil {
		return ProofKappaNu{}, err
	}
	responseBlinder := utils.ScalarFromLittleEndian(b[rmEnd:])

	return ProofKappaNu{
		challenge:          challenge,
		responseAttributes: responseAttributes,
		responseBlinder:    responseBlinder,
	}, nil
}

// constructProofCmCs non-interactive zero-knowledge proof of correctness of the ciphertexts and the commitment.
func constructProofKappaNu(
	params *coconutGo.Parameters,
	verificationKey *VerificationKey,
	signature *Signature,
	privateAttributes []*coconutGo.Attribute,
	blindingFactor *big.Int,
) (ProofKappaNu, error) {
	// create witnesses
	witnessRandom, err := params.RandomScalar()
	if err != nil {
		return ProofKappaNu{}, err
	}

	witnessAttributes, err := params.NRandomScalars(len(privateAttributes))
	if err != nil {
		return ProofKappaNu{}, err
	}

	// witnesses commitments
	Aw := utils.G2ScalarMul(params.Gen2(), &witnessRandom) // Aw = (g2 ^ wt)
	Aw.AddAssign(&verificationKey.alpha)                   // Aw = (g2 ^ wt) * alpha

	for i := 0; i < len(witnessAttributes); i++ {
		tmp := utils.G2ScalarMul(verificationKey.beta[i], witnessAttributes[i]) // tmp = beta[i] ^ wm[i]
		Aw.AddAssign(&tmp)                                                      // Aw = (g2 ^ wt) * alpha * (beta[0] ^ wm[0]) * ... * (beta[i] ^ wm[i])
	}

	Bw := utils.G1ScalarMul(&signature.sig1, &witnessRandom) // Bw = (h ^ wt)

	// challenge ([g1, g2, alpha, Aw, Bw]+hs+beta)
	challengeComponents := [][]byte{
		utils.G1JacobianToByteSlice(params.Gen1()),
		utils.G2JacobianToByteSlice(params.Gen2()),
		utils.G2JacobianToByteSlice(verificationKey.Alpha()),
		utils.G2JacobianToByteSlice(&Aw),
		utils.G1JacobianToByteSlice(&Bw),
	}

	for _, hsi := range params.Hs() {
		challengeComponents = append(challengeComponents, utils.G1AffineToByteSlice(hsi))
	}

	for _, betai := range verificationKey.Beta() {
		challengeComponents = append(challengeComponents, utils.G2JacobianToByteSlice(betai))
	}

	challenge := constructChallenge(challengeComponents)

	responseRandom := produceResponse(&witnessRandom, &challenge, blindingFactor)
	responseAttributes := produceResponses(witnessAttributes, &challenge, privateAttributes)

	return ProofKappaNu{
		challenge:          challenge,
		responseAttributes: responseAttributes,
		responseBlinder:    responseRandom,
	}, nil
}

// Verify verifies non-interactive zero-knowledge proof of correctness of kappa and nu.
func (proof *ProofKappaNu) verify(
	params *coconutGo.Parameters,
	verificationKey *VerificationKey,
	signature *Signature,
	kappa *bls381.G2Jac,
	nu *bls381.G1Jac,
) bool {
	// recompute Kappa and Nu commitments
	Aw := utils.G2ScalarMul(kappa, &proof.challenge)                // Aw = (kappa ^ c)
	tmp := utils.G2ScalarMul(params.Gen2(), &proof.responseBlinder) // tmp = (g2 ^ rt)
	Aw.AddAssign(&tmp)                                              // Aw = (kappa ^ c) * (g2 ^ rt)

	// tmp2 = (1 - c)
	var tmp2 big.Int
	tmp2.Sub(big.NewInt(1), &proof.challenge)

	// tmp = alpha ^ (1 - c)
	tmp = utils.G2ScalarMul(verificationKey.Alpha(), &tmp2)

	Aw.AddAssign(&tmp) // Aw = (kappa ^ c) * (g2 ^ rt) * alpha ^ (1 - c)
	for i := 0; i < len(proof.responseAttributes); i++ {
		tmp := utils.G2ScalarMul(verificationKey.beta[i], &proof.responseAttributes[i]) // tmp = (beta[i] ^ rm[i])
		Aw.AddAssign(&tmp)                                                              // Aw = (kappa ^ c) * (g2 ^ rt) * alpha ^ (1 - c) * (beta[0] ^ rm[0]) * ... * (beta[m] ^ rm[m])
	}

	Bw := utils.G1ScalarMul(nu, &proof.challenge)                      // Bw = (nu ^ c)
	tmp3 := utils.G1ScalarMul(&signature.sig1, &proof.responseBlinder) // tmp = (h ^ rt)
	Bw.AddAssign(&tmp3)                                                // Bw = (nu ^ c) * (h ^ rt)

	// challenge ([g1, g2, alpha, Aw, Bw]+hs+beta)
	challengeComponents := [][]byte{
		utils.G1JacobianToByteSlice(params.Gen1()),
		utils.G2JacobianToByteSlice(params.Gen2()),
		utils.G2JacobianToByteSlice(verificationKey.Alpha()),
		utils.G2JacobianToByteSlice(&Aw),
		utils.G1JacobianToByteSlice(&Bw),
	}

	for _, hsi := range params.Hs() {
		challengeComponents = append(challengeComponents, utils.G1AffineToByteSlice(hsi))
	}

	for _, betai := range verificationKey.Beta() {
		challengeComponents = append(challengeComponents, utils.G2JacobianToByteSlice(betai))
	}

	challenge := constructChallenge(challengeComponents)

	return challenge.Cmp(&proof.challenge) == 0
}
