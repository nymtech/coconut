package proofs

import (
	"crypto/sha256"
	"github.com/consensys/gurvy/bls381"
	coconut "gitlab.nymte.ch/nym/coconut/CoconutGo"
	"gitlab.nymte.ch/nym/coconut/CoconutGo/elgamal"
	"gitlab.nymte.ch/nym/coconut/CoconutGo/utils"
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
	// TODO: DOES IT NEED TO BE REDUCED MOD ORDER?
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

// ConstructProofCmCs non-interactive zero-knowledge proof of correctness of the ciphertexts and the commitment.
func ConstructProofCmCs(
	params *coconut.Parameters,
	publicKey *elgamal.PublicKey,
	ephemeralKeys []*elgamal.EphemeralKey,
	commitment *bls381.G1Jac,
	blindingFactor *big.Int,
	privateAttributes []*coconut.Attribute,
	publicAttributes []*coconut.Attribute,
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
	h, err := utils.HashToG1(cmBytes[:])
	if err != nil {
		return ProofCmCs{}, err
	}
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
func (proof *ProofCmCs) Verify(
	params *coconut.Parameters,
	publicKey *elgamal.PublicKey,
	commitment *bls381.G1Jac,
	attributesCiphertexts []*elgamal.Ciphertext,
) bool {
	if len(attributesCiphertexts) != len(proof.responseKeys) {
		return false
	}

	// recompute h
	cmBytes := utils.G1JacobianToByteSlice(commitment)
	h, err := utils.HashToG1(cmBytes[:])
	if err != nil {
		return false
	}
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
	Cw := utils.G1ScalarMul(g1, &proof.challenge)       // Cw = (cm * c)
	tmp := utils.G1ScalarMul(g1, &proof.responseRandom) // tmp = (rr * g1)
	Cw.AddAssign(&tmp)                                  // Cw = (cm * c) + (rr * g1)
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
	response_attributes []big.Int

	// rt
	response_blinder big.Int
}
