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
	"gitlab.nymte.ch/nym/coconut/coconutGo/utils"
)

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (sig *Signature) MarshalBinary() ([]byte, error) {
	sig1Bytes := utils.G1JacobianToByteSlice(&sig.sig1)
	sig2Bytes := utils.G1JacobianToByteSlice(&sig.sig2)

	return append(sig1Bytes, sig2Bytes...), nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (sig *Signature) UnmarshalBinary(data []byte) error {
	if len(data) != 96 {
		return errors.New("tried to deserialize signature with bytes of invalid length")
	}

	sig1, err := utils.G1JacobianFromBytes(data[:48])
	if err != nil {
		return err
	}

	sig2, err := utils.G1JacobianFromBytes(data[48:])
	if err != nil {
		return err
	}

	sig.sig1 = sig1
	sig.sig2 = sig2
	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (blindedSig *BlindedSignature) MarshalBinary() ([]byte, error) {
	hBytes := utils.G1JacobianToByteSlice(&blindedSig.sig1)
	cTildeBytes, err := blindedSig.sig2.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return append(hBytes, cTildeBytes...), nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (blindedSig *BlindedSignature) UnmarshalBinary(data []byte) error {
	if len(data) != 144 {
		return errors.New("tried to deserialize blinded signature with bytes of invalid length")
	}

	h, err := utils.G1JacobianFromBytes(data[:48])
	if err != nil {
		return err
	}

	if err := blindedSig.sig2.UnmarshalBinary(data[48:]); err != nil {
		return err
	}

	blindedSig.sig1 = h

	return nil
}


// x || ys.len() || ys
// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (sk *SecretKey) MarshalBinary() ([]byte, error) {
	xBytes := utils.ScalarToLittleEndian(sk.X())
	ysLenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(ysLenBytes, uint64(len(sk.ys)))
	b := append(xBytes[:], ysLenBytes...)

	for _, y := range sk.ys {
		yBytes := utils.ScalarToLittleEndian(&y)
		b = append(b, yBytes[:]...)
	}

	return b, nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (sk *SecretKey) UnmarshalBinary(data []byte) error {
	if len(data) < 32 * 2 + 8 || (len(data) - 8) % 32 != 0 {
		return errors.New("tried to deserialize secret key with bytes of invalid length")
	}

	sk.x = utils.ScalarFromLittleEndian(data[:32])
	yLen := binary.LittleEndian.Uint64(data[32:40])

	ys, err := utils.DeserializeScalarVec(yLen, data[40:])
	if err != nil {
		return err
	}

	sk.ys = ys

	return nil
}

// alpha || beta.len() || beta
// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (vk *VerificationKey) MarshalBinary() ([]byte, error) {
	alphaBytes := utils.G2JacobianToByteSlice(vk.Alpha())
	betaLenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(betaLenBytes, uint64(len(vk.beta)))
	b := append(alphaBytes[:], betaLenBytes...)

	for _, betaI := range vk.beta {
		b = append(b, utils.G2JacobianToByteSlice(betaI)...)
	}

	return b, nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (vk *VerificationKey) UnmarshalBinary(data []byte) error {
	if len(data) < 96 * 2 + 8 || (len(data) - 8) % 96 != 0  {
		return errors.New("tried to deserialize verification key with bytes of invalid length")
	}
	alpha, err := utils.G2JacobianFromBytes(data[:96])
	if err != nil {
		return err
	}

	betaLen := binary.LittleEndian.Uint64(data[96:104])
	actualBetaLen := (len(data) - 104) / 96
	if actualBetaLen != int(betaLen) {
		return errors.New("tried to deserialize verification key with inconsistent beta len")
	}

	beta := make([]*bls381.G2Jac, actualBetaLen)
	for i := 0; i < actualBetaLen; i++ {
		betaI, err := utils.G2JacobianFromBytes(data[104 + (i * 96): 104 + ((i+1)*96)])
		if err != nil {
			return err
		}
		beta[i] = &betaI
	}

	vk.alpha = alpha
	vk.beta = beta
	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
// challenge || rr || rk.len() || rk || rm.len() || rm
func (proof *ProofCmCs) MarshalBinary() ([]byte, error) {
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
	return b, nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (proof *ProofCmCs) UnmarshalBinary(data []byte) error {
	// at the very minimum there must be a single attribute being proven
	if len(data) < 32 * 4 + 16 || (len(data) - 16) % 32 != 0  {
		return errors.New("tried to deserialize proof of ciphertexts and commitment with bytes of invalid length")
	}

	challenge := utils.ScalarFromLittleEndian(data[:32])
	responseRandom := utils.ScalarFromLittleEndian(data[32:64])

	rkLen := binary.LittleEndian.Uint64(data[64:72])
	if len(data[72:]) < int(rkLen) * 32 + 8 {
		return errors.New("tried to deserialize proof of ciphertexts and commitment with insufficient number of bytes provided")
	}

	rkEnd := 72 * int(rkLen) * 32
	responseKeys, err := utils.DeserializeScalarVec(rkLen, data[72:rkLen])
	if err != nil {
		return err
	}

	rmLen := binary.LittleEndian.Uint64(data[rkLen:rkEnd+8])
	responseAttributes, err := utils.DeserializeScalarVec(rmLen, data[rkLen+8:])
	if err != nil {
		return err
	}

	proof.challenge = challenge
	proof.responseRandom = responseRandom
	proof.responseKeys = responseKeys
	proof.responseAttributes = responseAttributes

	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
// challenge || rm.len() || rm || rt
func (proof *ProofKappaNu) MarshalBinary() ([]byte, error) {
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
	b = append(challengeBytes[:], rtBytes[:]...)
	return b, nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (proof *ProofKappaNu) UnmarshalBinary(data []byte) error {
	// at the very minimum there must be a single attribute being proven
	if len(data) <  32 * 3 + 8  || (len(data) - 8) % 32 != 0  {
		return errors.New("tried to deserialize proof of kappa and nu with bytes of invalid length")
	}

	challenge := utils.ScalarFromLittleEndian(data[:32])
	rmLen := binary.LittleEndian.Uint64(data[32:40])
	if len(data[40:]) != int(rmLen + 1) * 32 {
		return errors.New("tried to deserialize proof of kappa and nu with insufficient number of bytes provided")
	}

	rmEnd := 40 + int(rmLen) * 32
	responseAttributes, err := utils.DeserializeScalarVec(rmLen, data[40:rmEnd])
	if err != nil {
		return nil
	}
	responseBlinder := utils.ScalarFromLittleEndian(data[rmEnd:])

	proof.challenge = challenge
	proof.responseAttributes = responseAttributes
	proof.responseBlinder = responseBlinder

	return nil
}