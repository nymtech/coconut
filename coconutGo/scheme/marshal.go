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
	"errors"
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

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (sk *SecretKey) MarshalBinary() ([]byte, error) {
	return sk.Bytes(), nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (sk *SecretKey) UnmarshalBinary(data []byte) error {
	key, err := SecretKeyFromBytes(data)
	if err != nil {
		return err
	}

	sk.x = key.x
	sk.ys = key.ys

	return nil
}

// alpha || beta.len() || beta
// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (vk *VerificationKey) MarshalBinary() ([]byte, error) {
	return vk.Bytes(), nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (vk *VerificationKey) UnmarshalBinary(data []byte) error {
	key, err := VerificationKeyFromBytes(data)
	if err != nil {
		return err
	}

	vk.alpha = key.alpha
	vk.beta = key.beta
	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (proof *ProofCmCs) MarshalBinary() ([]byte, error) {
	return proof.Bytes(), nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (proof *ProofCmCs) UnmarshalBinary(data []byte) error {
	proofCmCs, err := ProofCmCsFromBytes(data)
	if err != nil {
		return err
	}

	proof.challenge = proofCmCs.challenge
	proof.responseRandom = proofCmCs.responseRandom
	proof.responseKeys = proofCmCs.responseKeys
	proof.responseAttributes = proofCmCs.responseAttributes

	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (proof *ProofKappaNu) MarshalBinary() ([]byte, error) {
	return proof.Bytes(), nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (proof *ProofKappaNu) UnmarshalBinary(data []byte) error {
	proofKappaNu, err := ProofKappaNuFromBytes(data)
	if err != nil {
		return err
	}

	proof.challenge = proofKappaNu.challenge
	proof.responseAttributes = proofKappaNu.responseAttributes
	proof.responseBlinder = proofKappaNu.responseBlinder

	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
// cm || c.len() || c || pi_s
// TODO: subject to change once serde implementation in place in rust's version and whether
// it's 1:1 compatible with bincode (maybe len(pi_s) is needed?)
func (blindSignRequest *BlindSignRequest) MarshalBinary() ([]byte, error) {
	return blindSignRequest.Bytes(), nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (blindSignRequest *BlindSignRequest) UnmarshalBinary(data []byte) error {
	bsr, err := BlindSignRequestFromBytes(data)
	if err != nil {
		return err
	}
	blindSignRequest.commitment = bsr.commitment
	blindSignRequest.attributesCiphertexts = bsr.attributesCiphertexts
	blindSignRequest.piS = bsr.piS

	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
// kappa || nu || credential || pi_v
// TODO: subject to change once serde implementation in place in rust's version and whether
// it's 1:1 compatible with bincode (maybe len(pi_v) is needed?)
func (theta *Theta) MarshalBinary() ([]byte, error) {
	return theta.Bytes(), nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (theta *Theta) UnmarshalBinary(data []byte) error {
	t, err := ThetaFromBytes(data)
	if err != nil {
		return err
	}

	theta.kappa = t.kappa
	theta.nu = t.nu
	theta.credential = t.credential
	theta.piV = t.piV

	return nil
}
