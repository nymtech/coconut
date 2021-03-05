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

package elgamal

import (
	"errors"
	"gitlab.nymte.ch/nym/coconut/coconutGo/utils"
)

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (privateKey *PrivateKey) MarshalBinary() ([]byte, error) {
	b := utils.ScalarToLittleEndian(&privateKey.d)
	return b[:], nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (privateKey *PrivateKey) UnmarshalBinary(data []byte) error {
	privateKey.d = utils.ScalarFromLittleEndian(data)

	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (publicKey *PublicKey) MarshalBinary() ([]byte, error) {
	b := utils.G1JacobianToByteSlice(&publicKey.gamma)
	return b, nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (publicKey *PublicKey) UnmarshalBinary(data []byte) error {
	gamma, err := utils.G1JacobianFromBytes(data)
	if err != nil {
		return err
	}

	publicKey.gamma = gamma
	return nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (ciphertext *Ciphertext) MarshalBinary() (data []byte, err error) {
	c1Bytes := utils.G1JacobianToByteSlice(ciphertext.C1())
	c2Bytes := utils.G1JacobianToByteSlice(ciphertext.C2())

	return append(c1Bytes, c2Bytes...), nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (ciphertext *Ciphertext) UnmarshalBinary(data []byte) error {
	if len(data) != 96 {
		return errors.New("tried to deserialize elgamal ciphertext with bytes of invalid length")
	}

	c1, err := utils.G1JacobianFromBytes(data[:48])
	if err != nil {
		return err
	}

	c2, err := utils.G1JacobianFromBytes(data[48:])
	if err != nil {
		return err
	}

	ciphertext.c1 = c1
	ciphertext.c2 = c2
	return nil
}
