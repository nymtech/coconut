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

import "gitlab.nymte.ch/nym/coconut/coconutGo/utils"

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
