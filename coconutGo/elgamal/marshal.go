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
	"github.com/consensys/gurvy/bls381"
	"github.com/consensys/gurvy/bls381/fr"
)

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (privateKey *PrivateKey) MarshalBinary() ([]byte, error) {
	b := privateKey.Bytes()
	return b[:], nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (privateKey *PrivateKey) UnmarshalBinary(data []byte) error {
	if len(data) != fr.Limbs * 8 {
		return errors.New("tried to deserialize elgamal private key with bytes of invalid length")
	}

	var b [fr.Limbs * 8]byte
	copy(b[:], data)

	key, err := PrivateKeyFromBytes(b)
	if err != nil {
		return err
	}

	// ideally I would have just pointed the entire privateKey here, but due to interface
	// restriction (and Go's) I couldn't do that.
	privateKey.d = key.d
	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (publicKey *PublicKey) MarshalBinary() ([]byte, error) {
	b := publicKey.Bytes()
	return b[:], nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (publicKey *PublicKey) UnmarshalBinary(data []byte) error {
	if len(data) != bls381.SizeOfG1AffineCompressed {
		return errors.New("tried to deserialize elgamal public key with bytes of invalid length")
	}

	var b [bls381.SizeOfG1AffineCompressed]byte
	copy(b[:], data)

	key, err := PublicKeyFromBytes(b)
	if err != nil {
		return err
	}

	// ideally I would have just pointed the entire publicKey here, but due to interface
	// restriction (and Go's) I couldn't do that.
	publicKey.gamma = key.gamma
	return nil
}

// MarshalBinary is an implementation of a method on the
// BinaryMarshaler interface defined in https://golang.org/pkg/encoding/
func (ciphertext *Ciphertext) MarshalBinary() (data []byte, err error) {
	b := ciphertext.Bytes()
	return b[:], nil
}

// UnmarshalBinary is an implementation of a method on the
// BinaryUnmarshaler interface defined in https://golang.org/pkg/encoding/
func (ciphertext *Ciphertext) UnmarshalBinary(data []byte) error {
	if len(data) != 2 * bls381.SizeOfG1AffineCompressed {
		return errors.New("tried to deserialize elgamal ciphertext with bytes of invalid length")
	}

	var b [2 * bls381.SizeOfG1AffineCompressed]byte
	copy(b[:], data)

	c, err := CiphertextFromBytes(b)
	if err != nil {
		return err
	}

	// ideally I would have just pointed the entire ciphertext here, but due to interface
	// restriction (and Go's) I couldn't do that.
	ciphertext.c1 = c.c1
	ciphertext.c2 = c.c2
	return nil
}
