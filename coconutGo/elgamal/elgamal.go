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
	"github.com/consensys/gurvy/bls381"
	"github.com/consensys/gurvy/bls381/fr"
	"gitlab.nymte.ch/nym/coconut/coconutGo"
	"gitlab.nymte.ch/nym/coconut/coconutGo/utils"
	"math/big"
)

type EphemeralKey = big.Int

type Ciphertext struct {
	c1 bls381.G1Jac
	c2 bls381.G1Jac
}

func CiphertextFromRaw(c1 bls381.G1Jac, c2 bls381.G1Jac) Ciphertext {
	return Ciphertext{c1: c1, c2: c2}
}

// C1 returns first group element of the ElGamal ciphertext.
func (ciphertext *Ciphertext) C1() *bls381.G1Jac {
	return &ciphertext.c1
}

// C2 returns second group element of the ElGamal ciphertext.
func (ciphertext *Ciphertext) C2() *bls381.G1Jac {
	return &ciphertext.c2
}

func (ciphertext *Ciphertext) Bytes() [2 * bls381.SizeOfG1AffineCompressed]byte {
	c1Bytes := utils.G1JacobianToByteSlice(ciphertext.C1())
	c2Bytes := utils.G1JacobianToByteSlice(ciphertext.C2())

	var b [2 * bls381.SizeOfG1AffineCompressed]byte
	copy(b[bls381.SizeOfG1AffineCompressed:], c1Bytes)
	copy(b[:bls381.SizeOfG1AffineCompressed], c2Bytes)

	return b
}

func CiphertextFromBytes(b [2 * bls381.SizeOfG1AffineCompressed]byte) (Ciphertext, error) {
	c1, err := utils.G1JacobianFromBytes(b[:bls381.SizeOfG1AffineCompressed])
	if err != nil {
		return Ciphertext{}, err
	}
	c2, err := utils.G1JacobianFromBytes(b[bls381.SizeOfG1AffineCompressed:])
	if err != nil {
		return Ciphertext{}, err
	}

	return Ciphertext{
		c1: c1,
		c2: c2,
	}, nil
}

type PrivateKey struct {
	d big.Int
}

func (privateKey *PrivateKey) Decrypt(ciphertext *Ciphertext) bls381.G1Jac {
	c1 := &ciphertext.c1
	c2 := &ciphertext.c2

	// c1^d == g1^{d * k}
	tmp := utils.G1ScalarMul(c1, &privateKey.d)

	// (gamma^k * h^m) / (g1^{d * k})   |   note: gamma = g1^d
	return utils.G1Sub(c2, &tmp)
}

func (privateKey *PrivateKey) Bytes() [fr.Limbs * 8]byte {
	return utils.ScalarToLittleEndian(&privateKey.d)
}

func PrivateKeyFromBytes(b [fr.Limbs * 8]byte) (PrivateKey, error) {
	return PrivateKey{
		d: utils.ScalarFromLittleEndian(b[:]),
	}, nil
}

type PublicKey struct {
	gamma bls381.G1Jac
}

func (publicKey *PublicKey) Gamma() *bls381.G1Jac {
	return &publicKey.gamma
}

func (publicKey *PublicKey) Encrypt(params *coconutGo.Parameters, h *bls381.G1Jac, msg *big.Int) (Ciphertext, EphemeralKey, error) {
	k, err := params.RandomScalar()
	if err != nil {
		return Ciphertext{}, EphemeralKey{}, err
	}

	// c1 = g1^k
	c1 := utils.G1ScalarMul(params.Gen1(), &k)

	// t1 = gamma^k
	t1 := utils.G1ScalarMul(&publicKey.gamma, &k)

	// t2 = h^m;
	t2 := utils.G1ScalarMul(h, msg)

	// c2 = gamma^k * h^m
	c2 := utils.G1Add(&t1, &t2)

	return Ciphertext{
		c1: c1,
		c2: c2,
	}, k, nil
}

func (publicKey *PublicKey) Bytes() [bls381.SizeOfG1AffineCompressed]byte {
	var b [bls381.SizeOfG1AffineCompressed]byte
	copy(b[:], utils.G1JacobianToByteSlice(&publicKey.gamma))
	return b
}

func PublicKeyFromBytes(b [bls381.SizeOfG1AffineCompressed]byte) (PublicKey, error) {
	gamma, err := utils.G1JacobianFromBytes(b[:])
	if err != nil {
		return PublicKey{}, err
	}

	return PublicKey{
		gamma: gamma,
	}, nil
}

type KeyPair struct {
	privateKey PrivateKey
	publicKey  PublicKey
}

func (keypair *KeyPair) PrivateKey() *PrivateKey {
	return &keypair.privateKey
}

func (keypair *KeyPair) PublicKey() *PublicKey {
	return &keypair.publicKey
}

func Keygen(params *coconutGo.Parameters) (*KeyPair, error) {
	d, err := params.RandomScalar()
	if err != nil {
		return nil, err
	}

	gamma := utils.G1ScalarMul(params.Gen1(), &d)

	return &KeyPair{
		privateKey: PrivateKey{
			d: d,
		},
		publicKey: PublicKey{
			gamma: gamma,
		},
	}, nil
}
