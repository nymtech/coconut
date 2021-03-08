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
	"gitlab.nymte.ch/nym/coconut/coconutGo"
	"gitlab.nymte.ch/nym/coconut/coconutGo/utils"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestElGamalKeygen(t *testing.T) {
	params, err := coconutGo.Setup(1)
	if err != nil {
		panic(err)
	}

	keypair, err := Keygen(params)
	if err != nil {
		panic(err)
	}

	expected := utils.G1ScalarMul(params.Gen1(), &keypair.PrivateKey().d)
	gamma := keypair.PublicKey().gamma

	assert.Equal(t, utils.ToG1Affine(&expected), utils.ToG1Affine(&gamma))
}

func TestElGamalEncryption(t *testing.T) {
	params, err := coconutGo.Setup(1)
	if err != nil {
		panic(err)
	}

	keypair, err := Keygen(params)
	if err != nil {
		panic(err)
	}

	r, err := params.RandomScalar()
	if err != nil {
		panic(err)
	}
	h := utils.G1ScalarMul(params.Gen1(), &r)

	m, err := params.RandomScalar()
	if err != nil {
		panic(err)
	}

	ciphertext, ephemeralKey, err := keypair.PublicKey().Encrypt(params, &h, &m)
	if err != nil {
		panic(err)
	}

	expectedC1 := utils.G1ScalarMul(params.Gen1(), &ephemeralKey)
	assert.Equal(t, &expectedC1, ciphertext.C1(), "c1 should be equal to g1^k")

	t1 := utils.G1ScalarMul(&keypair.PublicKey().gamma, &ephemeralKey)
	t2 := utils.G1ScalarMul(&h, &m)
	expectedC2 := utils.G1Add(&t1, &t2)

	assert.Equal(t, utils.ToG1Affine(&expectedC2), utils.ToG1Affine(ciphertext.C2()), "c2 should be equal to gamma^k * h^m")
}

func TestElGamalDecryption(t *testing.T) {
	params, err := coconutGo.Setup(1)
	if err != nil {
		panic(err)
	}

	keypair, err := Keygen(params)
	if err != nil {
		panic(err)
	}

	r, err := params.RandomScalar()
	if err != nil {
		panic(err)
	}
	h := utils.G1ScalarMul(params.Gen1(), &r)

	m, err := params.RandomScalar()
	if err != nil {
		panic(err)
	}

	ciphertext, _, err := keypair.PublicKey().Encrypt(params, &h, &m)

	if err != nil {
		panic(err)
	}
	decrypted := keypair.PrivateKey().Decrypt(&ciphertext)
	expected := utils.G1ScalarMul(&h, &m)

	assert.Equal(t, utils.ToG1Affine(&expected), utils.ToG1Affine(&decrypted), "after ElGamal decryption, original h^m should be obtained")
}

/*
   #[test]
   fn private_key_bytes_roundtrip() {
       let mut params = Parameters::default();
       let private_key = PrivateKey(params.random_scalar());
       let bytes = private_key.to_bytes();

       // also make sure it is equivalent to the internal scalar's bytes
       assert_eq!(private_key.0.to_bytes(), bytes);
       assert_eq!(private_key, PrivateKey::from_bytes(&bytes).unwrap())
   }

   #[test]
   fn public_key_bytes_roundtrip() {
       let mut params = Parameters::default();
       let r = params.random_scalar();
       let public_key = PublicKey(params.gen1() * r);
       let bytes = public_key.to_bytes();

       // also make sure it is equivalent to the internal g1 compressed bytes
       assert_eq!(public_key.0.to_affine().to_compressed(), bytes);
       assert_eq!(public_key, PublicKey::from_bytes(&bytes).unwrap())
   }

*/
