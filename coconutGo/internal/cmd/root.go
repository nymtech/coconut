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

package cmd

import (
	"encoding/base64"
	"fmt"
	"github.com/spf13/cobra"
	"gitlab.nymte.ch/nym/coconut/coconutGo"
	"gitlab.nymte.ch/nym/coconut/coconutGo/elgamal"
	"gitlab.nymte.ch/nym/coconut/coconutGo/internal/utils"
	coconut "gitlab.nymte.ch/nym/coconut/coconutGo/scheme"
	"os"
	"strconv"
	"strings"
)

var (
	rootCmd = &cobra.Command{
		Use: "coconut-cli",
		Short: "coconut-go simple CLI for testing cross-language testing purposes",
	}
)

func parseAttributes(raw string) []*coconutGo.Attribute {
	sep := strings.Split(raw, " ")
	attrs := make([]*coconutGo.Attribute, len(sep))

	for i := range sep {
		num, err := strconv.ParseUint(sep[i], 10, 0)
		if err == nil {
			var attr coconutGo.Attribute
			attr.SetUint64(num)
			attrs[i] = &attr
		} else {
			attr := utils.HashToScalar([]byte(sep[i]))
			attrs[i] = &attr
		}
	}

	return attrs
}

func parseSignerSecret(raw string) coconut.SecretKey {
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		panic("failed to decode provided secret key!")
	}
	sk, err := coconut.SecretKeyFromBytes(decoded)
	if err != nil {
		panic("failed to recover provided secret key!")
	}
	return sk
}

func parseSignerVerificationKey(raw string) coconut.VerificationKey {
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		panic("failed to decode provided verification key!")
	}
	vk, err := coconut.VerificationKeyFromBytes(decoded)
	if err != nil {
		panic("failed to recover provided verification key!")
	}
	return vk
}

func parseIndices(raw string) []uint64 {
	sep := strings.Split(raw, " ")

	indices := make([]uint64, len(sep))

	for i := range sep {
		num, err := strconv.ParseUint(sep[i], 10, 0)
		if err != nil {
			panic("failed to parse provided index")
		}
		indices[i] = num
	}

	return indices
}

func parseSignatures(raw string) []*coconut.Signature {
	sep := strings.Split(raw, " ")
	sigs := make([]*coconut.Signature, len(sep))

	for i := range sep {
		sig := parseSignature(sep[i])
		sigs[i] = &sig
	}

	return sigs
}

func parseSignersVerification(raw string) []*coconut.VerificationKey {
	sep := strings.Split(raw, " ")
	keys := make([]*coconut.VerificationKey, len(sep))

	for i := range sep {
		key := parseSignerVerificationKey(sep[i])
		keys[i] = &key
	}

	return keys
}

func parseElGamalPrivate(raw string) elgamal.PrivateKey {
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		panic("failed to decode provided private key!")
	}
	var rawBytes [32]byte
	copy(rawBytes[:], decoded)

	key, err := elgamal.PrivateKeyFromBytes(rawBytes)
	if err != nil {
		panic("failed to recover provided private key!")
	}
	return key
}

func parseElGamalPublic(raw string) elgamal.PublicKey {
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		panic("failed to decode provided public key!")
	}
	var rawBytes [48]byte
	copy(rawBytes[:], decoded)

	key, err := elgamal.PublicKeyFromBytes(rawBytes)
	if err != nil {
		panic("failed to recover provided public key!")
	}
	return key
}

func parseSignature(raw string) coconut.Signature {
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		panic("failed to decode provided signature!")
	}
	var rawBytes [96]byte
	copy(rawBytes[:], decoded)

	sig, err := coconut.SignatureFromBytes(rawBytes)
	if err != nil {
		panic("failed to recover provided signature!")
	}
	return sig
}


func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize()
}