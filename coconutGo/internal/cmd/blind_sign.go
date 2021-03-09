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
	coconut "gitlab.nymte.ch/nym/coconut/coconutGo/scheme"
)

var (
	blindSignCmd = &cobra.Command{
		Use:   "blind-sign [-a number-of-attributes] [--elgamal public-key] [--pub public-attributes] [--req blind-sign-request] [--key issuer-key]",
		Short: "Creates a Coconut credential on the provided attributes with given signers",
		Run:   runBlindSign,
	}
	attributesSign                uint32
	rawIssuerKey                  string
	rawPublicAttributesBlindSign  string
	rawPrivateAttributesBlindSign string
	rawPublicKeyBlindSign         string
	rawLambda                     string
)

func parseLambda(raw string) coconut.BlindSignRequest {
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		panic("failed to decode provided lambda!")
	}
	lambda, err := coconut.BlindSignRequestFromBytes(decoded)
	if err != nil {
		panic("failed to recover provided lambda!")
	}
	return lambda
}

func init() {
	blindSignCmd.PersistentFlags().Uint32VarP(&attributesSign, "attributes", "a", 1, "number of attributes allowed in credential")
	blindSignCmd.PersistentFlags().StringVar(&rawPublicKeyBlindSign, "elgamal", "", "ElGamal public key")
	blindSignCmd.PersistentFlags().StringVar(&rawPrivateAttributesBlindSign, "pub", "", "space separated public attributes to sign")
	blindSignCmd.PersistentFlags().StringVar(&rawIssuerKey, "key", "", "secret key of this authority")
	blindSignCmd.PersistentFlags().StringVar(&rawLambda, "req", "", "blind sign request")

	if err := blindSignCmd.MarkPersistentFlagRequired("attributes"); err != nil {
		panic(err)
	}
	if err := blindSignCmd.MarkPersistentFlagRequired("elgamal"); err != nil {
		panic(err)
	}
	if err := blindSignCmd.MarkPersistentFlagRequired("pub"); err != nil {
		panic(err)
	}
	if err := blindSignCmd.MarkPersistentFlagRequired("key"); err != nil {
		panic(err)
	}
	if err := blindSignCmd.MarkPersistentFlagRequired("req"); err != nil {
		panic(err)
	}

	rootCmd.AddCommand(blindSignCmd)
}

func runBlindSign(cmd *cobra.Command, args []string) {
	secretKey := parseSignerSecret(rawIssuerKey)
	pubkey := parseElGamalPublic(rawPublicKeyBlindSign)
	publicAttributes := parseAttributes(rawPublicAttributesBlindSign)
	lambda := parseLambda(rawLambda)

	params, err := coconutGo.Setup(attributesSign)
	if err != nil {
		panic(err)
	}

	blindedSig, err := coconut.BlindSign(params, &secretKey, &pubkey, &lambda, publicAttributes)
	if err != nil {
		panic(err)
	}

	sigBytes := blindedSig.Bytes()
	encoded := base64.StdEncoding.EncodeToString(sigBytes[:])
	fmt.Printf("%v\n", encoded)
}
