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
	prepareBlindSignCmd = &cobra.Command{
		Use:   "prepare-blind-sign [--key public-key] [--pub public-attributes] [--priv private-attributes] [-a number-of-attributes]",
		Short: "Creates a Coconut blind sign request on the provided attributes",
		Run:   runPrepareBlindSign,
	}
	rawPublicAttributesPrepareBlind  string
	rawPrivateAttributesPrepareBlind string
	rawPublicKeyPrepareBlind         string
	numberOfAttributesPrepare        uint32
)

func init() {
	prepareBlindSignCmd.PersistentFlags().StringVar(&rawPublicKeyPrepareBlind, "key", "", "ElGamal public key")
	prepareBlindSignCmd.PersistentFlags().StringVar(&rawPublicAttributesPrepareBlind, "pub", "", "space separated public attributes to sign")
	prepareBlindSignCmd.PersistentFlags().StringVar(&rawPrivateAttributesPrepareBlind, "priv", "", "space separated private attributes to sign")
	prepareBlindSignCmd.PersistentFlags().Uint32VarP(&numberOfAttributesPrepare, "attributes", "a", 1, "number of attributes allowed in credential")

	if err := prepareBlindSignCmd.MarkPersistentFlagRequired("key"); err != nil {
		panic(err)
	}
	if err := prepareBlindSignCmd.MarkPersistentFlagRequired("priv"); err != nil {
		panic(err)
	}
	if err := prepareBlindSignCmd.MarkPersistentFlagRequired("attributes"); err != nil {
		panic(err)
	}

	rootCmd.AddCommand(prepareBlindSignCmd)
}

func runPrepareBlindSign(cmd *cobra.Command, args []string) {
	pubkey := parseElGamalPublic(rawPublicKeyPrepareBlind)
	publicAttributes := parseAttributes(rawPublicAttributesPrepareBlind)
	privateAttributes := parseAttributes(rawPrivateAttributesPrepareBlind)

	params, err := coconutGo.Setup(numberOfAttributesPrepare)
	if err != nil {
		panic(err)
	}

	lambda, err := coconut.PrepareBlindSign(
		params,
		&pubkey,
		privateAttributes,
		publicAttributes,
	)
	if err != nil {
		panic(err)
	}

	encoded := base64.StdEncoding.EncodeToString(lambda.Bytes())
	fmt.Printf("%v\n", encoded)
}
