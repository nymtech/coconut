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
	proveCmd = &cobra.Command{
		Use:   "prove [--sig signature] [--key aggregated-verification-key] [--priv private-attributes] [-a number-of-attributes]",
		Short: "Proves the provided Coconut signature",
		Run:   runProveCmd,
	}
	numberOfAttributesProve uint32
	rawPrivateAttributesProve string
	rawSignatureProve string
	rawKeyProve string
)


func init() {
	proveCmd.PersistentFlags().Uint32VarP(&numberOfAttributesProve, "attributes", "a", 1, "number of attributes allowed in credential")
	proveCmd.PersistentFlags().StringVar(&rawPrivateAttributesProve, "priv", "", "space separated private attributes to prove")
	proveCmd.PersistentFlags().StringVar(&rawSignatureProve, "sig", "", "aggregated coconut signature")
	proveCmd.PersistentFlags().StringVar(&rawKeyProve, "key", "", "aggregated verification key of the signers")

	if err := proveCmd.MarkPersistentFlagRequired("sig"); err != nil {
		panic(err)
	}
	if err := proveCmd.MarkPersistentFlagRequired("key"); err != nil {
		panic(err)
	}
	if err := proveCmd.MarkPersistentFlagRequired("priv"); err != nil {
		panic(err)
	}
	if err := proveCmd.MarkPersistentFlagRequired("attributes"); err != nil {
		panic(err)
	}

	rootCmd.AddCommand(proveCmd)
}

func runProveCmd(cmd *cobra.Command, args []string) {
	privateAttributes := parseAttributes(rawPrivateAttributesProve)
	sig := parseSignature(rawSignatureProve)
	vk := parseSignerVerificationKey(rawKeyProve)

	params, err := coconutGo.Setup(numberOfAttributesPrepare)
	if err != nil {
		panic(err)
	}

	theta, err := coconut.ProveCredential(params, &vk, &sig, privateAttributes)
	if err != nil {
		panic(err)
	}

	encoded := base64.StdEncoding.EncodeToString(theta.Bytes())
	fmt.Printf("%v\n", encoded)
}