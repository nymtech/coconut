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
	verifyCmd = &cobra.Command{
		Use:   "verify [--key aggregated-verification-key] [--theta credential-proof] [--pub public-attributes] [-a number-of-attributes]",
		Short: "Verifies the constructed coconut credential",
		Run:   runVerifyCmd,
	}
	numberOfAttributesVerify  uint32
	rawPublicAttributesVerify string
	rawTheta                  string
	rawKeyVerify              string
)

func init() {
	verifyCmd.PersistentFlags().Uint32VarP(&numberOfAttributesVerify, "attributes", "a", 1, "number of attributes allowed in credential")
	verifyCmd.PersistentFlags().StringVar(&rawPublicAttributesVerify, "pub", "", "space separated private attributes to prove")
	verifyCmd.PersistentFlags().StringVar(&rawKeyVerify, "key", "", "aggregated verification key of the signers")
	verifyCmd.PersistentFlags().StringVar(&rawTheta, "theta", "", "proof of the credential")

	if err := verifyCmd.MarkPersistentFlagRequired("key"); err != nil {
		panic(err)
	}
	if err := verifyCmd.MarkPersistentFlagRequired("theta"); err != nil {
		panic(err)
	}
	if err := verifyCmd.MarkPersistentFlagRequired("pub"); err != nil {
		panic(err)
	}
	if err := verifyCmd.MarkPersistentFlagRequired("attributes"); err != nil {
		panic(err)
	}

	rootCmd.AddCommand(verifyCmd)
}

func parseTheta(raw string) coconut.Theta {
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		panic("failed to decode provided theta!")
	}
	theta, err := coconut.ThetaFromBytes(decoded)
	if err != nil {
		panic("failed to recover provided theta!")
	}
	return theta
}

func runVerifyCmd(cmd *cobra.Command, args []string) {
	publicAttributes := parseAttributes(rawPublicAttributesVerify)
	vk := parseSignerVerificationKey(rawKeyVerify)
	theta := parseTheta(rawTheta)

	params, err := coconutGo.Setup(numberOfAttributesVerify)
	if err != nil {
		panic(err)
	}

	ok := coconut.VerifyCredential(params, &vk, &theta, publicAttributes)
	if ok {
		fmt.Printf("ok")
	} else {
		fmt.Printf("failure")
	}
}
