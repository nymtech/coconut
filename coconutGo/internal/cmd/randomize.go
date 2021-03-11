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
)

var (
	randomizeCmd = &cobra.Command{
		Use:   "randomize [--sig coconut-signature]",
		Short: "Randomizes the provided Coconut signature",
		Run:   runRandomizeCmd,
	}
	rawSignatureRandomize string
)


func init() {
	randomizeCmd.PersistentFlags().StringVar(&rawSignatureRandomize, "sig", "", "coconut signature")

	if err := randomizeCmd.MarkPersistentFlagRequired("sig"); err != nil {
		panic(err)
	}

	rootCmd.AddCommand(randomizeCmd)
}

func runRandomizeCmd(cmd *cobra.Command, args []string) {
	params, err := coconutGo.Setup(1)
	if err != nil {
		panic(err)
	}

	sig := parseSignature(rawSignatureRandomize)
	sigPrime, err := sig.Randomise(params)
	if err != nil {
		panic(err)
	}

	sigBytes := sigPrime.Bytes()
	encoded := base64.StdEncoding.EncodeToString(sigBytes[:])
	fmt.Printf("%v", encoded)
}