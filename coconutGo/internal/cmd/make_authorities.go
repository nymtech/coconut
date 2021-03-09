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
	attributesInit uint32
	threshold uint64
	numberOfAuthorities uint64
	makeAuthoritiesCmd = &cobra.Command{
		Use:   "init-issuers [-n number-of-auth] [-t threshold] [-a number-of-attributes]",
		Short: "Creates set of threshold coconut authorities",
		Run:   runInitIssuers,
	}
)

func init() {
	makeAuthoritiesCmd.PersistentFlags().Uint64VarP(&threshold, "threshold", "t", 1, "threshold value")
	makeAuthoritiesCmd.PersistentFlags().Uint64VarP(&numberOfAuthorities, "authorities", "n", 1, "number of signing authorities")
	makeAuthoritiesCmd.PersistentFlags().Uint32VarP(&attributesInit, "attributes", "a", 1, "number of attributes allowed in credential")
	if err := makeAuthoritiesCmd.MarkPersistentFlagRequired("threshold"); err != nil {
		panic(err)
	}
	if err := makeAuthoritiesCmd.MarkPersistentFlagRequired("authorities"); err != nil {
		panic(err)
	}
	if err := makeAuthoritiesCmd.MarkPersistentFlagRequired("attributes"); err != nil {
		panic(err)
	}

	rootCmd.AddCommand(makeAuthoritiesCmd)
}



func runInitIssuers(cmd *cobra.Command, args []string) {
	params, err := coconutGo.Setup(attributesInit)
	if err != nil {
		panic(err)
	}

	keys, err := coconut.TTPKeygen(params, threshold, numberOfAuthorities)
	if err != nil {
		panic(err)
	}

	// output line by line:
	// SK1
	// VK1
	// <blank>
	// SK2
	// VK2
	// ...
	for i := range keys {
		skEncoded := base64.StdEncoding.EncodeToString(keys[i].SecretKey.Bytes())
		vkEncoded := base64.StdEncoding.EncodeToString(keys[i].VerificationKey.Bytes())
		fmt.Printf("%v\n%v\n\n", skEncoded, vkEncoded)
	}
}