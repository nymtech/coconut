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
	coconut "gitlab.nymte.ch/nym/coconut/coconutGo/scheme"
)

var (
	aggregateKeysCmd = &cobra.Command{
		Use:   "aggregate-keys [--keys signers-verification-keys] [--indices key-indices]",
		Short: "Aggregates the provided coconut threshold keys",
		Run:   runAggregateKeys,
	}
	rawKeys  string
	rawKeyIndices string
)

func init() {
	aggregateKeysCmd.PersistentFlags().StringVar(&rawKeys, "keys", "", "Chosen verification keys of the authorities")
	aggregateKeysCmd.PersistentFlags().StringVar(&rawKeyIndices, "indices", "", "Indices associated with the keys")

	if err := aggregateKeysCmd.MarkPersistentFlagRequired("keys"); err != nil {
		panic(err)
	}
	if err := aggregateKeysCmd.MarkPersistentFlagRequired("indices"); err != nil {
		panic(err)
	}

	rootCmd.AddCommand(aggregateKeysCmd)
}

func runAggregateKeys(cmd *cobra.Command, args []string) {
	keys := parseSignersVerification(rawKeys)
	indices := parseIndices(rawKeyIndices)


	aggr, err := coconut.AggregateVerificationKeys(keys, indices)
	if err != nil {
		panic(err)
	}

	encoded := base64.StdEncoding.EncodeToString(aggr.Bytes())
	fmt.Printf("%v\n", encoded)
}
