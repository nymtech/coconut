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
	aggregateSigsCmd = &cobra.Command{
		Use:   "aggregate-sigs [--sigs signatures] [--indices key-indices]",
		Short: "Aggregates the provided coconut threshold signatures",
		Run:   runAggregateSigs,
	}
	rawSigs  string
	rawSigsInndices string
)

func init() {
	aggregateSigsCmd.PersistentFlags().StringVar(&rawSigs, "keys", "", "Chosen signatures to aggregate")
	aggregateSigsCmd.PersistentFlags().StringVar(&rawSigsInndices, "indices", "", "Indices associated with the signatures")

	if err := aggregateSigsCmd.MarkPersistentFlagRequired("keys"); err != nil {
		panic(err)
	}
	if err := aggregateSigsCmd.MarkPersistentFlagRequired("indices"); err != nil {
		panic(err)
	}

	rootCmd.AddCommand(aggregateSigsCmd)
}

func runAggregateSigs(cmd *cobra.Command, args []string) {
	sigs := parseSignatures(rawSigs)
	indices := parseIndices(rawSigsInndices)


	aggr, err := coconut.AggregateSignatures(sigs, indices)
	if err != nil {
		panic(err)
	}

	sigBytes := aggr.Bytes()
	encoded := base64.StdEncoding.EncodeToString(sigBytes[:])
	fmt.Printf("%v\n", encoded)
}
