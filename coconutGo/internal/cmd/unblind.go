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
	unblindCmd = &cobra.Command{
		Use:   "unblind [--sig blinded-signature] [--key elgamal-private-key]",
		Short: "Unblinds the provided Coconut signature",
		Run:   runUnblindCmd,
	}
	rawPrivateKeyUnblind string
	rawBlindedSignature string
)

func parseBlindedSignature(raw string) coconut.BlindedSignature {
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		panic("failed to decode provided blinded signature!")
	}
	var rawBytes [144]byte
	copy(rawBytes[:], decoded)
	
	sig, err := coconut.BlindedSignatureFromBytes(rawBytes)
	if err != nil {
		panic("failed to recover provided blinded signature!")
	}
	return sig
}

func init() {
	unblindCmd.PersistentFlags().StringVar(&rawPrivateKeyUnblind, "key", "", "elgamal private key")
	unblindCmd.PersistentFlags().StringVar(&rawBlindedSignature, "sig", "", "blinded signature")

	if err := unblindCmd.MarkPersistentFlagRequired("sig"); err != nil {
		panic(err)
	}
	if err := unblindCmd.MarkPersistentFlagRequired("key"); err != nil {
		panic(err)
	}

	rootCmd.AddCommand(unblindCmd)
}

func runUnblindCmd(cmd *cobra.Command, args []string) {
	privateKey := parseElGamalPrivate(rawPrivateKeyUnblind)
	blindedSig := parseBlindedSignature(rawBlindedSignature)
	
	sig := blindedSig.Unblind(&privateKey)

	sigBytes := sig.Bytes()
	encoded := base64.StdEncoding.EncodeToString(sigBytes[:])
	fmt.Printf("%v\n", encoded)
}