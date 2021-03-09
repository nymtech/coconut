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
)

var (
	initUserCmd = &cobra.Command{
		Use: "init-user",
		Short: "generates an ephemeral ElGamal keypair for a Coconut user",
		Run: runInitUser,
	}
)

func init() {
	rootCmd.AddCommand(initUserCmd)
}


func runInitUser(cmd *cobra.Command, args []string) {
	params, err := coconutGo.Setup(1)
	if err != nil {
		panic(err)
	}

	keys, err := elgamal.Keygen(params)
	if err != nil {
		panic(err)
	}

	// output line by line:
	// PrivateKey
	// PublicKey
	privBytes := keys.PrivateKey().Bytes()
	pubBytes := keys.PublicKey().Bytes()
	privEncoded := base64.StdEncoding.EncodeToString(privBytes[:])
	pubEncoded := base64.StdEncoding.EncodeToString(pubBytes[:])

	fmt.Printf("%v\n%v\n\n", privEncoded, pubEncoded)
}