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

package utils

import (
	"crypto/sha256"
	"gitlab.nymte.ch/nym/coconut/coconutGo"
	"gitlab.nymte.ch/nym/coconut/coconutGo/utils"
)

// TODO: perhaps this could go into the main library package?
func HashToScalar(msg []byte) coconutGo.Attribute {
	h := sha256.New()
	h.Write(msg)
	digest := h.Sum([]byte{})

	padSize := 64 - h.Size()
	var bytes [64]byte
	copy(bytes[64-padSize:], digest)

	return utils.ScalarFromBytesWide(bytes)
}
