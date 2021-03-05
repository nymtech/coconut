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

package coconut

import (
	"errors"
	"gitlab.nymte.ch/nym/coconut/coconutGo/utils"
)

func (sig *Signature) MarshalBinary() (data []byte, err error) {
	sig1Bytes := utils.G1JacobianToByteSlice(&sig.sig1)
	sig2Bytes := utils.G1JacobianToByteSlice(&sig.sig2)

	return append(sig1Bytes, sig2Bytes...), nil
}

func (sig *Signature) UnmarshalBinary(data []byte) error {
	if len(data) != 96 {
		return errors.New("tried to deserialize signature with bytes of invalid length")
	}

	sig1, err := utils.G1JacobianFromBytes(data[:48])
	if err != nil {
		return err
	}

	sig2, err := utils.G1JacobianFromBytes(data[48:])
	if err != nil {
		return err
	}

	sig.sig1 = sig1
	sig.sig2 = sig2
	return nil
}

func (blindedSig *BlindedSignature) MarshalBinary() (data []byte, err error) {
	hBytes := utils.G1JacobianToByteSlice(&blindedSig.sig1)
	cTildeBytes, err := blindedSig.sig2.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return append(hBytes, cTildeBytes...), nil
}

func (blindedSig *BlindedSignature) UnmarshalBinary(data []byte) error {
	if len(data) != 144 {
		return errors.New("tried to deserialize blinded signature with bytes of invalid length")
	}

	h, err := utils.G1JacobianFromBytes(data[:48])
	if err != nil {
		return err
	}

	if err := blindedSig.sig2.UnmarshalBinary(data[48:]); err != nil {
		return err
	}

	blindedSig.sig1 = h
	
	return nil
}
