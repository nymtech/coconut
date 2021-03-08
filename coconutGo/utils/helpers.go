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
	"crypto"
	"encoding/binary"
	"errors"
	"github.com/consensys/gurvy/bls381"
	"github.com/consensys/gurvy/bls381/fp"
	"github.com/consensys/gurvy/bls381/fr"
	_ "golang.org/x/crypto/sha3"
	"io"
	"math/big"
)

// R^2 = 2^512 mod q
var R2 = fr.Element{
	14526898881837571181,
	3129137299524312099,
	419701826671360399,
	524908885293268753,
}

// R^3 = 2^768 mod q
var R3 = fr.Element{
	14279814937963099055,
	1963020886675057040,
	8345518043873801240,
	7938258146690806761,
}

// B = 4, i.e. the curve coefficient
var B = fp.Element{
	12260768510540316659,
	6038201419376623626,
	5156596810353639551,
	12813724723179037911,
	10288881524157229871,
	708830206584151678,
}

func HashToG1(msg []byte) bls381.G1Affine {
	return incrementAndCheck(msg)
}

// Attempts to deserialize an uncompressed element, not checking if the
// element is in the correct subgroup.
// basically copied code from `func (p *G1Affine) SetBytes(buf []byte) (int, error)`
// but without the subgroup check
func g1AffineFromBytesUnchecked(bytes []byte) (bls381.G1Affine, error) {
	if len(bytes) < bls381.SizeOfG1AffineCompressed {
		return bls381.G1Affine{}, io.ErrShortBuffer
	}

	// recover flags
	compressionFlagSet := ((bytes[0] >> 7) & 1) == 1
	infinityFlagSet := ((bytes[0] >> 6) & 1) == 1
	largest := ((bytes[0] >> 5) & 1) == 1

	// first bit must be set - otherwise it implies uncompressed form (i.e. 96 bytes)
	// second bit must not be set - otherwise it implies the point at infinity
	if !compressionFlagSet || infinityFlagSet {
		return bls381.G1Affine{}, io.ErrShortBuffer
	}

	var p bls381.G1Affine

	originalVal := bytes[0]
	// mask away the flags
	bytes[0] &= 0b0001_1111

	p.X.SetBytes(bytes[0 : 0+fp.Bytes])

	// solve the curve equation to compute Y (y = sqrt(x^3 + 4))
	var YSquared, Y fp.Element

	YSquared.Square(&p.X).Mul(&YSquared, &p.X)
	YSquared.Add(&YSquared, &B)
	if Y.Sqrt(&YSquared) == nil {
		return bls381.G1Affine{}, errors.New("invalid compressed coordinate: square root doesn't exist")
	}

	if Y.LexicographicallyLargest() {
		// Y ">" -Y
		if !largest {
			Y.Neg(&Y)
		}
	} else {
		// Y "<=" -Y
		if largest {
			Y.Neg(&Y)
		}
	}

	p.Y = Y

	// restore flags
	bytes[0] = originalVal

	return p, nil
}

func incrementAndCheck(msg []byte) bls381.G1Affine {
	// reason for sha3 384 is for the 48 bytes output and it's a good enough solution
	// for the temporary use it has
	h := crypto.SHA3_384.New()

	ctr := uint64(0)
	for {
		ctrBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(ctrBytes, ctr)

		h.Write(msg)
		h.Write(ctrBytes)
		digest := h.Sum([]byte{})
		h.Reset()

		ctr += 1

		p, err := g1AffineFromBytesUnchecked(digest)
		if err != nil {
			continue
		} else {
			p.ClearCofactor(&p)
			return p
		}
	}
}

func ReverseBytes(bytes []byte) []byte {
	bytesNew := make([]byte, len(bytes))
	for i := 0; i < len(bytes); i++ {
		bytesNew[i] = bytes[len(bytes)-i-1]
	}
	return bytesNew
}

// do it the same way zcash is doing it in the rust library
func ScalarFromBytesWide(bytes [64]byte) big.Int {
	var d0 fr.Element
	var d1 fr.Element
	// recover limbs

	d0[0] = binary.LittleEndian.Uint64(bytes[0:8])
	d0[1] = binary.LittleEndian.Uint64(bytes[8:16])
	d0[2] = binary.LittleEndian.Uint64(bytes[16:24])
	d0[3] = binary.LittleEndian.Uint64(bytes[24:32])

	d1[0] = binary.LittleEndian.Uint64(bytes[32:40])
	d1[1] = binary.LittleEndian.Uint64(bytes[40:48])
	d1[2] = binary.LittleEndian.Uint64(bytes[48:56])
	d1[3] = binary.LittleEndian.Uint64(bytes[56:64])

	// Convert to Montgomery form
	// d0 * R2 + d1 * R3
	var t1 fr.Element
	t1.Mul(&d0, &R2)

	var t2 fr.Element
	t2.Mul(&d1, &R3)

	var res fr.Element
	res.Add(&t1, &t2)

	var resBI big.Int
	res.ToBigIntRegular(&resBI)

	return resBI
}

func ScalarToLittleEndian(scalar *big.Int) [fr.Limbs * 8]byte {
	var frScalar fr.Element
	// ensure correct order and width
	frScalar.SetBigInt(scalar)
	scalarBytes := frScalar.Bytes()

	var out [fr.Limbs * 8]byte
	for i := 0; i < fr.Limbs*8; i++ {
		out[fr.Limbs*8-1-i] = scalarBytes[i]
	}

	return out
}

// TODO: this is not checking for correct scalar...
func ScalarFromLittleEndian(bytes []byte) big.Int {
	var s big.Int

	s.SetBytes(ReverseBytes(bytes))
	return s
}

func DeserializeScalarVec(expectedLen uint64, bytes []byte) ([]big.Int, error) {
	if len(bytes) != int(expectedLen)*32 {
		return nil, errors.New("tried to deserialize scalar vector with inconsistent number of bytes")
	}

	out := make([]big.Int, expectedLen)
	for i := 0; i < int(expectedLen); i++ {
		s := ScalarFromLittleEndian(bytes[i*32 : (i+1)*32])
		out[i] = s
	}

	return out, nil
}

func ToG1Affine(jac *bls381.G1Jac) bls381.G1Affine {
	var res bls381.G1Affine
	res.FromJacobian(jac)
	return res
}

func ToG1Jacobian(aff *bls381.G1Affine) bls381.G1Jac {
	var res bls381.G1Jac
	res.FromAffine(aff)
	return res
}

func ToG2Affine(jac *bls381.G2Jac) bls381.G2Affine {
	var res bls381.G2Affine
	res.FromJacobian(jac)
	return res
}

func G1AffineToByteSlice(p *bls381.G1Affine) []byte {
	pBytes := p.Bytes()
	return pBytes[:]
}

func G1JacobianToByteSlice(p *bls381.G1Jac) []byte {
	pAff := ToG1Affine(p)
	return G1AffineToByteSlice(&pAff)
}

func G2JacobianToByteSlice(p *bls381.G2Jac) []byte {
	pAff := ToG2Affine(p)
	pAffBytes := pAff.Bytes()
	return pAffBytes[:]
}

func G1JacobianFromBytes(bytes []byte) (bls381.G1Jac, error) {
	var pAff bls381.G1Affine
	_, err := pAff.SetBytes(bytes)
	if err != nil {
		return bls381.G1Jac{}, err
	}

	var p bls381.G1Jac
	p.FromAffine(&pAff)

	return p, nil
}

func G2JacobianFromBytes(bytes []byte) (bls381.G2Jac, error) {
	var pAff bls381.G2Affine
	_, err := pAff.SetBytes(bytes)
	if err != nil {
		return bls381.G2Jac{}, err
	}

	var p bls381.G2Jac
	p.FromAffine(&pAff)

	return p, nil
}
