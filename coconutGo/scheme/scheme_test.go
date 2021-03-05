package coconut

import (
	"github.com/consensys/gurvy/bls381"
	"github.com/stretchr/testify/assert"
	"gitlab.nymte.ch/nym/coconut/coconutGo"
	"gitlab.nymte.ch/nym/coconut/coconutGo/elgamal"
	"gitlab.nymte.ch/nym/coconut/coconutGo/utils"
	"math/big"
	"testing"
)

func unwrapError(err error) {
	if err != nil {
		panic(err)
	}
}

func BenchmarkDoublePairing(b *testing.B) {
	g1jac, g2jac, _, _ := bls381.Generators()
	params := coconutGo.Setup(1)

	r, _ := params.RandomScalar()
	s, _ := params.RandomScalar()

	g11 := utils.G1ScalarMul(&g1jac, &r)
	g21 := utils.G2ScalarMul(&g2jac, &s)

	g12 := utils.G1ScalarMul(&g1jac, &s)
	g22 := utils.G2ScalarMul(&g2jac, &r)

	g11A := utils.ToG1Affine(&g11)
	g21A := utils.ToG2Affine(&g21)
	g12A := utils.ToG1Affine(&g12)
	g22A := utils.ToG2Affine(&g22)

	for i := 0; i < b.N; i++ {
		gt1, err := bls381.Pair([]bls381.G1Affine{g11A}, []bls381.G2Affine{g21A})
		if err != nil {
			panic(err)
		}
		gt2, err := bls381.Pair([]bls381.G1Affine{g12A}, []bls381.G2Affine{g22A})
		if err != nil {
			panic(err)
		}
		if gt1 != gt2 {
			panic(false)
		}
	}

}

var pairCheckGlobal bool

func BenchmarkMiller(b *testing.B) {
	g1jac, g2jac, _, _ := bls381.Generators()
	params := coconutGo.Setup(1)

	r, _ := params.RandomScalar()
	s, _ := params.RandomScalar()

	g11 := utils.G1ScalarMul(&g1jac, &r)
	g21 := utils.G2ScalarMul(&g2jac, &s)

	g12 := utils.G1ScalarMul(&g1jac, &s)
	g22 := utils.G2ScalarMul(&g2jac, &r)

	g11A := utils.ToG1Affine(&g11)
	g21A := utils.ToG2Affine(&g21)
	g22A := utils.ToG2Affine(&g22)

	var g12Neg bls381.G1Affine
	g12Neg.FromJacobian(&g12)
	g12Neg.Neg(&g12Neg)

	for i := 0; i < b.N; i++ {
		pairCheck, err := bls381.PairingCheck(
			[]bls381.G1Affine{g11A, g12Neg},
			[]bls381.G2Affine{g21A, g22A},
		)
		pairCheckGlobal = pairCheck
		if err != nil || pairCheckGlobal != true {
			panic(err)
		}
	}
}


// make sure credential created in rust on public attributes verifies in go
func TestRustSignatureOnPublic(t *testing.T) {
	params := coconutGo.Setup(2)

	xBytes := []byte{188, 179, 7, 116, 227, 238, 248, 132, 112, 18, 3, 169, 6, 179, 97, 202, 90, 175, 245, 181, 102, 111, 238, 21, 91, 248, 205, 117, 13, 244, 239, 30}
	yBytes1 := []byte{59, 59, 50, 96, 127, 192, 126, 148, 208, 89, 47, 81, 175, 184, 175, 163, 255, 93, 145, 66, 37, 38, 137, 233, 16, 101, 223, 25, 196, 150, 12, 6}
	yBytes2 := []byte{47, 186, 245, 60, 39, 101, 96, 106, 149, 202, 205, 169, 179, 29, 13, 55, 225, 63, 127, 70, 105, 173, 30, 23, 216, 16, 81, 106, 156, 97, 156, 57}
	attributeBytes1 := []byte{77, 93, 249, 147, 37, 254, 148, 71, 217, 189, 128, 231, 23, 17, 178, 0, 88, 171, 103, 255, 116, 241, 240, 13, 249, 101, 60, 165, 106, 85, 141, 102}
	attributeBytes2 := []byte{8, 102, 247, 34, 240, 77, 244, 180, 51, 93, 10, 204, 42, 51, 179, 107, 29, 18, 89, 109, 10, 183, 40, 52, 242, 26, 98, 59, 149, 4, 117, 7}
	sig1Bytes := []byte{137, 174, 188, 82, 83, 176, 198, 15, 91, 73, 114, 236, 249, 63, 210, 122, 102, 126, 249, 239, 203, 229, 70, 142, 26, 233, 183, 165, 169, 12, 76, 241, 170, 248, 131, 224, 197, 48, 32, 167, 30, 221, 169, 93, 138, 248, 226, 136}
	sig2Bytes := []byte{183, 255, 211, 2, 92, 75, 233, 106, 154, 58, 68, 42, 114, 239, 202, 123, 8, 234, 25, 4, 134, 9, 60, 209, 182, 112, 153, 11, 67, 108, 153, 202, 1, 195, 253, 237, 71, 221, 116, 185, 238, 71, 14, 148, 12, 93, 92, 9}

	secretKey := SecretKey{
		ys : make([]big.Int, 2),
	}

	secretKey.x = utils.ScalarFromLittleEndian(xBytes)
	secretKey.ys[0] = utils.ScalarFromLittleEndian(yBytes1)
	secretKey.ys[1] = utils.ScalarFromLittleEndian(yBytes2)

	attributes := make([]*coconutGo.Attribute, 2)
	attributes1 := utils.ScalarFromLittleEndian(attributeBytes1)
	attributes2 := utils.ScalarFromLittleEndian(attributeBytes2)
	attributes[0] = &attributes1
	attributes[1] = &attributes2

	verificationKey := secretKey.VerificationKey(params)

	sig, err := Sign(params, &secretKey, attributes)
	unwrapError(err)

	assert.True(t, Verify(params, &verificationKey, attributes, &sig))
	assert.Equal(t, utils.G1JacobianToByteSlice(&sig.sig1), sig1Bytes)
	assert.Equal(t, utils.G1JacobianToByteSlice(&sig.sig2), sig2Bytes)
}

// make sure credential created in rust on public and private attributes verifies in go
func TestRustSignatureMixed(t *testing.T) {
	params := coconutGo.Setup(4)

	xBytes := []byte{129, 231, 41, 23, 186, 112, 18, 104, 123, 84, 242, 148, 216, 18, 199, 189, 42, 37, 13, 126, 147, 99, 135, 160, 236, 66, 112, 76, 127, 149, 6, 75}
	yBytes1 := []byte{117, 166, 140, 142, 151, 152, 141, 165, 250, 154, 146, 238, 124, 59, 136, 40, 192, 23, 252, 105, 221, 250, 246, 162, 209, 135, 172, 92, 52, 53, 249, 10}
	yBytes2 := []byte{100, 113, 104, 155, 209, 26, 11, 234, 68, 13, 76, 193, 21, 48, 209, 139, 24, 28, 171, 158, 22, 181, 19, 24, 65, 92, 25, 151, 143, 204, 163, 97}
	yBytes3 := []byte{245, 228, 244, 30, 54, 136, 7, 179, 134, 153, 201, 44, 67, 49, 13, 207, 49, 163, 45, 161, 58, 151, 227, 132, 199, 255, 165, 79, 8, 84, 251, 110}
	yBytes4 := []byte{90, 156, 236, 128, 234, 1, 234, 64, 147, 94, 141, 132, 179, 64, 145, 103, 206, 164, 55, 91, 159, 221, 162, 130, 210, 168, 106, 48, 196, 232, 145, 66}
	attributePubBytes1 := []byte{238, 154, 57, 68, 198, 209, 61, 75, 123, 174, 14, 115, 29, 193, 81, 90, 161, 197, 246, 2, 93, 216, 30, 83, 134, 133, 79, 48, 35, 10, 13, 33}
	attributePubBytes2 := []byte{66, 71, 175, 89, 157, 159, 134, 193, 33, 202, 139, 60, 30, 202, 142, 121, 111, 66, 58, 156, 22, 161, 125, 168, 83, 47, 57, 226, 80, 220, 58, 105}
	attributePrivBytes1 := []byte{164, 174, 81, 99, 185, 69, 230, 184, 175, 79, 111, 142, 65, 167, 8, 9, 54, 103, 109, 162, 120, 189, 96, 195, 72, 236, 126, 222, 88, 115, 89, 77}
	attributePrivBytes2 := []byte{226, 179, 29, 72, 185, 41, 217, 53, 205, 34, 176, 5, 152, 209, 63, 194, 170, 118, 49, 181, 83, 137, 78, 78, 188, 44, 83, 72, 62, 248, 234, 11}

	elgamalPrivBytes := []byte{236, 251, 98, 105, 133, 10, 109, 131, 128, 222, 54, 139, 198, 89, 206, 220, 143, 68, 79, 242, 238, 155, 128, 66, 188, 18, 110, 161, 135, 239, 186, 13}
	elgamalPubBytes := []byte{143, 3, 173, 2, 15, 74, 242, 106, 68, 99, 90, 25, 144, 46, 205, 23, 99, 101, 255, 135, 48, 240, 28, 244, 12, 217, 32, 25, 216, 120, 34, 113, 134, 251, 253, 179, 47, 217, 30, 186, 217, 203, 245, 18, 202, 81, 216, 211}

	hBytes := []byte{136, 28, 21, 82, 51, 163, 23, 118, 100, 76, 141, 150, 111, 15, 109, 222, 9, 148, 194, 152, 218, 25, 152, 152, 24, 155, 131, 201, 52, 190, 25, 76, 215, 153, 15, 109, 122, 5, 149, 6, 200, 23, 214, 124, 6, 83, 207, 165}
	blindedSig1Bytes := []byte{133, 74, 27, 120, 60, 0, 238, 176, 16, 165, 188, 146, 28, 34, 93, 27, 216, 5, 33, 146, 244, 187, 27, 192, 136, 102, 101, 169, 254, 69, 219, 143, 106, 98, 56, 109, 242, 246, 113, 128, 43, 215, 162, 225, 202, 229, 124, 196}
	blindedSig2Bytes := []byte{141, 78, 83, 127, 101, 158, 88, 144, 2, 175, 150, 226, 159, 81, 200, 161, 47, 147, 29, 252, 181, 72, 60, 136, 171, 46, 86, 69, 170, 198, 155, 223, 249, 21, 1, 65, 39, 192, 67, 170, 42, 174, 200, 105, 12, 45, 202, 234}

	sig2Bytes := []byte{165, 83, 211, 181, 221, 90, 196, 20, 152, 172, 54, 166, 242, 66, 157, 137, 188, 203, 127, 166, 158, 149, 39, 9, 153, 21, 234, 196, 140, 138, 148, 62, 216, 131, 247, 37, 51, 181, 110, 234, 79, 8, 200, 61, 173, 223, 221, 9}

	secretKey := SecretKey{
		ys : make([]big.Int, 4),
	}

	secretKey.x = utils.ScalarFromLittleEndian(xBytes)
	secretKey.ys[0] = utils.ScalarFromLittleEndian(yBytes1)
	secretKey.ys[1] = utils.ScalarFromLittleEndian(yBytes2)
	secretKey.ys[2] = utils.ScalarFromLittleEndian(yBytes3)
	secretKey.ys[3] = utils.ScalarFromLittleEndian(yBytes4)

	attributesPublic := make([]*coconutGo.Attribute, 2)
	attributesPub1 := utils.ScalarFromLittleEndian(attributePubBytes1)
	attributesPub2 := utils.ScalarFromLittleEndian(attributePubBytes2)
	attributesPublic[0] = &attributesPub1
	attributesPublic[1] = &attributesPub2

	attributesPrivate := make([]*coconutGo.Attribute, 2)
	attributesPriv1 := utils.ScalarFromLittleEndian(attributePrivBytes1)
	attributesPriv2 := utils.ScalarFromLittleEndian(attributePrivBytes2)
	attributesPrivate[0] = &attributesPriv1
	attributesPrivate[1] = &attributesPriv2

	h, err := utils.G1JacobianFromBytes(hBytes)
	unwrapError(err)

	blindedSig1, err := utils.G1JacobianFromBytes(blindedSig1Bytes)
	unwrapError(err)

	blindedSig2, err := utils.G1JacobianFromBytes(blindedSig2Bytes)
	unwrapError(err)

	blindedSig := BlindedSignature{
		sig1: h,
		sig2: elgamal.CiphertextFromRaw(blindedSig1, blindedSig2),
	}

	elgamalPriv := elgamal.PrivateKey{}
	if err := elgamalPriv.UnmarshalBinary(elgamalPrivBytes); err != nil {
		panic(err)
	}

	elgamalPub := elgamal.PublicKey{}
	if err := elgamalPub.UnmarshalBinary(elgamalPubBytes); err != nil {
		panic(err)
	}

	sig := blindedSig.Unblind(&elgamalPriv)

	verificationKey := secretKey.VerificationKey(params)

	assert.Equal(t, hBytes, utils.G1JacobianToByteSlice(&sig.sig1))
	assert.Equal(t, sig2Bytes, utils.G1JacobianToByteSlice(&sig.sig2))

	theta, err := ProveCredential(params, &verificationKey, &sig, attributesPrivate)
	unwrapError(err)

	assert.True(t, VerifyCredential(params, &verificationKey, &theta, attributesPublic))
}