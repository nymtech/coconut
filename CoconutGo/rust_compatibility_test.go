package CoconutGo

import (
	"github.com/consensys/gurvy/bls381/fr"
	"github.com/stretchr/testify/assert"
	"gitlab.nymte.ch/nym/coconut/CoconutGo/utils"
	"math/big"
	"testing"
)

func TestScalarSerialization(t *testing.T) {
	// test value, limbs and byte representation
	scalar := big.NewInt(42)

	expectedLimbs := fr.Element{
		395136991140,
		16706400699492528220,
		10895998725622488597,
		6239700025071827469,
	}

	expectedBytes := []byte{42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	expectedValue := "42"

	assert.Equal(t, expectedBytes, utils.ReverseBytes(scalar.Bytes()))
	assert.Equal(t, expectedValue, scalar.String())

	var frScalar fr.Element
	frScalar.SetBigInt(scalar)

	assert.Equal(t, expectedLimbs, frScalar)


	// some exponentiation
	scalar512 := big.NewInt(512)
	var res big.Int
	// 42^512 mod o
	res.Mul(scalar, scalar512)
	res.Mod(&res, fr.Modulus())

	expectedLimbs = fr.Element{
		12744553619634797806,
		2812099285984544638,
		10023149335646001754,
		7871652299959646057,
	}
	expectedBytes = []byte{249, 153, 114, 33, 163, 49, 188, 167, 110, 39, 174, 124, 246, 13, 60, 19, 170, 123, 111, 95, 160, 195, 40, 158, 97, 19, 159, 91, 117, 144, 195, 112}
	expectedValue = "51004571234394176832463279876548201369249893565884470427882439455118619482617"

	assert.Equal(t, expectedBytes, utils.ReverseBytes(scalar.Bytes()))
	assert.Equal(t, expectedValue, scalar.String())

	var frRes fr.Element
	frScalar.SetBigInt(&res)

	assert.Equal(t, expectedLimbs, frRes)



	// 42
	// 42^512 mod order

}

