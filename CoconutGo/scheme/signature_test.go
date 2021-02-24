package coconut

import (
	"github.com/consensys/gurvy/bls381"
	"github.com/stretchr/testify/assert"
	. "gitlab.nymte.ch/nym/coconut/CoconutGo"
	"gitlab.nymte.ch/nym/coconut/CoconutGo/utils"
	"testing"
)

func unwrapError(err error) {
	if err != nil {
		panic(err)
	}
}

func TestVerificationOnTwoPublicAttributes(t *testing.T) {
	params, err := Setup(2)
	unwrapError(err)

	attributes, err := params.NRandomScalars(2)
	unwrapError(err)

	keypair1, err := Keygen(params)
	unwrapError(err)

	keypair2, err := Keygen(params)
	unwrapError(err)

	sig1, err := Sign(params, &keypair1.secretKey, attributes)
	unwrapError(err)

	sig2, err := Sign(params, &keypair2.secretKey, attributes)
	unwrapError(err)

	assert.True(t, Verify(params, &keypair1.verificationKey, attributes, &sig1))
	assert.False(t, Verify(params, &keypair2.verificationKey, attributes, &sig1))
	assert.False(t, Verify(params, &keypair1.verificationKey, attributes, &sig2))
}

/*
fn verification_on_two_public_attributes() {
        let rng = OsRng;

        let mut params = Parameters::new(rng, 2).unwrap();
        let attributes = params.n_random_scalars(2);

        let keypair1 = keygen(&mut params);
        let keypair2 = keygen(&mut params);
        let sig1 = sign(&mut params, &keypair1.secret_key, &attributes).unwrap();
        let sig2 = sign(&mut params, &keypair2.secret_key, &attributes).unwrap();

        assert!(verify(
            &params,
            &keypair1.verification_key,
            &attributes,
            &sig1,
        ));

        assert!(!verify(
            &params,
            &keypair2.verification_key,
            &attributes,
            &sig1,
        ));

        assert!(!verify(
            &params,
            &keypair1.verification_key,
            &attributes,
            &sig2,
        ));
    }
 */

func BenchmarkDoublePairing(b *testing.B) {
	g1jac, g2jac, _, _ := bls381.Generators()
	params, err := Setup(1)
	if err != nil {
		panic(err)
	}

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
	params, err := Setup(1)
	if err != nil {
		panic(err)
	}

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