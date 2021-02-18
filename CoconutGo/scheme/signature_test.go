package coconut

import (
	"github.com/stretchr/testify/assert"
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
