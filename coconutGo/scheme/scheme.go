// TODO: move/rename the file because its not idiomatic go

// TODOs:
/*
	- move params to other file because go is really bitchy about cyclic imports
	- change SVDW map to increment and check for rust compatibility
	- figure out which places should use Affine points rather than Jacobian
	- tests
	- move files around to more nicely deal with the cycles. having `coconutGo.Parameters` and `coconut.VerificationKey` uses in the same file looks disgusting
	- make comments notation consistent, i.e. either stick to g * r and g + h or g ^ r and g * h

*/

package coconut

import (
	"github.com/consensys/gurvy/bls381"
	"gitlab.nymte.ch/nym/coconut/coconutGo"
	"gitlab.nymte.ch/nym/coconut/coconutGo/elgamal"
	"gitlab.nymte.ch/nym/coconut/coconutGo/utils"
)

type Signature struct {
	sig1 bls381.G1Jac
	sig2 bls381.G1Jac
}

func (sig *Signature) Equal(other *Signature) bool {
	return utils.G1JacobianEqual(&sig.sig1, &other.sig1) && utils.G1JacobianEqual(&sig.sig2, &other.sig2)
}

type PartialSignature = Signature

type SignerIndex = uint64

type SignatureShare struct {
	signature Signature
	index     SignerIndex
}

func NewSignatureShare(signature Signature, index SignerIndex) SignatureShare {
	return SignatureShare{signature: signature, index: index}
}

func (sigShare *SignatureShare) Signature() *Signature {
	return &sigShare.signature
}

func (sigShare *SignatureShare) Index() SignerIndex {
	return sigShare.index
}

func (sig *Signature) Randomise(params *coconutGo.Parameters) (Signature, error) {
	r, err := params.RandomScalar()
	if err != nil {
		return Signature{}, err
	}

	sig1 := utils.G1ScalarMul(&sig.sig1, &r)
	sig2 := utils.G1ScalarMul(&sig.sig2, &r)

	return Signature{
		sig1: sig1,
		sig2: sig2,
	}, nil
}

type BlindedSignature struct {
	sig1 bls381.G1Jac
	sig2 elgamal.Ciphertext
}

func (blindedSig *BlindedSignature) Unblind(privateKey *elgamal.PrivateKey) Signature {
	return Signature{
		sig1: blindedSig.sig1,
		sig2: privateKey.Decrypt(&blindedSig.sig2),
	}
}

