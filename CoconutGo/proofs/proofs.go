package proofs

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/consensys/gurvy/bls381/fr"
	"math/big"
)

type ProofCmCs struct {
	challenge big.Int
	// rr
	response_random big.Int
	// rk
	response_keys []big.Int
	// rm
	response_attributes []big.Int
}


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

// do it the same way zcash is doing it in the rust library
func scalarFromBytesWide(bytes [64]byte) big.Int {
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

	fmt.Println("S fr", res)
	fmt.Println("S fr", res.String())
	fmt.Println("S fr", res.Bytes())
	var resBI big.Int
	//res.ToBigInt(&resBI)

	/*
	rust:
	s: 0x47761120765ceabc0a4bc3208cb1d2c267f6dfccbc1a2b3e7c99b29760622830
	32322818407927025939359778789648808124910768125310499785920609756176927828016
	A [8296047984791007455, 6749167863319126124, 990660411030559962, 3728100482992396851]
	s: [48, 40, 98, 96, 151, 178, 153, 124,
	62, 43, 26, 188, 204, 223, 246, 103,
	194, 210, 177, 140, 32, 195, 75, 10,
	188, 234, 92, 118, 32, 17, 118, 71]
	*/

	res.ToBigIntRegular(&resBI)
	fmt.Println("S", resBI.Bytes())

	return resBI
}

// ConstructChallenge construct a scalar challenge by hashing a number of elliptic curve points.
// note: this is slightly different from the reference python implementation
// as we omit the unnecessary string conversion. Instead we concatenate byte
// representations together and hash that.
// note2: G1 and G2 elements are using their compressed representations
// and as per the bls12-381 library all elements are using big-endian form
func constructChallenge(pointRepresentations [][]byte) big.Int {
	h := sha256.New()
	for _, pointRepresentation := range pointRepresentations {
		h.Write(pointRepresentation)
	}
	digest := h.Sum([]byte{})

	// TODO: this is only introduced for the initial compatibility with the rust library and
	// zcash's method for `from_bytes_wide` that does not seem to have a failing case.
	// In the future it should be replaced with something simpler that is implemented in both languages

	padSize := 64 - h.Size()
	var bytes [64]byte
	copy(bytes[64-padSize:], digest)

	return scalarFromBytesWide(bytes)

	//var res big.Int
	//res.SetBytes(digest)
	//
	//var res2 fr.Element
	//res2.SetBytes(digest)
	//fmt.Println(res2)
	//
	//fmt.Println(res2.String())
	//
	//
	//fmt.Println(res)
	//
	//var foo big.Int
	//mod := fp.Modulus()
	//foo.Mod(&res, mod)
	//
	//fmt.Println(foo)

	//return res

	/*
		fn compute_challenge<D, I, B>(iter: I) -> Scalar
		where
		    D: Digest,
		    I: Iterator<Item = B>,
		    B: AsRef<[u8]>,
		{
		    let mut h = D::new();
		    for point_representation in iter {
		        h.update(point_representation);
		    }
		    let digest = h.finalize();

		    // TODO: I don't like the 0 padding here (though it's what we've been using before,
		    // but we never had a security audit anyway...)
		    // instead we could maybe use the `from_bytes` variant and adding some suffix
		    // when computing the digest until we produce a valid scalar.
		    let mut bytes = [0u8; 64];
		    let pad_size = 64usize
		        .checked_sub(D::OutputSize::to_usize())
		        .unwrap_or_default();

		    bytes[pad_size..].copy_from_slice(&digest);

		    Scalar::from_bytes_wide(&bytes)
		}
	*/

	//return big.Int{}, nil
	//
	//csa := make([]string, len(pointRepresentations))
	//for i := range pointRepresentations {
	//	csa[i] = utils.ToCoconutString(pointRepresentations[i])
	//}
	//cs := strings.Join(csa, ",")
	//return utils.HashStringToBig(amcl.SHA256, cs)
}

// Produce witness - challenge * secret
func produceResponse(witness, challenge, secret *big.Int) big.Int {
	var tmp big.Int
	tmp.Mul(challenge, secret)

	var res big.Int
	// TODO: DOES IT NEED TO BE REDUCED MOD ORDER?
	res.Sub(witness, &tmp)

	return res
}

// note: it's caller's responsibility to ensure len(witnesses) = len(secrets)
func produceResponses(witnesses []*big.Int, challenge *big.Int, secrets []*big.Int) []big.Int {
	responses := make([]big.Int, len(witnesses))
	for i := 0; i < len(witnesses); i++ {
		responses[i] = produceResponse(witnesses[i], challenge, secrets[i])
	}
	return responses
}

/*





impl ProofCmCs {
    /// Construct proof of correctness of the ciphertexts and the commitment.
    pub(crate) fn construct<R: RngCore + CryptoRng>(
        params: &mut Parameters<R>,
        pub_key: &elgamal::PublicKey,
        ephemeral_keys: &[elgamal::EphemeralKey],
        commitment: &G1Projective,
        blinding_factor: &Scalar,
        private_attributes: &[Attribute],
        public_attributes: &[Attribute],
    ) -> Self {
        // note: this is only called from `prepare_blind_sign` that already checks
        // whether private attributes are non-empty and whether we don't have too many
        // attributes in total to sign.
        // we also know, due to the single call place, that ephemeral_keys.len() == private_attributes.len()

        // witness creation

        let witness_blinder = params.random_scalar();
        let witness_keys = params.n_random_scalars(ephemeral_keys.len());
        let witness_attributes =
            params.n_random_scalars(private_attributes.len() + public_attributes.len());

        // make h
        let h = hash_g1(commitment.to_bytes());

        // witnesses commitments
        let g1 = params.gen1();
        let hs_bytes = params
            .gen_hs()
            .iter()
            .map(|h| h.to_bytes())
            .collect::<Vec<_>>();

        // TODO NAMING: Aw, Bw, Cw.... ?
        // Aw[i] = (wk[i] * g1)
        let Aw_bytes = witness_keys
            .iter()
            .map(|wk_i| g1 * wk_i)
            .map(|witness| witness.to_bytes())
            .collect::<Vec<_>>();

        // Bw[i] = (wm[i] * h) + (wk[i] * gamma)
        let Bw_bytes = witness_keys
            .iter()
            .zip(witness_attributes.iter())
            .map(|(wk_i, wm_i)| pub_key * wk_i + h * wm_i)
            .map(|witness| witness.to_bytes())
            .collect::<Vec<_>>();

        // Cw = (wr * g1) + (wm[0] * hs[0]) + ... + (wm[i] * hs[i])
        let commitment_attributes = g1 * witness_blinder
            + witness_attributes
                .iter()
                .zip(params.gen_hs().iter())
                .map(|(wm_i, hs_i)| hs_i * wm_i)
                .sum::<G1Projective>();

        // challenge ([g1, g2, cm, h, Cw]+hs+Aw+Bw)
        let challenge = compute_challenge::<ChallengeDigest, _, _>(
            std::iter::once(params.gen1().to_bytes().as_ref())
                .chain(std::iter::once(params.gen2().to_bytes().as_ref()))
                .chain(std::iter::once(commitment.to_bytes().as_ref()))
                .chain(std::iter::once(h.to_bytes().as_ref()))
                .chain(std::iter::once(commitment_attributes.to_bytes().as_ref()))
                .chain(hs_bytes.iter().map(|hs| hs.as_ref()))
                .chain(Aw_bytes.iter().map(|aw| aw.as_ref()))
                .chain(Bw_bytes.iter().map(|bw| bw.as_ref())),
        );

        // responses
        let response_blinder = produce_response(&witness_blinder, &challenge, &blinding_factor);

        // TODO: maybe make `produce_responses` take an iterator instead?
        let response_keys = produce_responses(&witness_keys, &challenge, ephemeral_keys);
        let response_attributes = produce_responses(
            &witness_attributes,
            &challenge,
            &private_attributes
                .iter()
                .chain(public_attributes.iter())
                .collect::<Vec<_>>(),
        );

        ProofCmCs {
            challenge,
            response_random: response_blinder,
            response_keys,
            response_attributes,
        }
    }

    pub(crate) fn verify<R>(
        &self,
        params: &Parameters<R>,
        pub_key: &elgamal::PublicKey,
        commitment: &G1Projective,
        attributes_ciphertexts: &[elgamal::Ciphertext],
    ) -> bool {
        if self.response_keys.len() != attributes_ciphertexts.len() {
            return false;
        }

        // recompute h
        let h = hash_g1(commitment.to_bytes());

        // recompute witnesses commitments

        let g1 = params.gen1();
        let hs_bytes = params
            .gen_hs()
            .iter()
            .map(|h| h.to_bytes())
            .collect::<Vec<_>>();

        // Aw[i] = (c * c1[i]) + (rk[i] * g1)
        // TODO NAMING: Aw, Bw...
        let Aw_bytes = attributes_ciphertexts
            .iter()
            .map(|ciphertext| ciphertext.c1())
            .zip(self.response_keys.iter())
            .map(|(c1, res_attr)| c1 * self.challenge + g1 * res_attr)
            .map(|witness| witness.to_bytes())
            .collect::<Vec<_>>();

        // Bw[i] = (c * c2[i]) + (rk[i] * gamma) + (rm[i] * h)
        let Bw_bytes = izip!(
            attributes_ciphertexts
                .iter()
                .map(|ciphertext| ciphertext.c2()),
            self.response_keys.iter(),
            self.response_attributes.iter()
        )
        .map(|(c2, res_key, res_attr)| c2 * self.challenge + pub_key * res_key + h * res_attr)
        .map(|witness| witness.to_bytes())
        .collect::<Vec<_>>();

        // Cw = (cm * c) + (rr * g1) + (rm[0] * hs[0]) + ... + (rm[n] * hs[n])
        let commitment_attributes = commitment * self.challenge
            + g1 * self.response_random
            + self
                .response_attributes
                .iter()
                .zip(params.gen_hs().iter())
                .map(|(res_attr, hs)| hs * res_attr)
                .sum::<G1Projective>();

        // compute the challenge prime ([g1, g2, cm, h, Cw]+hs+Aw+Bw)
        let challenge = compute_challenge::<ChallengeDigest, _, _>(
            std::iter::once(params.gen1().to_bytes().as_ref())
                .chain(std::iter::once(params.gen2().to_bytes().as_ref()))
                .chain(std::iter::once(commitment.to_bytes().as_ref()))
                .chain(std::iter::once(h.to_bytes().as_ref()))
                .chain(std::iter::once(commitment_attributes.to_bytes().as_ref()))
                .chain(hs_bytes.iter().map(|hs| hs.as_ref()))
                .chain(Aw_bytes.iter().map(|aw| aw.as_ref()))
                .chain(Bw_bytes.iter().map(|bw| bw.as_ref())),
        );

        challenge == self.challenge
    }
}

*/

type ProofKappaNu struct {
	// c
	challenge big.Int

	// rm
	response_attributes []big.Int

	// rt
	response_blinder big.Int
}
