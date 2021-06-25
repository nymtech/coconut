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

use bls12_381::{multi_miller_loop, G1Affine, G2Affine, G2Prepared, Scalar};
use coconut_rs::{
    aggregate_signature_shares, aggregate_verification_keys, blind_sign, elgamal_keygen,
    prepare_blind_sign, prove_credential, setup, ttp_keygen, verify_credential, Attribute,
    BlindedSignature, ElGamalKeyPair, Parameters, Signature, SignatureShare, VerificationKey,
};
use criterion::{criterion_group, criterion_main, Criterion};
use ff::Field;
use group::{Curve, Group};
use std::ops::Neg;

fn double_pairing(g11: &G1Affine, g21: &G2Affine, g12: &G1Affine, g22: &G2Affine) {
    let gt1 = bls12_381::pairing(&g11, &g21);
    let gt2 = bls12_381::pairing(&g12, &g22);
    assert_eq!(gt1, gt2)
}

fn multi_miller_pairing_affine(g11: &G1Affine, g21: &G2Affine, g12: &G1Affine, g22: &G2Affine) {
    let miller_loop_result = multi_miller_loop(&[
        (g11, &G2Prepared::from(*g21)),
        (&g12.neg(), &G2Prepared::from(*g22)),
    ]);
    assert!(bool::from(
        miller_loop_result.final_exponentiation().is_identity()
    ))
}

fn multi_miller_pairing_with_prepared(
    g11: &G1Affine,
    g21: &G2Prepared,
    g12: &G1Affine,
    g22: &G2Prepared,
) {
    let miller_loop_result = multi_miller_loop(&[(g11, &g21), (&g12.neg(), &g22)]);
    assert!(bool::from(
        miller_loop_result.final_exponentiation().is_identity()
    ))
}

// the case of being able to prepare G2 generator
fn multi_miller_pairing_with_semi_prepared(
    g11: &G1Affine,
    g21: &G2Affine,
    g12: &G1Affine,
    g22: &G2Prepared,
) {
    let miller_loop_result =
        multi_miller_loop(&[(g11, &G2Prepared::from(*g21)), (&g12.neg(), &g22)]);
    assert!(bool::from(
        miller_loop_result.final_exponentiation().is_identity()
    ))
}

fn produce_blinded_signatures(
    params: &Parameters,
    public_attributes: &[Attribute],
    private_attributes: &[Attribute],
    elgamal_keypair: &ElGamalKeyPair,
    threshold: u64,
    num_authorities: u64,
) -> (Vec<BlindedSignature>, Vec<VerificationKey>) {
    let blind_sign_request = prepare_blind_sign(
        params,
        &elgamal_keypair.public_key(),
        private_attributes,
        public_attributes,
    )
    .unwrap();
    // generate blinded signatures
    let mut blinded_signatures = Vec::new();

    let coconut_keypairs = ttp_keygen(&params, threshold, num_authorities).unwrap();

    for keypair in coconut_keypairs.iter() {
        let blinded_signature = blind_sign(
            params,
            &keypair.secret_key(),
            &elgamal_keypair.public_key(),
            &blind_sign_request,
            public_attributes,
        )
        .unwrap();
        blinded_signatures.push(blinded_signature)
    }

    let verification_keys: Vec<VerificationKey> = coconut_keypairs
        .iter()
        .map(|keypair| keypair.verification_key())
        .collect();

    (blinded_signatures, verification_keys)
}

fn unblind_prove_and_verify(
    params: &Parameters,
    public_attributes: &[Attribute],
    private_attributes: &[Attribute],
    blinded_signatures: &[BlindedSignature],
    verification_keys: &[VerificationKey],
    elgamal_keypair: &ElGamalKeyPair,
    num_authorities: u64,
) {
    // Unblind
    let unblinded_signatures: Vec<Signature> = blinded_signatures
        .iter()
        .map(|signature| signature.unblind(&elgamal_keypair.private_key()))
        .collect();
    // Aggregate signatures

    let signature_shares: Vec<SignatureShare> = unblinded_signatures
        .iter()
        .enumerate()
        .map(|(idx, signature)| SignatureShare::new(*signature, (idx + 1) as u64))
        .collect();

    let signature = aggregate_signature_shares(&signature_shares).unwrap();

    // Lets bench worse case, ie aggregating all
    let indices: Vec<u64> = (1..=num_authorities).collect();

    // aggregate verification keys
    let verification_key = aggregate_verification_keys(&verification_keys, Some(&indices)).unwrap();

    // Randomize credentials and generate any cryptographic material to verify them
    let theta =
        prove_credential(&params, &verification_key, &signature, &private_attributes).unwrap();

    // Verify credentials
    verify_credential(&params, &verification_key, &theta, &public_attributes);
}

struct BenchCase {
    num_authorities: u64,
    threshold_p: f32,
    num_public_attrs: u32,
    num_private_attrs: u32,
}

impl BenchCase {
    fn threshold(&self) -> u64 {
        (self.num_authorities as f32 * self.threshold_p).round() as u64
    }

    fn num_attrs(&self) -> u32 {
        self.num_public_attrs + self.num_private_attrs
    }
}

fn bench_e2e(c: &mut Criterion) {
    let params = setup(5).unwrap();

    let public_attributes = params.n_random_scalars(2);
    let private_attributes = params.n_random_scalars(3);

    let elgamal_keypair = elgamal_keygen(&params);

    c.bench_function("elgamal_keygen", |b| b.iter(|| elgamal_keygen(&params)));

    let cases = vec![
        BenchCase {
            num_authorities: 10,
            threshold_p: 0.5,
            num_public_attrs: 1,
            num_private_attrs: 0,
        },
        BenchCase {
            num_authorities: 10,
            threshold_p: 0.5,
            num_public_attrs: 2,
            num_private_attrs: 1,
        },
        BenchCase {
            num_authorities: 10,
            threshold_p: 0.5,
            num_public_attrs: 6,
            num_private_attrs: 4,
        },
        BenchCase {
            num_authorities: 100,
            threshold_p: 0.5,
            num_public_attrs: 1,
            num_private_attrs: 0,
        },
        BenchCase {
            num_authorities: 200,
            threshold_p: 0.5,
            num_public_attrs: 1,
            num_private_attrs: 0,
        },
    ];

    for case in cases {
        let (blinded_signatures, verification_keys) = produce_blinded_signatures(
            &params,
            &public_attributes,
            &private_attributes,
            &elgamal_keypair,
            case.threshold(),
            case.num_authorities,
        );

        c.bench_function(
            &format!(
                "produce_blinded_signatures_{}_authorities_{}_attributes",
                case.num_authorities,
                case.num_attrs()
            ),
            |b| {
                b.iter(|| {
                    produce_blinded_signatures(
                        &params,
                        &public_attributes,
                        &private_attributes,
                        &elgamal_keypair,
                        case.threshold(),
                        case.num_authorities,
                    )
                })
            },
        );

        unblind_prove_and_verify(
            &params,
            &public_attributes,
            &private_attributes,
            &blinded_signatures,
            &verification_keys,
            &elgamal_keypair,
            case.num_authorities,
        );

        c.bench_function(
            &format!(
                "unblind_prove_and_verify_{}_authorities_{}_attributes",
                case.num_authorities,
                case.num_attrs()
            ),
            |b| {
                b.iter(|| {
                    unblind_prove_and_verify(
                        &params,
                        &public_attributes,
                        &private_attributes,
                        &blinded_signatures,
                        &verification_keys,
                        &elgamal_keypair,
                        case.num_authorities,
                    )
                })
            },
        );
    }
}

fn bench_pairings(c: &mut Criterion) {
    let mut rng = rand::thread_rng();

    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    let r = Scalar::random(&mut rng);
    let s = Scalar::random(&mut rng);

    let g11 = (g1 * r).to_affine();
    let g21 = (g2 * s).to_affine();
    let g21_prep = G2Prepared::from(g21);

    let g12 = (g1 * s).to_affine();
    let g22 = (g2 * r).to_affine();
    let g22_prep = G2Prepared::from(g22);

    c.bench_function("double pairing", |b| {
        b.iter(|| double_pairing(&g11, &g21, &g12, &g22))
    });

    c.bench_function("multi miller in affine", |b| {
        b.iter(|| multi_miller_pairing_affine(&g11, &g21, &g12, &g22))
    });

    c.bench_function("multi miller with prepared g2", |b| {
        b.iter(|| multi_miller_pairing_with_prepared(&g11, &g21_prep, &g12, &g22_prep))
    });

    c.bench_function("multi miller with semi-prepared g2", |b| {
        b.iter(|| multi_miller_pairing_with_semi_prepared(&g11, &g21, &g12, &g22_prep))
    });
}

criterion_group!(benches, bench_pairings);
criterion_group!(e2e, bench_e2e);
criterion_main!(benches, e2e);
