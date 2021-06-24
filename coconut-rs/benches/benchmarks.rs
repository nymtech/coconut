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
    prepare_blind_sign, prove_credential, setup, ttp_keygen, verify_credential, Signature,
    SignatureShare, VerificationKey,
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

fn bench_e2e(c: &mut Criterion) {
    let params = setup(5).unwrap();

    let public_attributes = params.n_random_scalars(2);
    let private_attributes = params.n_random_scalars(3);

    let elgamal_keypair = elgamal_keygen(&params);

    c.bench_function("elgamal_keygen", |b| b.iter(|| elgamal_keygen(&params)));

    // generate commitment and encryption
    let blind_sign_request = prepare_blind_sign(
        &params,
        &elgamal_keypair.public_key(),
        &private_attributes,
        &public_attributes,
    ).unwrap();

    c.bench_function("prepare_blind_sign", |b| {
        b.iter(|| {
            prepare_blind_sign(
                &params,
                &elgamal_keypair.public_key(),
                &private_attributes,
                &public_attributes,
            ).unwrap();
        })
    });

    // generate_keys
    let coconut_keypairs = ttp_keygen(&params, 2, 3).unwrap();

    c.bench_function("ttp_keygen", |b| b.iter(|| ttp_keygen(&params, 2, 3)));

    let verification_keys: Vec<VerificationKey> = coconut_keypairs
        .iter()
        .map(|keypair| keypair.verification_key())
        .collect();

    // aggregate verification keys
    let verification_key = aggregate_verification_keys(&verification_keys, Some(&[1, 2, 3])).unwrap();

    c.bench_function("aggregate_verification_keys", |b| {
        b.iter(|| aggregate_verification_keys(&verification_keys, Some(&[1, 2, 3])))
    });

    // generate blinded signatures
    let mut blinded_signatures = Vec::new();

    // Store secret_key for later bench
    let secret_key = coconut_keypairs.first().unwrap().secret_key();

    for keypair in coconut_keypairs {
        let blinded_signature = blind_sign(
            &params,
            &keypair.secret_key(),
            &elgamal_keypair.public_key(),
            &blind_sign_request,
            &public_attributes,
        ).unwrap();
        blinded_signatures.push(blinded_signature)
    }

    c.bench_function("blind_sign", |b| {
        b.iter(|| {
            blind_sign(
                &params,
                &secret_key,
                &elgamal_keypair.public_key(),
                &blind_sign_request,
                &public_attributes,
            )
        })
    });

    // Unblind

    let unblinded_signatures: Vec<Signature> = blinded_signatures
        .iter()
        .map(|signature| signature.unblind(&elgamal_keypair.private_key()))
        .collect();

    c.bench_function("unblind", |b| {
        b.iter(|| {
            blinded_signatures
                .iter()
                .map(|signature| signature.unblind(&elgamal_keypair.private_key()))
                .collect::<Vec<Signature>>()
        })
    });

    // Aggregate signatures

    let signature_shares: Vec<SignatureShare> = unblinded_signatures
        .iter()
        .enumerate()
        .map(|(idx, signature)| SignatureShare::new(*signature, (idx + 1) as u64))
        .collect();

    let signature = aggregate_signature_shares(&signature_shares).unwrap();

    c.bench_function("aggregate_signature_shares", |b| {
        b.iter(|| aggregate_signature_shares(&signature_shares))
    });

    // Randomize credentials and generate any cryptographic material to verify them
    let theta = prove_credential(&params, &verification_key, &signature, &private_attributes).unwrap();

    c.bench_function("prove_credential", |b| {
        b.iter(|| {
            prove_credential(&params, &verification_key, &signature, &private_attributes).unwrap()
        })
    });

    // Verify credentials
    verify_credential(&params, &verification_key, &theta, &public_attributes);

    c.bench_function("verify_credential", |b| {
        b.iter(|| verify_credential(&params, &verification_key, &theta, &public_attributes))
    });
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
