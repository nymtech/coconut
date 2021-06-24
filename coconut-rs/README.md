## Usage

```rust
use coconut_rs::{
    aggregate_signature_shares, aggregate_verification_keys, blind_sign, elgamal_keygen,
    prepare_blind_sign, prove_credential, setup, ttp_keygen, verify_credential, CoconutError,
    Signature, SignatureShare, VerificationKey,
};

fn main() -> Result<(), CoconutError> {
    let params = setup(5)?;

    let public_attributes = params.n_random_scalars(2);
    let private_attributes = params.n_random_scalars(3);

    let elgamal_keypair = elgamal_keygen(&params);

    // generate commitment and encryption
    let blind_sign_request = prepare_blind_sign(
        &params,
        &elgamal_keypair.public_key(),
        &private_attributes,
        &public_attributes,
    )?;

    // generate_keys
    let coconut_keypairs = ttp_keygen(&params, 2, 3)?;

    let verification_keys: Vec<VerificationKey> = coconut_keypairs
        .iter()
        .map(|keypair| keypair.verification_key())
        .collect();

    // aggregate verification keys
    let verification_key = aggregate_verification_keys(&verification_keys, Some(&[1,2,3]))?;

    // generate blinded signatures
    let mut blinded_signatures = Vec::new();

    for keypair in coconut_keypairs {
        let blinded_signature = blind_sign(
            &params,
            &keypair.secret_key(),
            &elgamal_keypair.public_key(),
            &blind_sign_request,
            &public_attributes,
        )?;
        blinded_signatures.push(blinded_signature)
    }

    // Unblind

    let unblinded_signatures: Vec<Signature> = blinded_signatures
        .into_iter()
        .map(|signature| signature.unblind(&elgamal_keypair.private_key()))
        .collect();

    // Aggregate signatures

    let signature_shares: Vec<SignatureShare> = unblinded_signatures
        .iter()
        .enumerate()
        .map(|(idx, signature)| SignatureShare::new(*signature, (idx + 1) as u64))
        .collect();

    let signature = aggregate_signature_shares(&signature_shares)?;

    // Randomize credentials and generate any cryptographic material to verify them

    let theta = prove_credential(
        &params,
        &verification_key,
        &signature,
        &private_attributes,
    )?;

    // Verify credentials

    assert!(verify_credential(
        &params,
        &verification_key,
        &theta,
        &public_attributes
    ));

    Ok(())
}
```

## Benchmarks

+ [aggretage_signature_shares](https://htmlpreview.github.io/?https://github.com/nymtech/coconut/blob/5cbbb702506d206a52e97f2207b7aec25a4005d8/coconut-rs/target/criterion/aggregate_signature_shares/report/index.html)

## References

+ [Public interface](https://github.com/asonnino/coconut/blob/master/coconut/scheme.py)