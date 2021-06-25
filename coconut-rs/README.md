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

100 iterations on 2,3 GHz 8-Core Intel Core i9 MacBook Pro

```
double pairing          time:   [4.3830 ms 4.4139 ms 4.4463 ms]                            
multi miller in affine  time:   [2.8097 ms 2.8164 ms 2.8235 ms]                                    
multi miller with prepared g2                                                                             
                        time:   [2.3726 ms 2.3762 ms 2.3800 ms]
multi miller with semi-prepared g2                                                                             
                        time:   [2.5839 ms 2.5913 ms 2.6007 ms]
elgamal_keygen          time:   [442.61 us 446.98 us 452.76 us]                           
produce_blinded_signatures_10_authorities_1_attributes                                                                            
                        time:   [264.89 ms 265.54 ms 266.27 ms]
unblind_prove_and_verify_10_authorities_1_attributes                                                                            
                        time:   [138.32 ms 140.18 ms 142.06 ms]
produce_blinded_signatures_10_authorities_3_attributes                                                                            
                        time:   [229.57 ms 231.00 ms 232.50 ms]
unblind_prove_and_verify_10_authorities_3_attributes                                                                            
                        time:   [128.43 ms 128.95 ms 129.53 ms]
produce_blinded_signatures_10_authorities_10_attributes                                                                            
                        time:   [228.46 ms 229.67 ms 230.91 ms]
unblind_prove_and_verify_10_authorities_10_attributes                                                                            
                        time:   [129.69 ms 130.46 ms 131.37 ms]
produce_blinded_signatures_100_authorities_1_attributes                                                                            
                        time:   [2.6077 s 2.6182 s 2.6290 s]
unblind_prove_and_verify_100_authorities_1_attributes                                                                            
                        time:   [1.0216 s 1.0237 s 1.0261 s]
produce_blinded_signatures_200_authorities_1_attributes                                                                            
                        time:   [6.4803 s 6.5419 s 6.6024 s]
unblind_prove_and_verify_200_authorities_1_attributes                                                                            
                        time:   [2.2503 s 2.2621 s 2.2740 s]
```

## References

+ [Public interface](https://github.com/asonnino/coconut/blob/master/coconut/scheme.py)