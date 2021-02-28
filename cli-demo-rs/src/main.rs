use coconut_rs::scheme::keygen::KeyPair;
use coconut_rs::scheme::setup::Parameters;
use coconut_rs::scheme::signature::{
    blind_sign, prepare_blind_sign, prove_credential, verify_credential, BlindedSignature,
    Signature, SignatureShare,
};
use coconut_rs::scheme::VerificationKey;
use coconut_rs::{elgamal, Attribute};
use digest::Digest;
use group::GroupEncoding;
use rand::seq::SliceRandom;
use rand_core::OsRng;
use read_input::prelude::*;
use sha2::digest::generic_array::typenum::Unsigned;
use sha2::Sha256;
use std::fmt::{Debug, Display, Formatter};
use std::{fmt, process};

struct App {
    params: Parameters<OsRng>,
    authority_keys: Vec<KeyPair>,
    client_elgamal: elgamal::KeyPair,
    threshold: u64,
}

impl App {
    pub fn new(
        mut params: Parameters<OsRng>,
        authority_keys: Vec<KeyPair>,
        threshold: u64,
    ) -> Self {
        let client_elgamal = elgamal::keygen(&mut params);
        App {
            params,
            authority_keys,
            client_elgamal,
            threshold,
        }
    }

    fn print_authorities(&self) {
        println!("Coconut signing authorities:");
        self.authority_keys.iter().enumerate().for_each(|(i, key)| {
            println!(
                "[{}] [t = {}] - {}",
                i + 1,
                self.threshold,
                format_authority(&key.verification_key)
            )
        })
    }

    fn blind_sign(
        &mut self,
        public: &[RawAttribute],
        private: &[RawAttribute],
    ) -> Vec<BlindedSignature> {
        let public_scalars: Vec<Attribute> =
            public.iter().map(|attr| attr.clone().into()).collect();
        let private_scalars: Vec<Attribute> =
            private.iter().map(|attr| attr.clone().into()).collect();

        let blind_sign_request = prepare_blind_sign(
            &mut self.params,
            self.client_elgamal.public_key(),
            &private_scalars,
            &public_scalars,
        )
        .expect("failed to create a blind sign request");

        let mut sigs = Vec::new();
        for keypair in &self.authority_keys {
            let sig = blind_sign(
                &mut self.params,
                &keypair.secret_key,
                self.client_elgamal.public_key(),
                &blind_sign_request,
                &public_scalars,
            )
            .expect("failed to blind sign attributes");
            sigs.push(sig)
        }

        sigs
    }

    fn randomise_credential(&mut self, credential: &Signature) -> Signature {
        credential.randomise(&mut self.params)
    }

    fn aggregate_keys(&self, indices: &[u64]) -> VerificationKey {
        let target_vks: Vec<_> = indices
            .iter()
            .map(|&id| {
                self.authority_keys[id as usize - 1]
                    .verification_key
                    .clone()
            })
            .collect();

        coconut_rs::scheme::aggregation::aggregate_verification_keys(&target_vks, Some(&indices))
            .expect("failed to aggregate signatures")
    }

    fn blind_verify(
        &mut self,
        public: &[RawAttribute],
        private: &[RawAttribute],
        vk: &VerificationKey,
        signature: &Signature,
    ) -> bool {
        let public_scalars: Vec<Attribute> =
            public.iter().map(|attr| attr.clone().into()).collect();
        let private_scalars: Vec<Attribute> =
            private.iter().map(|attr| attr.clone().into()).collect();

        let credential_proof = prove_credential(&mut self.params, vk, &signature, &private_scalars)
            .expect("failed to prove the credential!");
        verify_credential(&self.params, vk, &credential_proof, &public_scalars)
    }
}

fn format_authority(key: &VerificationKey) -> String {
    // just format alpha, that's more than enough
    let alpha = key.tmp_get_alpha();
    let bytes = alpha.to_bytes();
    let bytes_ref = bytes.as_ref();
    // use only first few bytes to not take entire terminal
    format!("{} ...", base64::encode(&bytes_ref[..32]))
}

fn format_signature(sig: &Signature) -> String {
    let s1bytes = sig.0.to_bytes();
    let s2bytes = sig.1.to_bytes();

    let s1bytes_ref = s1bytes.as_ref();
    let s2bytes_ref = s2bytes.as_ref();

    format!(
        "({} ... , {} ...)",
        base64::encode(&s1bytes_ref[..16]),
        base64::encode(&s2bytes_ref[..16]),
    )
}

fn format_blinded_signature(sig: &BlindedSignature) -> String {
    let s1bytes = sig.0.to_bytes();
    let s21bytes = sig.1 .0.to_bytes();
    let s22bytes = sig.1 .1.to_bytes();

    let s1bytes_ref = s1bytes.as_ref();
    let s21bytes_ref = s21bytes.as_ref();
    let s22bytes_ref = s22bytes.as_ref();

    format!(
        "({} ..., ({} ... , {} ...)",
        base64::encode(&s1bytes_ref[..16]),
        base64::encode(&s21bytes_ref[..16]),
        base64::encode(&s22bytes_ref[..16])
    )
}

#[derive(Clone)]
enum RawAttribute {
    Text(String),
    Number(u64),
}

// TODO: this perhaps will go to the coconut crate
fn hash_to_scalar<M>(msg: M) -> Attribute
where
    M: AsRef<[u8]>,
{
    let mut h = Sha256::new();
    h.update(msg);
    let digest = h.finalize();

    let mut bytes = [0u8; 64];
    let pad_size = 64usize
        .checked_sub(<Sha256 as Digest>::OutputSize::to_usize())
        .unwrap_or_default();

    bytes[pad_size..].copy_from_slice(&digest);

    Attribute::from_bytes_wide(&bytes)
}

impl Into<Attribute> for RawAttribute {
    fn into(self) -> Attribute {
        match self {
            RawAttribute::Text(raw) => hash_to_scalar(raw.as_bytes()),
            RawAttribute::Number(num) => Attribute::from(num),
        }
    }
}

impl Display for RawAttribute {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            RawAttribute::Text(text) => write!(f, "{}", text),
            RawAttribute::Number(num) => write!(f, "{}", num),
        }
    }
}

impl Debug for RawAttribute {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            RawAttribute::Text(text) => write!(f, "{}", text),
            RawAttribute::Number(num) => write!(f, "{}", num),
        }
    }
}

impl From<String> for RawAttribute {
    fn from(raw: String) -> Self {
        // try to parse as number
        if let Ok(num) = raw.parse::<u64>() {
            RawAttribute::Number(num)
        } else {
            RawAttribute::Text(raw)
        }
    }
}

fn get_attributes(name: &str, entered: u32, max: u32) -> (Vec<RawAttribute>, u32) {
    let mut attributes: Vec<RawAttribute> = Vec::new();
    let mut entered_new = 0;
    loop {
        println!(
            "\n[currently entered {} attributes in total out of maximum defined {}]",
            entered + entered_new,
            max
        );
        let attribute: String = input()
            .msg(format!(
                "Enter your {} attribute (press ENTER to go to next step): ",
                name.to_ascii_uppercase(),
            ))
            .get();

        if attribute.is_empty() {
            println!("Got all {} attributes - {:?}", name, attributes);
            return (attributes, entered_new);
        }
        entered_new += 1;

        attributes.push(attribute.into());
    }
}

fn get_private_attributes(entered: u32, max: u32) -> (Vec<RawAttribute>, u32) {
    get_attributes("private", entered, max)
}

fn get_public_attributes(entered: u32, max: u32) -> (Vec<RawAttribute>, u32) {
    get_attributes("public", entered, max)
}

fn print_blinded_sigs(sigs: &[BlindedSignature]) {
    println!("Obtained the following blinded signatures: ");
    sigs.iter()
        .enumerate()
        .for_each(|(i, sig)| println!("[{}] - {}", i + 1, format_blinded_signature(&sig)))
}

fn print_signatures(sigs: &[Signature]) {
    println!("Obtained the following signatures: ");
    sigs.iter()
        .enumerate()
        .for_each(|(i, sig)| println!("[{}] - {}", i + 1, format_signature(&sig)))
}

fn aggregate_signatures(unoredered_sigs: &[Signature], indices: &[u64]) -> Signature {
    let target_sigs: Vec<_> = indices
        .iter()
        .map(|&id| SignatureShare::new(unoredered_sigs[id as usize - 1], id))
        .collect();

    coconut_rs::scheme::aggregation::aggregate_signature_shares(&target_sigs)
        .expect("failed to aggregate signatures")
}

fn main() {
    // how many attributes
    println!("\nWelcome to the Nym Credential Library Demo.\n\n\
    This generates demo outputs a number of identity attributes attributes (claims) and has a set of authorities sign them using the Coconut signature scheme.\n\n\
    At each step, you may have options. Press ENTER to go to the next stage.  \n\n\
    1)  First, you will be prompted for the number of attributes. You need to enter the total number of attributes. \n\n\
    Then you will be asked to enter the values of 2) public attributes and then 3) private attributes (proofs of claims). \
    These values of these attributes can be any number or string, and so can be W3C DIDs like \"did:example:12345abcde.\" \n\n\
    4) Then you will be asked for a number of authorities that are authorized to verify your claims.\n\n\
    5) Lastly, you will be asked for a threshold value, which is the number of authorities that must be online to verify your claims at any given instance. \n\n\
    6) You may then \"re-randomize\" your credential as many times a you want to preserve your privacy. \n\n\
    Then in the final step 7) you will be asked to type in the values entered for your attributes in Step 2 and Step 3 again. At the end, the demo will output a credential composed of elliptic curve points.\n\n");

    let attributes: u32 = input()
        .msg("Enter the maximum number of credential attributes: ")
        .add_test(|&x| x > 0)
        .err("That does not look like a positive number greater than 0. Please try again")
        .get();

    let n: u64 = input()
        .msg("Enter the number of authorities: ")
        .add_test(|&x| x > 0)
        .err("That does not look like a positive number greater than 0. Please try again")
        .get();

    let n2 = n;

    let t: u64 = input()
        .msg("Enter the threshold value: ")
        .add_test(move |x| *x <= n2)
        .add_test(|&x| x > 0)
        .err("That does not look like a valid threshold value. Please try again")
        .get();

    println!(
        "Generating keys for {} authorities (aggregation threshold of {}) ...",
        n, t
    );
    let mut params = coconut_rs::scheme::setup::Parameters::new(OsRng, attributes).unwrap();
    let keys = coconut_rs::scheme::keygen::ttp_keygen(&mut params, t, n).unwrap();
    let mut app = App::new(params, keys, t);

    app.print_authorities();
    println!("\n\n");

    let (public_attributes, entered_public) = get_public_attributes(0, attributes);
    let (private_attributes, _) = get_private_attributes(entered_public, attributes);

    if private_attributes.is_empty() {
        println!("ERROR: Did not provide any private attributes to sign");
        process::exit(1)
    }

    if public_attributes.len() + private_attributes.len() > attributes as usize {
        println!("ERROR: Provided more attributes to sign than supported by the generated keys");
        process::exit(1)
    }

    println!(
        "\n\nGoing to sign the following:\nPUBLIC: {:?}\nPRIVATE: {:?}",
        public_attributes, private_attributes
    );

    let blinded_signature = app.blind_sign(&public_attributes, &private_attributes);
    print_blinded_sigs(&blinded_signature);

    println!("\nUnblinding the signatures...\n");
    let signatures: Vec<_> = blinded_signature
        .into_iter()
        .map(|bs| bs.unblind(app.client_elgamal.private_key()))
        .collect();
    print_signatures(&signatures);

    let indices: Vec<_> = (1..=n).collect();

    println!("Choosing {} random signatures to aggregate...", t);
    let sample: Vec<_> = indices
        .choose_multiple(&mut OsRng, t as usize)
        .map(|v| *v)
        .collect();
    println!("Chosen indices: {:?}", sample);

    let aggregated_sig = aggregate_signatures(&signatures, &sample);

    println!(
        "\n YOUR CREDENTIAL: {}\n",
        format_signature(&aggregated_sig)
    );

    println!("Randomising the credential...\n");
    let mut randomised = aggregated_sig.clone();
    loop {
        let r: String = input()
            .msg("Enter 'r' to randomise the credential again or just press enter to finish the procedure: ")
            .err("Please enter either 'r' or enter")
            .get();
        if r.is_empty() {
            break;
        } else if r == "r" {
            randomised = app.randomise_credential(&randomised);
            println!(
                "\n YOUR RANDOMISED CREDENTIAL: {}\n",
                format_signature(&randomised)
            );
        }
    }

    // println!(
    //     "Choosing {} random verification keys to aggregate for verification...\n",
    //     t
    // );
    // let sample: Vec<_> = indices
    //     .choose_multiple(&mut OsRng, t as usize)
    //     .map(|v| *v)
    //     .collect();
    // println!("Chosen indices: {:?}", sample);
    //
    // let aggregated_vk = app.aggregate_keys(&sample);
    // println!(
    //     "Aggregated verification key: {}",
    //     format_authority(&aggregated_vk)
    // );
    //
    // println!("Verifying the credential!");
    // println!("Provide your original attributes");
    //
    // let public_attributes = get_public_attributes();
    // let private_attributes = get_private_attributes();
    //
    // let verification_result = app.blind_verify(
    //     &public_attributes,
    //     &private_attributes,
    //     &aggregated_vk,
    //     &randomised,
    // );
    // if verification_result {
    //     println!("\nYour credential verified correctly!")
    // } else {
    //     println!("\nYour credential failed to get verified!");
    // }
}
