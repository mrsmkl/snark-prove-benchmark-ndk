use std::os::raw::{c_char};
use std::ffi::{CString};
use std::format;
use epoch_snark::{prove, trusted_setup, verify};
use std::time::Instant;

use algebra::{
    bls12_377::{Bls12_377, G1Projective},
    ProjectiveCurve, Zero,
    PairingEngine,
    UniformRand
};

// use bls_crypto::test_helpers::{keygen_batch, keygen_mul};
use bls_crypto::{PublicKey, Signature};
use epoch_snark::{EpochBlock, EpochTransition};

// Same RNG for all tests
pub fn rng() -> rand::rngs::ThreadRng {
    rand::thread_rng()
}

/// generate a keypair
pub fn keygen<E: PairingEngine>() -> (E::Fr, E::G2Projective) {
    let rng = &mut rng();
    let generator = E::G2Projective::prime_subgroup_generator();

    let secret_key = E::Fr::rand(rng);
    let pubkey = generator.mul(secret_key);
    (secret_key, pubkey)
}

/// generate N keypairs
pub fn keygen_mul<E: PairingEngine>(num: usize) -> (Vec<E::Fr>, Vec<E::G2Projective>) {
    let mut secret_keys = Vec::new();
    let mut public_keys = Vec::new();
    for _ in 0..num {
        let (secret_key, public_key) = keygen::<E>();
        secret_keys.push(secret_key);
        public_keys.push(public_key);
    }
    (secret_keys, public_keys)
}

/// generate `num_batches` sets of keypair vectors, each `num_per_batch` size
#[allow(clippy::type_complexity)]
pub fn keygen_batch<E: PairingEngine>(
    num_batches: usize,
    num_per_batch: usize,
) -> (Vec<Vec<E::Fr>>, Vec<Vec<E::G2Projective>>) {
    let mut secret_keys = Vec::new();
    let mut public_keys = Vec::new();
    (0..num_batches).for_each(|_| {
        let (secret_keys_i, public_keys_i) = keygen_mul::<E>(num_per_batch);
        secret_keys.push(secret_keys_i);
        public_keys.push(public_keys_i);
    });
    (secret_keys, public_keys)
}

/// sum the elements in the provided slice
pub fn sum<P: ProjectiveCurve>(elements: &[P]) -> P {
    elements.iter().fold(P::zero(), |acc, key| acc + key)
}

/// N messages get signed by N committees of varying sizes
/// N aggregate signatures are returned
pub fn sign_batch<E: PairingEngine>(
    secret_keys: &[Vec<E::Fr>],
    messages: &[E::G1Projective],
) -> Vec<E::G1Projective> {
    secret_keys
        .iter()
        .zip(messages)
        .map(|(secret_keys, message)| {
            let (_, asig) = sign::<E>(*message, &secret_keys);
            asig
        })
        .collect::<Vec<_>>()
}

// signs a message with a vector of secret keys and returns the list of sigs + the agg sig
pub fn sign<E: PairingEngine>(
    message_hash: E::G1Projective,
    secret_keys: &[E::Fr],
) -> (Vec<E::G1Projective>, E::G1Projective) {
    let sigs = secret_keys
        .iter()
        .map(|key| message_hash.mul(*key))
        .collect::<Vec<_>>();
    let asig = sigs
        .iter()
        .fold(E::G1Projective::zero(), |acc, sig| acc + sig);
    (sigs, asig)
}

// Returns the initial epoch and a list of signed `num_epochs` state transitions
pub fn generate_test_data(
    num_validators: usize,
    faults: usize,
    num_epochs: usize,
) -> (EpochBlock, Vec<EpochTransition>, EpochBlock) {
    let bitmaps = generate_bitmaps(num_epochs, num_validators, faults);
    let initial_validator_set = keygen_mul::<Bls12_377>(num_validators as usize);
    // Generate the initial epoch. This was proven to be correct either via
    // the previous epoch proof, or it's the genesis block
    let initial_pubkeys = initial_validator_set
        .1
        .iter()
        .map(|pk| PublicKey::from(*pk))
        .collect::<Vec<_>>();
    let first_epoch = generate_block(
        0,
        0,
        &[1u8; EpochBlock::ENTROPY_BYTES],
        &[2u8; EpochBlock::ENTROPY_BYTES],
        faults,
        num_validators,
        &initial_pubkeys,
    );

    // Generate keys for the validators of each epoch
    let validators = keygen_batch::<Bls12_377>(num_epochs, num_validators as usize);
    // generate the block for i+1th epoch
    let pubkeys = validators
        .1
        .iter()
        .map(|epoch_keys| epoch_keys.iter().map(|pk| PublicKey::from(*pk)).collect())
        .collect::<Vec<Vec<_>>>();

    // Signers will be from the 1st to the last-1 epoch
    let mut signers = vec![initial_validator_set.0];
    signers.extend_from_slice(&validators.0[..validators.0.len() - 1]);
    // sign each state transition
    let mut transitions = vec![];
    for (i, signers_epoch) in signers.iter().enumerate() {
        let block: EpochBlock = generate_block(
            i + 1,
            i + 10,
            &[(i + 2) as u8; EpochBlock::ENTROPY_BYTES],
            &[(i + 1) as u8; EpochBlock::ENTROPY_BYTES],
            faults,
            num_validators,
            &pubkeys[i],
        );
        let hash = block.hash_to_g1_cip22().unwrap();

        // A subset of the i-th validator set, signs on the i+1th epoch's G1 hash
        let bitmap_epoch = &bitmaps[i];
        let asig = {
            let mut asig = G1Projective::zero();
            for (j, sk) in signers_epoch.iter().enumerate() {
                if bitmap_epoch[j] {
                    asig += hash.mul(*sk)
                }
            }
            asig
        };
        let asig = Signature::from(asig);

        let transition = EpochTransition {
            block,
            aggregate_signature: asig,
            bitmap: bitmap_epoch.to_vec(),
        };
        transitions.push(transition);
    }
    let last_epoch = transitions[transitions.len() - 1].block.clone();

    (first_epoch, transitions, last_epoch)
}

fn generate_block(
    index: usize,
    round: usize,
    epoch_entropy: &[u8],
    parent_entropy: &[u8],
    non_signers: usize,
    max_validators: usize,
    pubkeys: &[PublicKey],
) -> EpochBlock {
    EpochBlock {
        index: index as u16,
        round: round as u8,
        epoch_entropy: Some(epoch_entropy.to_vec()),
        parent_entropy: Some(parent_entropy.to_vec()),
        maximum_non_signers: non_signers as u32,
        maximum_validators: max_validators,
        new_public_keys: pubkeys.to_vec(),
    }
}

// generates `num_epochs` bitmaps with `num_validators - faults` 1 bits set and `faults` 0 bits set
fn generate_bitmaps(num_epochs: usize, num_validators: usize, faults: usize) -> Vec<Vec<bool>> {
    let mut ret = Vec::new();
    for _ in 0..num_epochs {
        let mut bitmap = vec![true; num_validators];
        for b in bitmap.iter_mut().take(faults) {
            *b = false;
        }
        ret.push(bitmap)
    }
    ret
}

#[no_mangle]
pub extern fn run_bench() -> *mut c_char {
    let rng = &mut rand::thread_rng();
    let num_validators = 1;
    let num_epochs = 1;
    let hashes_in_bls12_377 = false;
    let faults = (num_validators - 1) / 3;

    // Trusted setup
    let timer_1 = Instant::now();
    let params =
        trusted_setup(num_validators, num_epochs, faults, rng, hashes_in_bls12_377).unwrap();
    let time_1 = timer_1.elapsed();

    let timer_2 = Instant::now();
    // Create the state to be proven (first - last and in between)
    // Note: This is all data which should be fetched via the Celo blockchain
    let (first_epoch, transitions, last_epoch) =
        generate_test_data(num_validators, faults, num_epochs);

    // Prover generates the proof given the params
    let proof = prove(
        &params,
        num_validators as u32,
        &first_epoch,
        &transitions,
        num_epochs,
    )
    .unwrap();
    let time_2 = timer_2.elapsed();
    let timer_3 = Instant::now();

    // Verifier checks the proof
    let res = verify(&params.epochs.vk, &first_epoch, &last_epoch, &proof);
    let time_3 = timer_3.elapsed();
    assert!(res.is_ok());
    CString::new(format!("Setup {}, Generate {}, Verify {}", time_1.as_millis(), time_2.as_millis(), time_3.as_millis())).unwrap().into_raw()
//    CString::new(format!("Setup, Generate, Verify")).unwrap().into_raw()
}

/// Expose the JNI interface for android below
#[cfg(target_os="android")]
#[allow(non_snake_case)]
pub mod android {
    extern crate jni;

    use super::*;
    use self::jni::JNIEnv;
    use self::jni::objects::JClass;
    use self::jni::sys::{jstring};

    #[no_mangle]
    pub unsafe extern fn Java_org_celo_snarkbenchmark_Bench_bench(env: JNIEnv, _: JClass) -> jstring {
        let world_ptr = CString::from_raw(run_bench());
        let output = env.new_string(world_ptr.to_str().unwrap()).expect("Couldn't create java string!");

        output.into_inner()
    }
}



