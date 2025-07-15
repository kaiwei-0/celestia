use clap::Parser;
use hex::FromHex;
use pico_sdk::{client::DefaultProverClient, init_logger};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::{env, fs};
use zkvm_common::{KEY_LEN, NONCE_LEN, chacha, std_only::ZkvmOutput};

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,

    #[clap(long, default_value = "20")]
    n: u32,

    #[clap(long, value_name = "FILE")]
    save_inputs: Option<std::path::PathBuf>,
    #[clap(long, value_name = "FILE")]
    load_inputs: Option<std::path::PathBuf>,
}

#[derive(Serialize, Deserialize)]
pub struct ZkvmInput {
    pub key: [u8; KEY_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub plaintext: Vec<u8>,
}

pub fn save_inputs_bin(
    path: &std::path::Path,
    key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    plaintext: &[u8],
) -> bincode::Result<()> {
    let input = ZkvmInput {
        key,
        nonce,
        plaintext: plaintext.to_vec(),
    };
    let mut f = File::create(path)?;
    bincode::serialize_into(&mut f, &input)?;
    Ok(())
}

pub fn load_inputs_bin(path: &std::path::Path) -> bincode::Result<ZkvmInput> {
    bincode::deserialize_from(File::open(path)?)
}

/// Loads an ELF file from the specified path.
pub fn load_elf(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|err| {
        panic!("Failed to load ELF file from {}: {}", path, err);
    })
}

fn main() {
    // Setup the logger.
    init_logger();
    dotenv::dotenv().ok();

    // Initialize Pico prover client
    let elf = load_elf("./program-chacha/elf/riscv32im-pico-zkvm-elf");
    let client = DefaultProverClient::new(&elf);
    // Initialize new stdin
    let mut stdin_builder = client.new_stdin_builder();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    // Setup the inputs:
    // - key = 32 bytes
    // - nonce = 12 bytes (MUST BE UNIQUE - NO REUSE!)
    // - input_plaintext = bytes to encrypt

    let (input_key, input_nonce, plaintext_vec, mut stdin) =
        if let Some(ref path) = args.load_inputs {
            let inp = load_inputs_bin(path).unwrap();
            stdin_builder.write_slice(&inp.key);
            stdin_builder.write_slice(&inp.nonce);
            stdin_builder.write_slice(&inp.plaintext);
            (inp.key, inp.nonce, inp.plaintext, stdin_builder)
        } else {
            let key = <[u8; KEY_LEN]>::from_hex(
                std::env::var("ENCRYPTION_KEY").expect("Missing ENCRYPTION_KEY env var"),
            )
            .unwrap_or_else(|_| {
                panic!(
                    "ENCRYPTION_KEY must be {} bytes, hex encoded (ex: `1234...abcd`)",
                    KEY_LEN
                )
            });

            let nonce: [u8; NONCE_LEN] = zkvm_common::random_nonce();
            const PLAINTEXT: &[u8] = include_bytes!("../../../static/proof_input_example.bin");

            // let mut st = SP1Stdin::new();
            stdin_builder.write_slice(&key);
            stdin_builder.write_slice(&nonce);
            stdin_builder.write_slice(PLAINTEXT);

            if let Some(ref path) = args.save_inputs {
                save_inputs_bin(path, key, nonce, PLAINTEXT).unwrap();
                println!("✔️  inputs saved to {}", path.display());
            }
            (key, nonce, PLAINTEXT.to_vec(), stdin_builder)
        };

    if args.execute {
        // Execute the program
        let (cycles, pv_stream) = client.emulate(stdin);

        // Read the output.
        // - privkey sha2 hash = 32 bytes
        // - nonce = 12 bytes
        // - plaintext sha2 hash = 32 bytes
        // - ciphertext = encrypted bytes, ~1M bytes
        let output = ZkvmOutput::from_bytes(pv_stream.as_slice()).expect("Failed to parse header");

        // Check against the input
        let input_plaintext_digest = Sha256::digest(&plaintext_vec);
        println!(
            "Input -> plaintext hash: 0x{}",
            zkvm_common::std_only::bytes_to_hex(&input_plaintext_digest)
        );
        dbg!(&output);

        assert_eq!(input_nonce, output.nonce);
        // NOTE: stream cipher is decrypted by running the chacha encryption again.
        // (plaintext XOR keystream XOR keystream = plaintext; QED)
        let mut output_plaintext = output.ciphertext.to_owned();
        chacha(&input_key, &output.nonce, &mut output_plaintext);

        assert_eq!(output_plaintext, plaintext_vec);
        println!("Decryption of zkVM ciphertext matches input!");
        let input_key_hash = Sha256::digest(input_key);
        assert_eq!(input_key_hash.as_slice(), output.privkey_hash);
        println!("Key used matched!");

        // Record the number of cycles executed.
        println!("Number of cycles: {}", cycles);
    } else {
        // Set up output path
        let current_dir = env::current_dir().expect("Failed to get current directory");
        let output_path = current_dir.join("./test_data");

        fs::create_dir_all(&output_path).expect("Failed to create output directory");

        // Set up groth16 verifier and generate pico proof
        // The first parameter `need_setup = true` ensures the Groth16 verifier is set up,
        // but this setup is required only once.
        let need_setup = true;
        client
            .prove_evm(stdin, need_setup, output_path.clone(), "kb")
            .expect("Failed to generate evm proof");

        println!("Successfully generated proof!");
    }
}
