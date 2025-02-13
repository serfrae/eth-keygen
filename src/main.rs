use anyhow::Result;
use clap::Parser;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use k256::ecdsa::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha3::{Digest, Keccak256};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;
use std::sync::mpsc;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short = 's', long, default_value = "")]
    starts_with: String,

    #[arg(short = 'e', long, default_value = "")]
    ends_with: String,

    #[arg(short = 'c', long, default_value = "false")]
    is_checksum: bool,

    #[arg(short = 'o', long, required = false)]
    outfile: Option<PathBuf>,

    #[arg(short = 'n', long, default_value = "1")]
    num_matches: u64,
}

#[derive(Debug)]
struct Wallet {
    address: String,
    secret: String,
}

fn secret_to_address(secret: &[u8]) -> String {
    let signing_key = SigningKey::from_bytes(secret.into()).unwrap();
    let verifying_key = VerifyingKey::from(&signing_key);
    let public_key = verifying_key.to_encoded_point(false);
    let public_key_bytes = public_key.as_bytes();

    let mut hasher = Keccak256::new();
    hasher.update(&public_key_bytes[1..]);
    let result = hasher.finalize();

    hex::encode(&result[12..])
}

fn get_random_wallet() -> Wallet {
    let mut rng = OsRng;
    let secret = SigningKey::random(&mut rng);
    let secret_bytes = secret.to_bytes();

    Wallet {
        address: secret_to_address(&secret_bytes),
        secret: hex::encode(secret_bytes),
    }
}

fn check_char(c: char, index: usize, hash: &[u8]) -> char {
    if (hash[index / 2] >> (4 * (1 - index % 2)) & 0x0f) >= 8 {
        c.to_ascii_uppercase()
    } else {
        c.to_ascii_lowercase()
    }
}

fn is_valid_address(address: &str, prefix: &str, suffix: &str, is_checksum: bool) -> bool {
    let address_prefix = &address[..prefix.len()];
    let address_suffix = &address[40 - suffix.len()..];

    if !is_checksum {
        return prefix.to_lowercase() == address_prefix.to_lowercase()
            && suffix.to_lowercase() == address_suffix.to_lowercase();
    }

    if prefix != address_prefix || suffix != address_suffix {
        return false;
    }

    let mut hasher = Keccak256::new();
    hasher.update(address.as_bytes());
    let hash = hasher.finalize();

    for (i, c) in prefix.chars().enumerate() {
        if c != check_char(address.chars().nth(i).unwrap(), i, &hash) {
            return false;
        }
    }

    for (i, c) in suffix.chars().enumerate() {
        let j = i + 40 - suffix.len();
        if c != check_char(address.chars().nth(j).unwrap(), j, &hash) {
            return false;
        }
    }

    true
}

fn to_checksum_address(address: &str) -> String {
    let mut hasher = Keccak256::new();
    hasher.update(address.as_bytes());
    let hash = hasher.finalize();

    address
        .chars()
        .enumerate()
        .map(|(i, c)| check_char(c, i, &hash))
        .collect()
}

fn save_wallet(address: &str, secret: &str, outfile: Option<&PathBuf>) -> std::io::Result<()> {
    let path = match outfile {
        Some(path) => path,
        None => &PathBuf::from(format!("{address}.txt")),
    };
    let mut file = File::create(path)?;
    writeln!(file, "Address: {}", address)?;
    writeln!(file, "Private Key: {}", secret)?;
    Ok(())
}

fn main() {
    let start = std::time::Instant::now();
    let args = Args::parse();
    let (counter_tx, counter_rx) = mpsc::channel::<()>();

    ctrlc::set_handler(move || {
        println!("\nCaught interrupt signal, exiting...");
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    std::thread::spawn(move || {
        let mut counter = 0u64;
        let multi = MultiProgress::new();
        let pb = multi.add(ProgressBar::new_spinner());
        pb.set_style(
            ProgressStyle::default_spinner()
                .template(
                    "{spinner:.green} [{elapsed_precise}] {pos}/{len} addresses found ({msg} searched)",
                )
                .unwrap(),
        );
        pb.enable_steady_tick(Duration::from_millis(100));

        loop {
            match counter_rx.recv() {
                Ok(_) => {
                    counter += 1;
                    pb.set_message(counter.to_string());
                }
                Err(e) => {
                    eprintln!("Error receiving counter: {}", e);
                    break;
                }
            }
        }
    });

    let num_threads = num_cpus::get();
    println!("Starting {} worker threads...", num_threads);

    let (tx, rx) = std::sync::mpsc::channel();

    for i in 0..num_threads {
        let tx: std::sync::mpsc::Sender<Result<(String, String)>> = tx.clone();
        let args = args.clone();
        let counter_tx = counter_tx.clone();

        std::thread::spawn(move || {
            println!("Worker thread {} started", i);

            loop {
                counter_tx.send(()).unwrap();
                let wallet = get_random_wallet();

                if is_valid_address(
                    &wallet.address,
                    &args.starts_with,
                    &args.ends_with,
                    args.is_checksum,
                ) {
                    let checksum_address = format!("0x{}", to_checksum_address(&wallet.address));
                    tx.send(Ok((checksum_address, wallet.secret))).unwrap();
                    break;
                }
            }
        });
    }

    let mut matches = 0u64;
    while matches < args.num_matches {
        match rx.recv() {
            Ok(Ok((address, secret))) => {
                println!("Found matching address!");
                println!("Address: {}", address);
                println!("Secret: {}", secret);

                if let Err(e) = save_wallet(&address, &secret, args.outfile.as_ref()) {
                    eprintln!("Error saving wallet to file: {}", e);
                } else {
                    println!("Address and private key saved to {address}.txt");
                    matches += 1;
                }
            }
            Ok(Err(e)) => {
                eprintln!("Error: {}", e);
            }
            Err(e) => {
                eprintln!("Channel error: {}", e);
            }
        }
    }

    println!(
        "{} matches found in: {:.2?}",
        args.num_matches,
        start.elapsed()
    );
}
