use clap::Parser;
use rayon::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use std::fs;
use serde_json::{json, to_string_pretty};
use chrono::{DateTime, Utc};
use bip39::{Mnemonic, Language};
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sha3::{Digest, Keccak256};
use bitcoin::{
    Address, Network, PrivateKey, PublicKey as BtcPublicKey,
    secp256k1::{Secp256k1 as BtcSecp256k1, SecretKey as BtcSecretKey},
};
use base58::ToBase58;
use ripemd::Ripemd160;
use sha2::Sha256;
use rand::RngCore;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Blockchain type: btc, eth, xrp, or sol
    #[arg(short, long, default_value = "sol")]
    chain: String,

    /// The pattern to search for at the beginning of the address
    #[arg(short, long)]
    prefix: Option<String>,

    /// The pattern to search for at the end of the address
    #[arg(short, long)]
    suffix: Option<String>,

    /// Number of threads to use (0 = auto-detect)
    #[arg(short, long, default_value_t = 0)]
    threads: usize,

    /// Case sensitive search
    #[arg(short, long)]
    case_sensitive: bool,

    /// Maximum attempts before giving up (0 = unlimited)
    #[arg(short, long, default_value_t = 0)]
    max_attempts: u64,

    /// Case matching mode: exact, upper, lower, mixed
    #[arg(long, default_value = "exact")]
    case_mode: String,

    /// Chunk size for thread work distribution
    #[arg(long, default_value_t = 10000)]
    chunk_size: usize,

    /// Output file name for saving found address data (default: data.json)
    #[arg(short, long, default_value = "data.json")]
    output: String,

    /// Clear/reset the output file before starting search
    #[arg(long)]
    clear_output: bool,
}

#[derive(Clone)]
struct OptimizedPattern {
    exact: String,
    upper: String,
    lower: String,
    case_mode: String,
    pattern_len: usize,
}

impl OptimizedPattern {
    fn new(pattern: &str, case_mode: &str) -> Self {
        let upper = pattern.to_uppercase();
        let lower = pattern.to_lowercase();
        let pattern_len = pattern.len();
        
        Self {
            exact: pattern.to_string(),
            upper,
            lower,
            case_mode: case_mode.to_string(),
            pattern_len,
        }
    }
    
    #[inline(always)]
    fn matches(&self, text: &str) -> bool {
        if text.len() < self.pattern_len {
            return false;
        }
        
        let text_slice = &text[..self.pattern_len];
        
        match self.case_mode.as_str() {
            "exact" => text_slice == self.exact,
            "upper" => text_slice.eq_ignore_ascii_case(&self.exact),
            "lower" => text_slice.eq_ignore_ascii_case(&self.exact),
            "mixed" => self.matches_mixed_case(text_slice),
            _ => text_slice == self.exact,
        }
    }
    
    #[inline(always)]
    fn matches_suffix(&self, text: &str) -> bool {
        if text.len() < self.pattern_len {
            return false;
        }
        
        let text_slice = &text[text.len() - self.pattern_len..];
        
        match self.case_mode.as_str() {
            "exact" => text_slice == self.exact,
            "upper" => text_slice.eq_ignore_ascii_case(&self.exact),
            "lower" => text_slice.eq_ignore_ascii_case(&self.exact),
            "mixed" => self.matches_mixed_case(text_slice),
            _ => text_slice == self.exact,
        }
    }
    
    #[inline(always)]
    fn matches_mixed_case(&self, text_slice: &str) -> bool {
        if text_slice.len() != self.pattern_len {
            return false;
        }
        
        let pattern_bytes = self.exact.as_bytes();
        let text_bytes = text_slice.as_bytes();
        
        for i in 0..self.pattern_len {
            let pattern_char = pattern_bytes[i];
            let text_char = text_bytes[i];
            
            if pattern_char.is_ascii_uppercase() && !text_char.is_ascii_uppercase() {
                return false;
            }
            if pattern_char.is_ascii_lowercase() && !text_char.is_ascii_lowercase() {
                return false;
            }
        }
        true
    }
}

#[derive(Clone, Debug)]
struct WalletData {
    address: String,
    private_key: String,
    seed_phrase: String,
}

// BTC Address Generation
fn generate_btc_address() -> Result<WalletData, Box<dyn std::error::Error>> {
    // Generate entropy for 12-word mnemonic (128 bits = 16 bytes)
    let mut entropy = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut entropy);
    
    // Generate mnemonic from entropy
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)?;
    
    // Generate seed from mnemonic
    let seed = mnemonic.to_seed("");
    
    // Derive private key from seed (use first 32 bytes)
    let mut priv_key_bytes = [0u8; 32];
    priv_key_bytes.copy_from_slice(&seed[..32]);
    
    // Create bitcoin private key
    let secp = BtcSecp256k1::new();
    let secret_key = BtcSecretKey::from_slice(&priv_key_bytes)?;
    let private_key = PrivateKey::new(secret_key, Network::Bitcoin);
    
    // Generate public key
    let public_key = BtcPublicKey::from_private_key(&secp, &private_key);
    
    // Generate address (P2PKH)
    let address = Address::p2pkh(&public_key, Network::Bitcoin);
    
    Ok(WalletData {
        address: address.to_string(),
        private_key: private_key.to_wif(),
        seed_phrase: mnemonic.to_string(),
    })
}

// ETH Address Generation
fn generate_eth_address() -> Result<WalletData, Box<dyn std::error::Error>> {
    // Generate entropy for 12-word mnemonic (128 bits = 16 bytes)
    let mut entropy = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut entropy);
    
    // Generate mnemonic from entropy
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)?;
    
    // Generate seed from mnemonic
    let seed = mnemonic.to_seed("");
    
    // Derive private key from seed (use first 32 bytes)
    let mut priv_key_bytes = [0u8; 32];
    priv_key_bytes.copy_from_slice(&seed[..32]);
    
    // Ensure valid private key
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&priv_key_bytes)?;
    
    // Generate public key
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let public_key_bytes = public_key.serialize_uncompressed();
    
    // Hash public key with Keccak256
    let hash = Keccak256::digest(&public_key_bytes[1..]); // Skip 0x04 prefix
    let address_bytes = &hash[12..]; // Last 20 bytes
    
    // Format as hex address
    let address = format!("0x{}", hex::encode(address_bytes));
    
    // Format private key as hex
    let private_key = format!("0x{}", hex::encode(priv_key_bytes));
    
    Ok(WalletData {
        address,
        private_key,
        seed_phrase: mnemonic.to_string(),
    })
}

// XRP Address Generation
fn generate_xrp_address() -> Result<WalletData, Box<dyn std::error::Error>> {
    // Generate entropy for 12-word mnemonic (128 bits = 16 bytes)
    let mut entropy = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut entropy);
    
    // Generate mnemonic from entropy
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)?;
    
    // Generate seed from mnemonic
    let seed = mnemonic.to_seed("");
    
    // Derive private key from seed (use first 32 bytes)
    let mut priv_key_bytes = [0u8; 32];
    priv_key_bytes.copy_from_slice(&seed[..32]);
    
    // Ensure valid private key
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&priv_key_bytes)?;
    
    // Generate public key
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let public_key_bytes = public_key.serialize_uncompressed();
    
    // XRP address encoding
    // 1. Hash public key with SHA256
    let sha256_hash = Sha256::digest(&public_key_bytes[1..]);
    
    // 2. Hash with RIPEMD160
    let mut ripemd = Ripemd160::new();
    ripemd.update(&sha256_hash);
    let ripemd_hash = ripemd.finalize();
    
    // 3. Add version byte (0x00 for XRP)
    let mut address_bytes = vec![0x00];
    address_bytes.extend_from_slice(&ripemd_hash);
    
    // 4. Calculate checksum (double SHA256, take first 4 bytes)
    let checksum1 = Sha256::digest(&address_bytes);
    let checksum2 = Sha256::digest(&checksum1);
    address_bytes.extend_from_slice(&checksum2[..4]);
    
    // 5. Base58 encode
    let address = address_bytes.to_base58();
    
    // Format private key as hex
    let private_key = format!("0x{}", hex::encode(priv_key_bytes));
    
    Ok(WalletData {
        address,
        private_key,
        seed_phrase: mnemonic.to_string(),
    })
}

// SOL Address Generation
fn generate_sol_address() -> Result<WalletData, Box<dyn std::error::Error>> {
    use solana_sdk::signature::{Keypair, Signer};
    
    // Generate entropy for 12-word mnemonic (128 bits = 16 bytes)
    let mut entropy = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut entropy);
    
    // Generate mnemonic from entropy
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)?;
    
    // Generate seed from mnemonic
    let seed = mnemonic.to_seed("");
    
    // Derive keypair from seed (Solana uses Ed25519)
    // Use first 32 bytes of seed
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&seed[..32]);
    
    // Create keypair from seed
    let keypair = Keypair::from_bytes(&key_bytes)
        .map_err(|_| "Failed to create keypair from seed")?;
    
    let address = keypair.pubkey().to_string();
    let private_key = keypair.to_base58_string();
    
    Ok(WalletData {
        address,
        private_key,
        seed_phrase: mnemonic.to_string(),
    })
}

fn analyze_case_pattern(pattern: &str) -> (bool, bool, bool) {
    let mut has_upper = false;
    let mut has_lower = false;
    
    for &byte in pattern.as_bytes() {
        if byte.is_ascii_uppercase() {
            has_upper = true;
        } else if byte.is_ascii_lowercase() {
            has_lower = true;
        }
    }
    
    let has_mixed = has_upper && has_lower;
    (has_upper, has_lower, has_mixed)
}

fn save_to_json(
    wallet: &WalletData,
    attempts: u64,
    elapsed_time: std::time::Duration,
    chain: &str,
    pattern: Option<&str>,
    pattern_type: &str,
    case_mode: &str,
    filename: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let now: DateTime<Utc> = Utc::now();
    
    let new_address = json!({
        "chain": chain,
        "address": wallet.address,
        "private_key": wallet.private_key,
        "seed_phrase": wallet.seed_phrase,
        "found_at": now.to_rfc3339(),
        "search_parameters": {
            "pattern": pattern,
            "pattern_type": pattern_type,
            "case_mode": case_mode
        },
        "search_stats": {
            "attempts": attempts,
            "elapsed_time_seconds": elapsed_time.as_secs_f64(),
            "elapsed_time_human": format!("{:?}", elapsed_time)
        }
    });
    
    // Try to read existing file and append to it
    let mut addresses = if fs::metadata(filename).is_ok() {
        let content = fs::read_to_string(filename)?;
        if content.trim().is_empty() {
            json!({ "vanity_addresses": [] })
        } else {
            serde_json::from_str(&content).unwrap_or_else(|_| json!({ "vanity_addresses": [] }))
        }
    } else {
        json!({ "vanity_addresses": [] })
    };
    
    // Add new address to the array
    if let Some(addresses_array) = addresses["vanity_addresses"].as_array_mut() {
        addresses_array.push(new_address);
    }
    
    let json_string = to_string_pretty(&addresses)?;
    fs::write(filename, json_string)?;
    
    println!("💾 Address added to {}", filename);
    Ok(())
}

fn display_current_addresses(filename: &str) -> Result<(), Box<dyn std::error::Error>> {
    if fs::metadata(filename).is_ok() {
        let content = fs::read_to_string(filename)?;
        if !content.trim().is_empty() {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(addresses) = data["vanity_addresses"].as_array() {
                    if !addresses.is_empty() {
                        println!("📚 Current addresses in {}: {}", filename, addresses.len());
                        for (i, addr) in addresses.iter().enumerate() {
                            if let Some(address) = addr["address"].as_str() {
                                if let Some(chain) = addr["chain"].as_str() {
                                    if let Some(found_at) = addr["found_at"].as_str() {
                                        println!("   {}. [{}] {} (found: {})", i + 1, chain.to_uppercase(), address, found_at);
                                    }
                                }
                            }
                        }
                        println!("");
                    }
                }
            }
        }
    }
    Ok(())
}

fn main() {
    let args = Args::parse();
    
    // Validate chain
    let chain = args.chain.to_lowercase();
    if !["btc", "eth", "xrp", "sol"].contains(&chain.as_str()) {
        eprintln!("❌ Error: Invalid chain. Must be one of: btc, eth, xrp, sol");
        std::process::exit(1);
    }
    
    // Validate that exactly one pattern is provided (prefix OR suffix, not both)
    match (&args.prefix, &args.suffix) {
        (Some(_), Some(_)) => {
            eprintln!("❌ Error: Cannot specify both --prefix and --suffix. Use only one.");
            std::process::exit(1);
        }
        (None, None) => {
            eprintln!("❌ Error: Must specify either --prefix or --suffix");
            std::process::exit(1);
        }
        _ => {}
    }
    
    let (pattern, pattern_type) = if let Some(ref prefix) = args.prefix {
        (prefix.clone(), "prefix")
    } else {
        (args.suffix.clone().unwrap(), "suffix")
    };
    
    // Analyze the case pattern
    let pattern_analysis = analyze_case_pattern(&pattern);
    
    println!("🔍 Searching for {} vanity address:", chain.to_uppercase());
    println!("   🎯 Pattern: {} ({})", pattern, pattern_type);
    println!("📝 Case sensitive: {}", args.case_sensitive);
    println!("🎯 Case mode: {}", args.case_mode);
    
    // Print case analysis
    let (has_upper, has_lower, has_mixed) = pattern_analysis;
    println!("📊 Pattern case analysis:");
    println!("   - Contains uppercase: {}", has_upper);
    println!("   - Contains lowercase: {}", has_lower);
    println!("   - Mixed case: {}", has_mixed);
    
    // Pre-compute optimized pattern
    let optimized_pattern = OptimizedPattern::new(&pattern, &args.case_mode);
    
    // Clear output file if requested
    if args.clear_output {
        let empty_data = json!({ "vanity_addresses": [] });
        let json_string = to_string_pretty(&empty_data).unwrap();
        if let Err(e) = fs::write(&args.output, json_string) {
            eprintln!("⚠️  Warning: Could not clear output file: {}", e);
        } else {
            println!("🗑️  Output file {} cleared", args.output);
        }
    }
    
    // Display current addresses in output file
    if let Err(e) = display_current_addresses(&args.output) {
        eprintln!("⚠️  Warning: Could not read output file: {}", e);
    }
    
    // Set number of threads
    let num_threads = if args.threads == 0 {
        let cpu_cores = num_cpus::get();
        let pattern_complexity = optimized_pattern.pattern_len;
        
        let optimal_threads = if pattern_complexity > 8 {
            cpu_cores * 2
        } else if pattern_complexity > 4 {
            cpu_cores
        } else {
            cpu_cores.saturating_sub(1).max(1)
        };
        
        optimal_threads.min(32)
    } else {
        args.threads
    };
    
    // Configure thread pool
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .stack_size(8 * 1024 * 1024)
        .build_global()
        .unwrap();
    
    println!("🧵 Using {} threads (optimized for pattern complexity)", num_threads);
    println!("📦 Chunk size: {}", args.chunk_size);
    println!("🚀 Starting search...\n");
    
    let start_time = Instant::now();
    let attempts = Arc::new(AtomicU64::new(0));
    
    // Create work chunks
    let work_chunks: Vec<Vec<()>> = (0..num_threads)
        .map(|_| vec![(); args.chunk_size])
        .collect();
    
    // Search for vanity address
    let result = work_chunks
        .into_par_iter()
        .find_any(|_| {
            let mut local_attempts = 0u64;
            let mut last_progress = 0u64;
            
            loop {
                local_attempts += 1;
                
                // Check if we've reached max attempts
                if args.max_attempts > 0 && local_attempts >= args.max_attempts {
                    return true;
                }
                
                // Generate wallet based on chain
                let wallet_result = match chain.as_str() {
                    "btc" => generate_btc_address(),
                    "eth" => generate_eth_address(),
                    "xrp" => generate_xrp_address(),
                    "sol" => generate_sol_address(),
                    _ => unreachable!(),
                };
                
                let wallet = match wallet_result {
                    Ok(w) => w,
                    Err(_) => continue,
                };
                
                // Check if address matches pattern
                let matches = if args.case_sensitive {
                    match pattern_type {
                        "prefix" => wallet.address.starts_with(&pattern),
                        "suffix" => wallet.address.ends_with(&pattern),
                        _ => false,
                    }
                } else {
                    match pattern_type {
                        "prefix" => optimized_pattern.matches(&wallet.address),
                        "suffix" => optimized_pattern.matches_suffix(&wallet.address),
                        _ => false,
                    }
                };
                
                if matches {
                    let total_attempts = attempts.fetch_add(local_attempts, Ordering::Relaxed) + local_attempts;
                    
                    println!("🎉 Found matching address!");
                    println!("📍 Address: {}", wallet.address);
                    println!("🔑 Private key: {}", wallet.private_key);
                    println!("🌱 Seed phrase: {}", wallet.seed_phrase);
                    println!("📊 Attempts: {}", total_attempts);
                    println!("⏱️  Time taken: {:?}", start_time.elapsed());
                    
                    // Save data to JSON
                    let elapsed_time = start_time.elapsed();
                    save_to_json(
                        &wallet,
                        total_attempts,
                        elapsed_time,
                        &chain,
                        Some(&pattern),
                        pattern_type,
                        &args.case_mode,
                        &args.output,
                    ).unwrap();
                    
                    return true;
                }
                
                // Update global counter and progress
                if local_attempts % 50_000 == 0 {
                    attempts.fetch_add(50_000, Ordering::Relaxed);
                    
                    let current_total = attempts.load(Ordering::Relaxed);
                    if current_total - last_progress >= 5_000_000 {
                        let elapsed = start_time.elapsed();
                        let rate = current_total as f64 / elapsed.as_secs_f64();
                        println!("🔍 Attempts: {} | Rate: {:.0}/sec | Current: {}", 
                                current_total, rate, wallet.address);
                        last_progress = current_total;
                    }
                }
            }
        });
    
    if result.is_some() {
        println!("\n✅ Vanity address found successfully!");
    } else {
        println!("\n❌ Search completed without finding a match");
        if args.max_attempts > 0 {
            println!("📊 Total attempts: {}", attempts.load(Ordering::Relaxed));
        }
    }
    
    let total_time = start_time.elapsed();
    let total_attempts = attempts.load(Ordering::Relaxed);
    let final_rate = total_attempts as f64 / total_time.as_secs_f64();
    
    println!("⏱️  Total time: {:?}", total_time);
    println!("📊 Total attempts: {}", total_attempts);
    println!("🚀 Final rate: {:.0} attempts/second", final_rate);
    println!("💡 Performance tip: Adjust --chunk-size and --threads for optimal performance");
}

