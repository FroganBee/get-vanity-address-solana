# Solana Vanity Address Generator

A high-performance vanity address generator for Solana blockchain built with Rust and multi-threading.

### Stay Connected
| Platform | Link | Purpose |
|----------|------|---------|
| Telegram | [t.me/solzen33](https://t.me/solzen33) | Announcements & Support |
| X | [x.com/solzen33](https://x.com/solzen33) | News & Updates |

## Features

- 🚀 **Multi-threaded**: Automatically uses all available CPU cores for maximum performance
- 🔍 **Suffix matching**: Search for addresses ending with specific patterns
- 🎯 **Advanced case handling**: Multiple case matching modes for precise control
- ⚙️ **Configurable**: Customize thread count, case sensitivity, and max attempts
- 📊 **Progress tracking**: Real-time progress updates and statistics
- 🔐 **Secure**: Generates cryptographically secure keypairs

## Installation

1. Make sure you have Rust installed:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. Clone and build the project:
   ```bash
   cd vanity-address
   cargo build --release
   ```

## Usage

### Basic Usage

Search for an address ending with "pump":
```bash
cargo run -- --suffix pump
```

### Advanced Options

```bash
# Search for case-sensitive suffix
cargo run -- --suffix pump --case-sensitive

# Use specific number of threads
cargo run -- --suffix SOL --threads 8

# Limit maximum attempts
cargo run -- --suffix TEST --max-attempts 1000000

# Use specific case mode
cargo run -- --suffix Pump --case-mode mixed

# Combine options
cargo run -- --suffix COOL --threads 16 --case-mode upper --max-attempts 5000000
```

### Command Line Arguments

- `-s, --suffix <SUFFIX>`: Suffix pattern to search for (default: "pump")
- `-t, --threads <THREADS>`: Number of threads (0 = auto-detect, default: 20)
- `-c, --case-sensitive`: Enable case-sensitive search
- `-m, --max-attempts <MAX_ATTEMPTS>`: Maximum attempts before giving up (0 = unlimited, default: 0)
- `--case-mode <MODE>`: Case matching mode (exact, upper, lower, mixed, default: exact)

## Case Modes

The tool provides several case matching modes for flexible pattern matching:

### 1. **exact** (default)
- Matches the exact case pattern you specify
- Example: `--suffix Pump` will only match addresses ending with "Pump"

### 2. **upper**
- Converts both address and suffix to uppercase for comparison
- Example: `--suffix pump --case-mode upper` will match "PUMP", "Pump", "pump", etc.

### 3. **lower**
- Converts both address and suffix to lowercase for comparison
- Example: `--suffix PUMP --case-mode lower` will match "pump", "Pump", "PUMP", etc.

### 4. **mixed**
- Preserves the original case pattern while allowing case-insensitive matching
- Example: `--suffix Pump --case-mode mixed` will match "Pump", "pUmp", "PUMP", etc.
- The found address will have the same case pattern as your specified suffix

## Examples

### Find a "pump" vanity address
```bash
cargo run -- --suffix pump
```

### Find a case-sensitive "Pump" address
```bash
cargo run -- --suffix Pump --case-sensitive
```

### Find any address ending with "SOL" (case-insensitive)
```bash
cargo run -- --suffix SOL --case-mode upper
```

### Find address with mixed case "Moon"
```bash
cargo run -- --suffix Moon --case-mode mixed
```

### Quick test with limited attempts
```bash
cargo run -- --suffix TEST --max-attempts 100000
```

## Performance Tips

- **Longer suffixes** take exponentially longer to find
- **Case-sensitive** searches are faster than case-insensitive
- **More threads** = faster search (up to your CPU core count)
- **Shorter suffixes** (2-4 characters) are practical for most use cases
- **Mixed case mode** is slightly slower than simple case modes

## Suffix Difficulty

| Suffix Length | Estimated Time | Difficulty |
|---------------|----------------|------------|
| 2 characters | Seconds        | Easy       |
| 3 characters | Minutes        | Medium     |
| 4 characters | Hours          | Hard       |
| 5+ characters| Days/Weeks     | Very Hard  |

## Output

When a matching address is found, you'll see:
```
🎉 Found matching address!
📍 Address: 1234567890...pump
🔑 Private key: [base58_encoded_private_key]
📊 Attempts: 12345
⏱️  Time taken: 2.5s
🔍 Found suffix case analysis:
   - Found suffix: pump
   - Contains uppercase: false
   - Contains lowercase: true
   - Mixed case: false
```

## Security Notes

- **Never share your private keys**
- **Store private keys securely**
- **Use a dedicated machine** for generating vanity addresses
- **Consider using a hardware wallet** for production use

## Building from Source

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Run tests
cargo test

# Check code quality
cargo clippy
```

## Dependencies

- `solana-sdk`: Solana blockchain integration
- `rayon`: Parallel processing and threading
- `clap`: Command-line argument parsing
- `base58`: Base58 encoding for addresses
- `num_cpus`: CPU core detection

## License

This project is open source and available under the MIT License.
