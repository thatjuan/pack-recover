# pack-recover

A fast, parallel archive password recovery tool supporting multiple formats (RAR, 7zip, and ZIP).

## Features

- **Multi-format support**: RAR (including RAR5), 7-Zip, and ZIP archives
- **Parallel processing**: Leverages all CPU cores for maximum speed using Rayon
- **Dual implementation**: Choose between external CLI tools or native Rust libraries
- **Smart detection**: Automatically detects archive format and encryption type
- **Progress tracking**: Real-time progress bar with ETA
- **Flexible output**: Quiet mode for scripting, verbose mode for debugging
- **Post-recovery actions**: Automatically extract archives and optionally delete originals
- **Resume capability**: Skip passwords with `--offset` for distributed cracking
- **Glob patterns**: Process multiple archives with wildcard patterns

## Installation

### Quick Install (Linux/macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/thatjuan/pack-recover/main/install.sh | sh
```

### From Source

Requires [Rust](https://rustup.rs/) 1.70+:

```bash
git clone https://github.com/thatjuan/pack-recover.git
cd pack-recover
cargo build --release
sudo cp target/release/pack-recover /usr/local/bin/
```

### Using Cargo

```bash
cargo install --git https://github.com/thatjuan/pack-recover.git
```

## Dependencies

### For Native Mode (default with `--native`)

No external dependencies required - uses pure Rust libraries.

### For External CLI Mode (default)

Install the following tools:

**macOS (Homebrew):**
```bash
brew install p7zip unar
brew install --cask rar
```

**Ubuntu/Debian:**
```bash
sudo apt install p7zip-full unrar unar
```

**Arch Linux:**
```bash
sudo pacman -S p7zip unrar
yay -S unar  # from AUR
```

## Usage

### Basic Usage

```bash
# Recover password for a single archive
pack-recover -a archive.rar -w wordlist.txt

# Process multiple archives with glob pattern
pack-recover -a "*.7z" -w passwords.txt

# Use native Rust libraries (no external tools needed)
pack-recover -a archive.zip -w wordlist.txt --native
```

### Options

```
Usage: pack-recover [OPTIONS] [COMMAND]

Options:
  -a, --archive <PATTERN>    Glob pattern for archive files (e.g., "*.rar", "archives/*.7z")
  -w, --wordlist <PATH>      Path to password wordlist file
  -t, --threads <N>          Number of threads (default: number of CPU cores)
  -q, --quiet                Quiet mode - only output the found password
  -v, --verbose              Verbose mode - show each password attempt
      --limit <N>            Maximum number of passwords to try
      --offset <N>           Skip first N passwords (for resume/distributed cracking)
      --native               Use native Rust libraries instead of external CLI tools
      --unpack               Extract archive after password is found
      --delete               Delete archive after successful extraction (requires --unpack)
  -h, --help                 Print help
  -V, --version              Print version

Commands:
  clean                      Remove duplicate passwords from a wordlist
```

### Examples

```bash
# Basic password recovery
pack-recover -a secret.rar -w rockyou.txt

# Use 4 threads and show progress
pack-recover -a encrypted.7z -w wordlist.txt -t 4

# Quiet mode for scripting (only outputs password if found)
PASSWORD=$(pack-recover -a file.zip -w words.txt -q)

# Extract after finding password
pack-recover -a backup.rar -w passwords.txt --unpack

# Extract and delete original archive
pack-recover -a backup.rar -w passwords.txt --unpack --delete

# Process all RAR files in a directory
pack-recover -a "downloads/*.rar" -w wordlist.txt

# Resume from password #10000 (for distributed cracking)
pack-recover -a large.7z -w huge_wordlist.txt --offset 10000 --limit 10000

# Use native mode (no external tools required)
pack-recover -a archive.zip -w wordlist.txt --native

# Clean a wordlist (remove duplicates)
pack-recover clean -i wordlist_dirty.txt -o wordlist_clean.txt
```

### Distributed Cracking

Split a large wordlist across multiple machines:

```bash
# Machine 1: passwords 0-999999
pack-recover -a target.rar -w wordlist.txt --offset 0 --limit 1000000

# Machine 2: passwords 1000000-1999999
pack-recover -a target.rar -w wordlist.txt --offset 1000000 --limit 1000000

# Machine 3: passwords 2000000-2999999
pack-recover -a target.rar -w wordlist.txt --offset 2000000 --limit 1000000
```

## Encryption Types

pack-recover detects and handles different encryption types:

| Type | Description | Detection |
|------|-------------|-----------|
| **None** | Archive is not encrypted | Skipped automatically |
| **Content Only** | File contents encrypted, headers visible | File listing visible |
| **Header Encrypted** | Full encryption including file names | Cannot list contents |

## Performance

- Utilizes all available CPU cores by default
- Native mode is generally faster (no process spawning overhead)
- Progress updates every 10 passwords to minimize overhead
- Early termination when password is found

### Benchmarks

Typical performance on an 8-core machine:

| Mode | Passwords/sec |
|------|---------------|
| Native (ZIP) | ~50,000 |
| Native (RAR) | ~10,000 |
| Native (7z) | ~5,000 |
| CLI tools | ~1,000-5,000 |

*Actual performance depends on archive size, encryption method, and hardware.*

## Supported Formats

| Format | Extensions | Native Support | CLI Tools |
|--------|------------|----------------|-----------|
| RAR | `.rar` | Yes (unrar crate) | `unrar`, `lsar` |
| RAR5 | `.rar` | Yes | `unrar`, `lsar` |
| 7-Zip | `.7z` | Yes (sevenz-rust) | `7z` |
| ZIP | `.zip` | Yes (zip crate) | `unzip` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Password found (or archive not encrypted) |
| 1 | Password not found in wordlist |
| Other | Error occurred |

## Building from Source

```bash
# Clone the repository
git clone https://github.com/thatjuan/pack-recover.git
cd pack-recover

# Build release binary
make build

# Run tests (requires external tools)
make test

# Install to /usr/local/bin
sudo make install

# Uninstall
sudo make uninstall
```

## Development

```bash
# Run in debug mode
cargo run -- -a test.rar -w wordlist.txt

# Run tests
cargo test

# Run clippy
cargo clippy

# Format code
cargo fmt
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This tool is intended for legitimate password recovery purposes only, such as:
- Recovering passwords for your own archives
- Authorized penetration testing
- Security research

Do not use this tool to access archives you do not have permission to access.
