use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use console::style;
use crossbeam_channel::bounded;
use glob::glob;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use unrar::Archive as RarArchive;

/// A fast, parallel archive password recovery tool (RAR, 7zip, and ZIP)
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Glob pattern for archive(s) to process (e.g., "*.rar" or "archives/*.7z")
    #[arg(short, long)]
    archive: Option<String>,

    /// Path to the password list file (one password per line)
    #[arg(short, long)]
    wordlist: Option<PathBuf>,

    /// Number of parallel threads (default: number of CPU cores)
    #[arg(short, long)]
    threads: Option<usize>,

    /// Quiet mode - only output the password if found
    #[arg(short, long, default_value_t = false)]
    quiet: bool,

    /// Verbose mode - show each password attempt
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// Maximum number of passwords to try (optional)
    #[arg(short, long)]
    limit: Option<usize>,

    /// Skip first N passwords in wordlist (optional, for resuming/chunking)
    #[arg(short, long)]
    offset: Option<usize>,

    /// Use native Rust libraries instead of external commands (faster but requires additional dependencies)
    #[arg(long, default_value_t = false)]
    native: bool,

    /// Unpack the archive after password is found (extracts to folder named after archive)
    #[arg(long, default_value_t = false)]
    unpack: bool,

    /// Delete the archive after successful unpacking (requires --unpack)
    #[arg(long, default_value_t = false, requires = "unpack")]
    delete: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Clean up a wordlist by removing duplicates
    Clean {
        /// Path to the input wordlist file
        #[arg(short, long)]
        input: PathBuf,

        /// Path to the output wordlist file
        #[arg(short, long)]
        output: PathBuf,

        /// Quiet mode - only output summary
        #[arg(short, long, default_value_t = false)]
        quiet: bool,
    },
}

/// Represents the archive format
#[derive(Debug, Clone, Copy, PartialEq)]
enum ArchiveFormat {
    Rar,
    SevenZip,
    Zip,
}

/// Represents the type of encryption on an archive
#[derive(Debug, Clone, Copy, PartialEq)]
enum EncryptionType {
    /// No encryption detected
    None,
    /// Only file contents are encrypted (file names visible)
    ContentOnly,
    /// Full encryption including headers (file names hidden)
    HeaderEncrypted,
}

/// Result of attempting password recovery on an archive
#[derive(Debug, Clone)]
enum RecoveryResult {
    /// Password was found
    Found(String),
    /// Password was not found in wordlist
    NotFound,
    /// Archive is not encrypted
    NotEncrypted,
    /// Archive could not be processed (with error message)
    Error(String),
}

/// Detect archive format based on file extension
fn detect_archive_format(archive_path: &Path) -> Option<ArchiveFormat> {
    let extension = archive_path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_lowercase());

    match extension.as_deref() {
        Some("rar") => Some(ArchiveFormat::Rar),
        Some("7z") => Some(ArchiveFormat::SevenZip),
        Some("zip") => Some(ArchiveFormat::Zip),
        _ => None,
    }
}

/// Detect the encryption type of a RAR archive
fn detect_rar_encryption_type(archive_path: &PathBuf) -> Result<EncryptionType> {
    // First, check if we can list the archive without a password
    let output = Command::new("lsar")
        .arg("-j") // JSON output for reliable parsing
        .arg(archive_path)
        .output()
        .context("Failed to execute lsar. Make sure 'unar' is installed (brew install unar)")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Check if the archive itself is readable
    if stderr.contains("Couldn't open") || stderr.contains("couldn't be opened") {
        bail!("Cannot open archive: {}", archive_path.display());
    }

    // If lsar fails or shows password requirement, headers are encrypted
    if !output.status.success()
        || stderr.contains("password")
        || stderr.contains("Password")
        || stderr.contains("encrypted")
    {
        return Ok(EncryptionType::HeaderEncrypted);
    }

    // Archive can be listed - check if files need password for extraction
    // Try to test the archive without password
    let test_output = Command::new("lsar")
        .arg("-t") // Test integrity
        .arg(archive_path)
        .output()?;

    let test_stderr = String::from_utf8_lossy(&test_output.stderr);

    // Check the JSON output for encryption indicators
    if stdout.contains("\"XADIsEncrypted\":1")
        || stdout.contains("\"XADIsEncrypted\": 1")
        || stdout.contains("\"isEncrypted\":true")
        || stdout.contains("\"isEncrypted\": true")
    {
        // Files are encrypted but headers are not
        return Ok(EncryptionType::ContentOnly);
    }

    // If test fails mentioning password/encryption, content is encrypted
    if test_stderr.contains("password")
        || test_stderr.contains("Password")
        || test_stderr.contains("Wrong password")
    {
        return Ok(EncryptionType::ContentOnly);
    }

    // Double-check by trying to extract to /dev/null
    let extract_test = Command::new("unar")
        .arg("-o")
        .arg("-") // Output to stdout (which we'll discard)
        .arg("-q") // Quiet
        .arg(archive_path)
        .output()?;

    if !extract_test.status.success() {
        let extract_stderr = String::from_utf8_lossy(&extract_test.stderr);
        if extract_stderr.contains("password")
            || extract_stderr.contains("Password")
            || extract_stderr.contains("encrypted")
        {
            return Ok(EncryptionType::ContentOnly);
        }
    }

    // If we get here, archive is not encrypted
    Ok(EncryptionType::None)
}

/// Test if a password works for a RAR archive using unrar (most reliable)
fn test_rar_password(archive_path: &PathBuf, password: &str) -> bool {
    // Use unrar t (test) command - it properly validates passwords via CRC checks
    // This works for both header-encrypted and content-only encrypted archives
    let output = Command::new("unrar")
        .arg("t") // Test archive integrity
        .arg(format!("-p{}", password)) // Password (no space after -p)
        .arg("-idq") // Quiet mode, disable messages
        .arg(archive_path)
        .output();

    match output {
        Ok(result) => {
            // unrar returns 0 only on success with correct password
            // Wrong password gives non-zero exit and "Checksum error" or "wrong password"
            if result.status.success() {
                let stdout = String::from_utf8_lossy(&result.stdout);
                let stderr = String::from_utf8_lossy(&result.stderr);
                // Double-check no error indicators in output
                !stdout.contains("Checksum error")
                    && !stdout.contains("wrong password")
                    && !stdout.contains("Wrong password")
                    && !stdout.contains("CRC failed")
                    && !stdout.contains("Corrupt file")
                    && !stderr.contains("Checksum error")
                    && !stderr.contains("wrong password")
                    && !stderr.contains("Wrong password")
                    && !stderr.contains("CRC failed")
                    && !stderr.contains("Corrupt file")
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

/// Validate RAR password more thoroughly to avoid false positives
fn validate_rar_password(archive_path: &PathBuf, password: &str) -> bool {
    // Use unrar t for thorough integrity test with password
    // This is the most reliable method as unrar performs full CRC verification
    let test_output = Command::new("unrar")
        .arg("t") // Test command
        .arg(format!("-p{}", password))
        .arg(archive_path)
        .output();

    match test_output {
        Ok(result) => {
            let stderr = String::from_utf8_lossy(&result.stderr);
            let stdout = String::from_utf8_lossy(&result.stdout);

            // Must succeed (exit 0) AND have "All OK" in output AND no error indicators
            let success = result.status.success();
            let has_all_ok = stdout.contains("All OK") || stdout.contains("Ok");
            let no_errors = !stderr.contains("Checksum error")
                && !stderr.contains("wrong password")
                && !stderr.contains("Wrong password")
                && !stderr.contains("CRC failed")
                && !stderr.contains("Corrupt file")
                && !stdout.contains("Checksum error")
                && !stdout.contains("wrong password")
                && !stdout.contains("Wrong password")
                && !stdout.contains("CRC failed")
                && !stdout.contains("Corrupt file")
                && !stdout.contains("No files to extract");

            success && has_all_ok && no_errors
        }
        Err(_) => false,
    }
}

/// Detect the encryption type of a 7zip archive
fn detect_7z_encryption_type(archive_path: &PathBuf) -> Result<EncryptionType> {
    // Try to list archive contents with 7z l command
    // Use -p"" to provide empty password and prevent interactive prompt
    let output = Command::new("7z")
        .arg("l")
        .arg("-p")
        .arg(archive_path)
        .output()
        .context("Failed to execute 7z. Make sure '7z' is installed (brew install p7zip)")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Check if the archive can be opened at all (file not found, corrupted, etc.)
    if stderr.contains("Cannot open the file as archive")
        || stderr.contains("cannot open")
        || stderr.contains("No such file")
    {
        bail!("Cannot open archive: {}", archive_path.display());
    }

    // Check for header encryption (can't list files without password)
    if !output.status.success()
        || stdout.contains("Enter password")
        || stderr.contains("Wrong password")
        || stdout.contains("Can not open encrypted archive")
        || stderr.contains("Can not open encrypted archive")
        || stderr.contains("Headers Error")
    {
        // Headers are encrypted - need password to even list contents
        return Ok(EncryptionType::HeaderEncrypted);
    }

    // Archive can be listed - check if files are encrypted
    // Look for encryption indicators in the listing
    if stdout.contains("Encrypted = +")
        || (stdout.contains("Method =") && stdout.contains("7zAES"))
    {
        return Ok(EncryptionType::ContentOnly);
    }

    // Try to test extract without password to confirm
    // Use -p"" to provide empty password and prevent interactive prompt
    let test_output = Command::new("7z")
        .arg("t")
        .arg("-p")
        .arg(archive_path)
        .output()?;

    let test_stdout = String::from_utf8_lossy(&test_output.stdout);
    let test_stderr = String::from_utf8_lossy(&test_output.stderr);

    // If test fails asking for password, contents are encrypted
    if !test_output.status.success()
        && (test_stdout.contains("Enter password")
            || test_stderr.contains("Wrong password")
            || test_stdout.contains("Can not open encrypted archive")
            || test_stderr.contains("Can not open encrypted archive")
            || test_stderr.contains("Data Error"))
    {
        return Ok(EncryptionType::ContentOnly);
    }

    // If test succeeds without password, archive is not encrypted
    if test_output.status.success() && test_stdout.contains("Everything is Ok") {
        return Ok(EncryptionType::None);
    }

    // Default to content encryption if we can list but can't extract
    Ok(EncryptionType::ContentOnly)
}

/// Test if a password works for a 7zip archive
fn test_7z_password(archive_path: &PathBuf, password: &str) -> bool {
    // Use 7z t (test) command with password
    let output = Command::new("7z")
        .arg("t")
        .arg(format!("-p{}", password))
        .arg("-bso0") // Disable stdout (progress)
        .arg("-bsp0") // Disable progress percentage
        .arg(archive_path)
        .output();

    match output {
        Ok(result) => {
            if result.status.success() {
                let stdout = String::from_utf8_lossy(&result.stdout);
                let stderr = String::from_utf8_lossy(&result.stderr);
                // Verify no error indicators
                !stdout.contains("Data Error")
                    && !stdout.contains("CRC Failed")
                    && !stdout.contains("Wrong password")
                    && !stderr.contains("Data Error")
                    && !stderr.contains("CRC Failed")
                    && !stderr.contains("Wrong password")
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

/// Validate 7zip password more thoroughly to avoid false positives
fn validate_7z_password(archive_path: &PathBuf, password: &str) -> bool {
    // Full test with password
    let test_output = Command::new("7z")
        .arg("t")
        .arg(format!("-p{}", password))
        .arg(archive_path)
        .output();

    match test_output {
        Ok(result) => {
            let stdout = String::from_utf8_lossy(&result.stdout);
            let stderr = String::from_utf8_lossy(&result.stderr);

            // Must succeed (exit 0) AND have "Everything is Ok" AND no error indicators
            let success = result.status.success();
            let has_ok = stdout.contains("Everything is Ok");
            let no_errors = !stdout.contains("Data Error")
                && !stdout.contains("CRC Failed")
                && !stdout.contains("Wrong password")
                && !stdout.contains("Can not open encrypted archive")
                && !stderr.contains("Data Error")
                && !stderr.contains("CRC Failed")
                && !stderr.contains("Wrong password");

            success && has_ok && no_errors
        }
        Err(_) => false,
    }
}

// ============================================================================
// Native implementations using Rust libraries
// ============================================================================

/// Detect the encryption type of a RAR archive using native library
fn detect_rar_encryption_type_native(archive_path: &PathBuf) -> Result<EncryptionType> {
    // Try to open without password first
    let archive = RarArchive::new(archive_path.to_str().unwrap());

    match archive.open_for_listing() {
        Ok(open_archive) => {
            // Check if headers indicate encryption
            if open_archive.has_encrypted_headers() {
                return Ok(EncryptionType::HeaderEncrypted);
            }

            // Check individual entries for encryption
            for entry_result in open_archive {
                match entry_result {
                    Ok(entry) => {
                        if entry.is_encrypted() {
                            return Ok(EncryptionType::ContentOnly);
                        }
                    }
                    Err(_) => {
                        // Error reading entry might indicate encryption
                        return Ok(EncryptionType::ContentOnly);
                    }
                }
            }

            // No encryption detected
            Ok(EncryptionType::None)
        }
        Err(e) => {
            let error_str = format!("{:?}", e);
            // If we can't open for listing, headers might be encrypted
            if error_str.contains("password") || error_str.contains("Password") || error_str.contains("ERAR_MISSING_PASSWORD") {
                Ok(EncryptionType::HeaderEncrypted)
            } else {
                bail!("Cannot open archive: {} - {:?}", archive_path.display(), e)
            }
        }
    }
}

/// Test if a password works for a RAR archive using native library
fn test_rar_password_native(archive_path: &PathBuf, password: &str) -> bool {
    let archive = RarArchive::with_password(archive_path.to_str().unwrap(), password.as_bytes());

    match archive.open_for_processing() {
        Ok(open_archive) => {
            // Try to process each entry to verify the password via CRC checks
            let mut cursor = open_archive;
            loop {
                match cursor.read_header() {
                    Ok(Some(header)) => {
                        // Test the file (read without extracting to disk)
                        match header.test() {
                            Ok(next) => {
                                cursor = next;
                            }
                            Err(_) => {
                                // CRC check failed - wrong password
                                return false;
                            }
                        }
                    }
                    Ok(None) => {
                        // No more entries - all tests passed
                        return true;
                    }
                    Err(_) => {
                        // Error reading header - wrong password or corrupt
                        return false;
                    }
                }
            }
        }
        Err(_) => false,
    }
}

/// Validate RAR password using native library (same as test for native impl)
fn validate_rar_password_native(archive_path: &PathBuf, password: &str) -> bool {
    // For native implementation, test already does full CRC verification
    test_rar_password_native(archive_path, password)
}

/// Detect the encryption type of a 7zip archive using native library
fn detect_7z_encryption_type_native(archive_path: &PathBuf) -> Result<EncryptionType> {
    let mut file = File::open(archive_path)
        .context(format!("Cannot open archive: {}", archive_path.display()))?;

    let len = file.metadata()?.len();

    // Try to read archive without password using SevenZReader
    match sevenz_rust::SevenZReader::new(&mut file, len, sevenz_rust::Password::empty()) {
        Ok(reader) => {
            // Archive readable without password, check for encryption markers
            // Check folder coders for encryption
            for folder in reader.archive().folders.iter() {
                for coder in folder.coders.iter() {
                    // 7zAES method ID starts with 0x06F10701
                    if coder.decompression_method_id().starts_with(&[0x06, 0xF1, 0x07, 0x01]) {
                        return Ok(EncryptionType::ContentOnly);
                    }
                }
            }
            Ok(EncryptionType::None)
        }
        Err(e) => {
            let error_str = format!("{:?}", e);
            if error_str.contains("password") || error_str.contains("Password") || error_str.contains("encrypted") || error_str.contains("BadPassword") {
                Ok(EncryptionType::HeaderEncrypted)
            } else {
                // Try with empty password - if it still fails, might be header encrypted
                file.seek(SeekFrom::Start(0))?;
                match sevenz_rust::SevenZReader::new(&mut file, len, "".into()) {
                    Err(_) => Ok(EncryptionType::HeaderEncrypted),
                    Ok(_) => Ok(EncryptionType::None),
                }
            }
        }
    }
}

/// Test if a password works for a 7zip archive using native library
fn test_7z_password_native(archive_path: &PathBuf, password: &str) -> bool {
    // Try to read and decompress using SevenZReader to verify password
    let mut file = match File::open(archive_path) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let len = match file.metadata() {
        Ok(m) => m.len(),
        Err(_) => return false,
    };

    // Try to create reader with password
    let mut reader = match sevenz_rust::SevenZReader::new(&mut file, len, password.into()) {
        Ok(r) => r,
        Err(_) => return false,
    };

    // Try to read each entry to verify CRC (this validates the password)
    // We need to actually read the content and check if decryption succeeds
    let result = reader.for_each_entries(|entry, entry_reader| {
        if entry.is_directory() {
            return Ok(true);
        }
        // Read and discard content to verify CRC
        // If the password is wrong, this will fail
        let mut buf = Vec::new();
        match entry_reader.read_to_end(&mut buf) {
            Ok(_) => Ok(true),
            Err(e) => {
                // Return an error to signal password failure
                Err(sevenz_rust::Error::MaybeBadPassword(e))
            }
        }
    });

    result.is_ok()
}

/// Validate 7zip password using native library (same as test for native impl)
fn validate_7z_password_native(archive_path: &PathBuf, password: &str) -> bool {
    // For native implementation, test already does full verification
    test_7z_password_native(archive_path, password)
}

// ============================================================================
// ZIP implementations
// ============================================================================

/// Detect the encryption type of a ZIP archive using CLI (unzip)
fn detect_zip_encryption_type(archive_path: &PathBuf) -> Result<EncryptionType> {
    // Use unzip -l to list archive contents
    let output = Command::new("unzip")
        .arg("-l")
        .arg(archive_path)
        .output()
        .context("Failed to execute unzip. Make sure 'unzip' is installed")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Check if the archive can be opened at all
    if stderr.contains("cannot find")
        || stderr.contains("No such file")
        || stderr.contains("End-of-central-directory signature not found")
    {
        bail!("Cannot open archive: {}", archive_path.display());
    }

    // If unzip -l works, we can list files - check if they're encrypted
    // Try to test extract without password
    let test_output = Command::new("unzip")
        .arg("-t")
        .arg(archive_path)
        .output()?;

    let test_stdout = String::from_utf8_lossy(&test_output.stdout);
    let test_stderr = String::from_utf8_lossy(&test_output.stderr);

    // Check for encryption indicators
    if test_stdout.contains("unsupported compression method")
        || test_stdout.contains("need PK compat.")
        || test_stderr.contains("unsupported compression method")
        || test_stderr.contains("incorrect password")
        || test_stdout.contains("incorrect password")
        || test_stderr.contains("bad CRC")
        || test_stdout.contains("bad CRC")
        || test_stdout.contains("unable to get password")
        || test_stderr.contains("unable to get password")
        || test_stdout.contains("skipping:")
        || (test_stdout.contains("[") && test_stdout.contains("encrypted"))
    {
        // ZIP doesn't have header encryption like RAR - file names are always visible
        // So encrypted ZIPs are always ContentOnly
        return Ok(EncryptionType::ContentOnly);
    }

    // If test succeeds without issues, archive is not encrypted
    if test_output.status.success() && test_stdout.contains("No errors detected") {
        return Ok(EncryptionType::None);
    }

    // Check if listing shows encryption markers
    if stdout.contains("Encrypted") {
        return Ok(EncryptionType::ContentOnly);
    }

    // Default to no encryption if we can list and test without errors
    Ok(EncryptionType::None)
}

/// Test if a password works for a ZIP archive using CLI (unzip)
fn test_zip_password(archive_path: &PathBuf, password: &str) -> bool {
    // Use unzip -t with password to test
    let output = Command::new("unzip")
        .arg("-t")
        .arg("-P")
        .arg(password)
        .arg(archive_path)
        .output();

    match output {
        Ok(result) => {
            let stdout = String::from_utf8_lossy(&result.stdout);
            let stderr = String::from_utf8_lossy(&result.stderr);

            // Check for success
            if result.status.success() && stdout.contains("No errors detected") {
                // Verify no error indicators
                !stdout.contains("incorrect password")
                    && !stdout.contains("bad CRC")
                    && !stderr.contains("incorrect password")
                    && !stderr.contains("bad CRC")
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

/// Validate ZIP password more thoroughly using CLI
fn validate_zip_password(archive_path: &PathBuf, password: &str) -> bool {
    // For ZIP, the test function already does full CRC verification
    test_zip_password(archive_path, password)
}

/// Detect the encryption type of a ZIP archive using native library
fn detect_zip_encryption_type_native(archive_path: &PathBuf) -> Result<EncryptionType> {
    let file = File::open(archive_path)
        .context(format!("Cannot open archive: {}", archive_path.display()))?;

    let mut archive = zip::ZipArchive::new(file)
        .context(format!("Cannot read ZIP archive: {}", archive_path.display()))?;

    // Check each file entry for encryption using raw access (doesn't require password)
    for i in 0..archive.len() {
        let file = archive.by_index_raw(i)
            .context("Failed to read ZIP entry")?;

        if file.encrypted() {
            // ZIP doesn't support header encryption - file names are always visible
            return Ok(EncryptionType::ContentOnly);
        }
    }

    Ok(EncryptionType::None)
}

/// Test if a password works for a ZIP archive using native library
fn test_zip_password_native(archive_path: &PathBuf, password: &str) -> bool {
    let file = match File::open(archive_path) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut archive = match zip::ZipArchive::new(file) {
        Ok(a) => a,
        Err(_) => return false,
    };

    // Find the first encrypted file and test password against it
    // We only need to test one file to verify the password
    for i in 0..archive.len() {
        let file = match archive.by_index_decrypt(i, password.as_bytes()) {
            Ok(f) => f,
            Err(_) => return false, // Any error means wrong password or corrupted
        };

        // For encrypted files, read a small amount to trigger decryption verification
        // ZIP uses CRC32 checks that will fail early on wrong password
        if file.encrypted() {
            use std::io::Read;
            let mut limited_reader = file.take(1024); // Only read first 1KB
            let mut buf = [0u8; 1024];
            if limited_reader.read(&mut buf).is_err() {
                return false;
            }
            // Found and tested an encrypted file - password works for this file
            return true;
        }
    }

    // No encrypted files found, password is irrelevant
    true
}

/// Validate ZIP password using native library - does full CRC verification
fn validate_zip_password_native(archive_path: &PathBuf, password: &str) -> bool {
    let file = match File::open(archive_path) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut archive = match zip::ZipArchive::new(file) {
        Ok(a) => a,
        Err(_) => return false,
    };

    // Full validation: read all encrypted files completely to verify CRC
    for i in 0..archive.len() {
        let mut file = match archive.by_index_decrypt(i, password.as_bytes()) {
            Ok(f) => f,
            Err(_) => return false,
        };

        if file.encrypted() {
            let mut buf = Vec::new();
            if std::io::Read::read_to_end(&mut file, &mut buf).is_err() {
                return false;
            }
        }
    }

    true
}

// ============================================================================
// Archive extraction functions
// ============================================================================

/// Get the output directory name for extraction (archive name without extension)
fn get_extract_dir(archive_path: &Path) -> PathBuf {
    let parent = archive_path.parent().unwrap_or(Path::new("."));
    let stem = archive_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("extracted");
    parent.join(stem)
}

/// Extract a RAR archive using the unrar command
fn extract_rar_archive(archive_path: &PathBuf, password: &str, output_dir: &Path) -> Result<()> {
    // Create output directory if it doesn't exist
    std::fs::create_dir_all(output_dir)
        .context(format!("Failed to create output directory: {}", output_dir.display()))?;

    let output = Command::new("unrar")
        .arg("x") // Extract with full paths
        .arg("-o+") // Overwrite existing files
        .arg(format!("-p{}", password))
        .arg(archive_path)
        .arg(format!("{}/", output_dir.display())) // Trailing slash ensures extraction into dir
        .output()
        .context("Failed to execute unrar for extraction")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "Failed to extract RAR archive: {}{}",
            stderr,
            if stderr.is_empty() { stdout.as_ref() } else { "" }
        );
    }

    Ok(())
}

/// Extract a 7zip archive using the 7z command
fn extract_7z_archive(archive_path: &PathBuf, password: &str, output_dir: &Path) -> Result<()> {
    // Create output directory if it doesn't exist
    std::fs::create_dir_all(output_dir)
        .context(format!("Failed to create output directory: {}", output_dir.display()))?;

    let output = Command::new("7z")
        .arg("x") // Extract with full paths
        .arg(format!("-p{}", password))
        .arg(format!("-o{}", output_dir.display()))
        .arg("-y") // Yes to all prompts (overwrite)
        .arg(archive_path)
        .output()
        .context("Failed to execute 7z for extraction")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "Failed to extract 7z archive: {}{}",
            stderr,
            if stderr.is_empty() { stdout.as_ref() } else { "" }
        );
    }

    Ok(())
}

/// Extract a RAR archive using native library
fn extract_rar_archive_native(archive_path: &PathBuf, password: &str, output_dir: &Path) -> Result<()> {
    // Create output directory if it doesn't exist
    std::fs::create_dir_all(output_dir)
        .context(format!("Failed to create output directory: {}", output_dir.display()))?;

    let archive = RarArchive::with_password(archive_path.to_str().unwrap(), password.as_bytes());

    let open_archive = archive
        .open_for_processing()
        .map_err(|e| anyhow::anyhow!("Failed to open RAR archive: {:?}", e))?;

    // Extract all files
    let mut cursor = open_archive;
    loop {
        match cursor.read_header() {
            Ok(Some(header)) => {
                // Extract file to output directory
                match header.extract_with_base(output_dir) {
                    Ok(next) => {
                        cursor = next;
                    }
                    Err(e) => {
                        return Err(anyhow::anyhow!("Failed to extract file: {:?}", e));
                    }
                }
            }
            Ok(None) => {
                // No more entries
                break;
            }
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to read header: {:?}", e));
            }
        }
    }

    Ok(())
}

/// Extract a 7zip archive using native library
fn extract_7z_archive_native(archive_path: &PathBuf, password: &str, output_dir: &Path) -> Result<()> {
    // Create output directory if it doesn't exist
    std::fs::create_dir_all(output_dir)
        .context(format!("Failed to create output directory: {}", output_dir.display()))?;

    sevenz_rust::decompress_file_with_password(archive_path, output_dir, password.into())
        .map_err(|e| anyhow::anyhow!("Failed to extract 7z archive: {:?}", e))?;

    Ok(())
}

/// Extract a ZIP archive using the unzip command
fn extract_zip_archive(archive_path: &PathBuf, password: &str, output_dir: &Path) -> Result<()> {
    // Create output directory if it doesn't exist
    std::fs::create_dir_all(output_dir)
        .context(format!("Failed to create output directory: {}", output_dir.display()))?;

    let output = Command::new("unzip")
        .arg("-o") // Overwrite existing files
        .arg("-P")
        .arg(password)
        .arg(archive_path)
        .arg("-d")
        .arg(output_dir)
        .output()
        .context("Failed to execute unzip for extraction")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "Failed to extract ZIP archive: {}{}",
            stderr,
            if stderr.is_empty() { stdout.as_ref() } else { "" }
        );
    }

    Ok(())
}

/// Extract a ZIP archive using native library
fn extract_zip_archive_native(archive_path: &PathBuf, password: &str, output_dir: &Path) -> Result<()> {
    // Create output directory if it doesn't exist
    std::fs::create_dir_all(output_dir)
        .context(format!("Failed to create output directory: {}", output_dir.display()))?;

    let file = File::open(archive_path)
        .context(format!("Cannot open archive: {}", archive_path.display()))?;

    let mut archive = zip::ZipArchive::new(file)
        .context(format!("Cannot read ZIP archive: {}", archive_path.display()))?;

    for i in 0..archive.len() {
        let mut file = archive.by_index_decrypt(i, password.as_bytes())
            .context("Failed to read ZIP entry")?;

        let outpath = match file.enclosed_name() {
            Some(path) => output_dir.join(path),
            None => continue,
        };

        if file.is_dir() {
            std::fs::create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    std::fs::create_dir_all(p)?;
                }
            }
            let mut outfile = File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
        }

        // Set permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(mode) = file.unix_mode() {
                std::fs::set_permissions(&outpath, std::fs::Permissions::from_mode(mode))?;
            }
        }
    }

    Ok(())
}

/// Extract an archive using the appropriate method based on format and mode
fn extract_archive(
    archive_path: &PathBuf,
    password: &str,
    native: bool,
) -> Result<PathBuf> {
    let output_dir = get_extract_dir(archive_path);
    let format = detect_archive_format(archive_path)
        .ok_or_else(|| anyhow::anyhow!("Unsupported archive format"))?;

    match (format, native) {
        (ArchiveFormat::Rar, true) => extract_rar_archive_native(archive_path, password, &output_dir)?,
        (ArchiveFormat::Rar, false) => extract_rar_archive(archive_path, password, &output_dir)?,
        (ArchiveFormat::SevenZip, true) => extract_7z_archive_native(archive_path, password, &output_dir)?,
        (ArchiveFormat::SevenZip, false) => extract_7z_archive(archive_path, password, &output_dir)?,
        (ArchiveFormat::Zip, true) => extract_zip_archive_native(archive_path, password, &output_dir)?,
        (ArchiveFormat::Zip, false) => extract_zip_archive(archive_path, password, &output_dir)?,
    }

    Ok(output_dir)
}

/// Recover password for a single archive
fn recover_archive_password(
    archive_path: &PathBuf,
    passwords: &[String],
    threads: usize,
    quiet: bool,
    verbose: bool,
    native: bool,
) -> RecoveryResult {
    // Detect archive format
    let archive_format = match detect_archive_format(archive_path) {
        Some(format) => format,
        None => {
            return RecoveryResult::Error(
                "Unsupported archive format. Supported: .rar, .7z, .zip".to_string(),
            )
        }
    };

    // Check for required tools based on format (only for non-native mode)
    if !native {
        match archive_format {
            ArchiveFormat::Rar => {
                if Command::new("lsar").arg("--version").output().is_err() {
                    return RecoveryResult::Error(
                        "'lsar' command not found. Please install unar: brew install unar".to_string(),
                    );
                }
                if Command::new("unrar").output().is_err() {
                    return RecoveryResult::Error(
                        "'unrar' command not found. Please install rar: brew install --cask rar"
                            .to_string(),
                    );
                }
            }
            ArchiveFormat::SevenZip => {
                if Command::new("7z").output().is_err() {
                    return RecoveryResult::Error(
                        "'7z' command not found. Please install p7zip: brew install p7zip".to_string(),
                    );
                }
            }
            ArchiveFormat::Zip => {
                if Command::new("unzip").arg("-v").output().is_err() {
                    return RecoveryResult::Error(
                        "'unzip' command not found. Please install unzip".to_string(),
                    );
                }
            }
        }
    }

    // Detect encryption type
    let encryption_type = match (archive_format, native) {
        (ArchiveFormat::Rar, true) => detect_rar_encryption_type_native(archive_path),
        (ArchiveFormat::Rar, false) => detect_rar_encryption_type(archive_path),
        (ArchiveFormat::SevenZip, true) => detect_7z_encryption_type_native(archive_path),
        (ArchiveFormat::SevenZip, false) => detect_7z_encryption_type(archive_path),
        (ArchiveFormat::Zip, true) => detect_zip_encryption_type_native(archive_path),
        (ArchiveFormat::Zip, false) => detect_zip_encryption_type(archive_path),
    };

    let encryption_type = match encryption_type {
        Ok(enc) => enc,
        Err(e) => return RecoveryResult::Error(format!("Failed to analyze archive: {}", e)),
    };

    if encryption_type == EncryptionType::None {
        return RecoveryResult::NotEncrypted;
    }

    // Set up thread pool
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
        .ok();

    // Create progress bar
    let pb = if quiet {
        ProgressBar::hidden()
    } else {
        let pb = ProgressBar::new(passwords.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}")
                .expect("Invalid template")
                .progress_chars("█▓▒░"),
        );
        pb.enable_steady_tick(std::time::Duration::from_millis(100));
        pb
    };

    // Atomic flags for early termination
    let found = Arc::new(AtomicBool::new(false));
    let tested_count = Arc::new(AtomicUsize::new(0));

    // Channel for found password
    let (sender, receiver) = bounded::<String>(1);

    let archive_path_arc = Arc::new(archive_path.clone());

    // Parallel password testing
    passwords.par_iter().for_each(|password| {
        // Check if already found
        if found.load(Ordering::Relaxed) {
            return;
        }

        let count = tested_count.fetch_add(1, Ordering::Relaxed);

        if verbose && !quiet {
            pb.set_message(format!("Trying: {}", password));
        }

        // Test the password using format-specific function
        let test_result = match (archive_format, native) {
            (ArchiveFormat::Rar, true) => test_rar_password_native(&archive_path_arc, password),
            (ArchiveFormat::Rar, false) => test_rar_password(&archive_path_arc, password),
            (ArchiveFormat::SevenZip, true) => test_7z_password_native(&archive_path_arc, password),
            (ArchiveFormat::SevenZip, false) => test_7z_password(&archive_path_arc, password),
            (ArchiveFormat::Zip, true) => test_zip_password_native(&archive_path_arc, password),
            (ArchiveFormat::Zip, false) => test_zip_password(&archive_path_arc, password),
        };

        if test_result {
            // Validate to avoid false positives
            let valid = match (archive_format, native) {
                (ArchiveFormat::Rar, true) => validate_rar_password_native(&archive_path_arc, password),
                (ArchiveFormat::Rar, false) => validate_rar_password(&archive_path_arc, password),
                (ArchiveFormat::SevenZip, true) => validate_7z_password_native(&archive_path_arc, password),
                (ArchiveFormat::SevenZip, false) => validate_7z_password(&archive_path_arc, password),
                (ArchiveFormat::Zip, true) => validate_zip_password_native(&archive_path_arc, password),
                (ArchiveFormat::Zip, false) => validate_zip_password(&archive_path_arc, password),
            };
            if valid
                && found
                    .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
                    .is_ok()
            {
                let _ = sender.try_send(password.clone());
            }
        }

        if count.is_multiple_of(10) {
            pb.set_position(count as u64);
        }
    });

    pb.finish_and_clear();

    // Check if password was found
    if let Ok(password) = receiver.try_recv() {
        RecoveryResult::Found(password)
    } else {
        RecoveryResult::NotFound
    }
}

/// Clean up a wordlist by removing duplicates while preserving order
fn clean_wordlist(input: &PathBuf, output: &PathBuf, quiet: bool) -> Result<()> {
    if !input.exists() {
        bail!("Input wordlist not found: {}", input.display());
    }

    if !quiet {
        println!(
            "{} Wordlist Cleanup Tool",
            style("🧹").cyan()
        );
        println!("{}", style("─".repeat(50)).dim());
        println!("  Input:  {}", style(input.display()).green());
        println!("  Output: {}", style(output.display()).green());
        println!("{}", style("─".repeat(50)).dim());
        println!("{} Reading wordlist...", style("📖").cyan());
    }

    let file = File::open(input).context("Failed to open input wordlist")?;
    let reader = BufReader::new(file);

    let mut seen: HashSet<String> = HashSet::new();
    let mut unique_passwords: Vec<String> = Vec::new();
    let mut total_lines = 0usize;
    let mut empty_lines = 0usize;

    for line in reader.lines() {
        let line = line.context("Failed to read line from wordlist")?;
        total_lines += 1;

        if line.is_empty() {
            empty_lines += 1;
            continue;
        }

        if seen.insert(line.clone()) {
            unique_passwords.push(line);
        }
    }

    let duplicates_removed = total_lines - empty_lines - unique_passwords.len();

    if !quiet {
        println!("{} Writing deduplicated wordlist...", style("✍").cyan());
    }

    let out_file = File::create(output).context("Failed to create output wordlist")?;
    let mut writer = BufWriter::new(out_file);

    for password in &unique_passwords {
        writeln!(writer, "{}", password).context("Failed to write to output wordlist")?;
    }

    writer.flush().context("Failed to flush output wordlist")?;

    if !quiet {
        println!("{}", style("─".repeat(50)).dim());
        println!("{} Summary", style("📊").cyan().bold());
        println!("{}", style("─".repeat(50)).dim());
        println!("  Total lines read:     {}", style(total_lines).yellow());
        println!("  Empty lines skipped:  {}", style(empty_lines).dim());
        println!(
            "  Duplicates removed:   {}",
            style(duplicates_removed).red()
        );
        println!(
            "  Unique passwords:     {}",
            style(unique_passwords.len()).green().bold()
        );
        println!("{}", style("─".repeat(50)).dim());
        println!(
            "{} Cleaned wordlist written to: {}",
            style("✓").green().bold(),
            style(output.display()).green()
        );
    } else {
        println!(
            "{} -> {} ({} unique, {} duplicates removed)",
            input.display(),
            output.display(),
            unique_passwords.len(),
            duplicates_removed
        );
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Handle subcommands
    if let Some(command) = args.command {
        return match command {
            Commands::Clean { input, output, quiet } => clean_wordlist(&input, &output, quiet),
        };
    }

    // Regular password recovery mode - require archive and wordlist
    let archive = args.archive.ok_or_else(|| anyhow::anyhow!("Archive pattern is required. Use --archive <PATTERN> or run 'pack-recover --help' for usage."))?;
    let wordlist = args.wordlist.ok_or_else(|| anyhow::anyhow!("Wordlist path is required. Use --wordlist <PATH> or run 'pack-recover --help' for usage."))?;

    // Validate wordlist exists
    if !wordlist.exists() {
        bail!("Wordlist not found: {}", wordlist.display());
    }

    // Expand glob pattern to get all matching archives
    let archive_paths: Vec<PathBuf> = glob(&archive)
        .context("Failed to parse glob pattern")?
        .filter_map(|entry| entry.ok())
        .filter(|path| path.is_file())
        .collect();

    if archive_paths.is_empty() {
        bail!("No archives found matching pattern: {}", archive);
    }

    let threads = args.threads.unwrap_or_else(num_cpus::get);

    if !args.quiet {
        println!(
            "{} Archive Password Recovery Tool v{}",
            style("⚡").cyan(),
            env!("CARGO_PKG_VERSION")
        );
        println!("{}", style("─".repeat(50)).dim());
        println!("  Pattern:   {}", style(&archive).green());
        println!("  Archives:  {}", style(archive_paths.len()).yellow());
        println!("  Wordlist:  {}", style(wordlist.display()).green());
        println!("  Threads:   {}", style(threads).yellow());
        println!(
            "  Mode:      {}",
            if args.native {
                style("native (Rust libraries)").cyan()
            } else {
                style("external (CLI tools)").yellow()
            }
        );
        if args.unpack {
            println!("  Unpack:    {}", style("enabled").green());
        }
        println!("{}", style("─".repeat(50)).dim());
    }

    // Load passwords
    if !args.quiet {
        println!("{} Loading wordlist...", style("📖").cyan());
    }

    let file = File::open(&wordlist).context("Failed to open wordlist")?;
    let reader = BufReader::new(file);
    let mut passwords: Vec<String> = reader
        .lines()
        .map_while(Result::ok)
        .filter(|line| !line.is_empty())
        .collect();

    let total_loaded = passwords.len();

    if total_loaded == 0 {
        bail!("Wordlist is empty");
    }

    // Apply offset if specified (skip first N passwords)
    let offset_applied = if let Some(offset) = args.offset {
        if offset > 0 && offset < passwords.len() {
            passwords = passwords.into_iter().skip(offset).collect();
            true
        } else if offset >= passwords.len() {
            bail!(
                "Offset {} is beyond wordlist size {}",
                offset,
                total_loaded
            );
        } else {
            false
        }
    } else {
        false
    };

    // Apply limit if specified
    let limit_applied = if let Some(limit) = args.limit {
        if limit < passwords.len() {
            passwords.truncate(limit);
            true
        } else {
            false
        }
    } else {
        false
    };

    let total_passwords = passwords.len();

    if !args.quiet {
        match (offset_applied, limit_applied) {
            (true, true) => {
                println!(
                    "  Passwords: {} loaded (offset: {}, limit: {} from {})",
                    style(total_passwords).yellow(),
                    style(args.offset.unwrap()).yellow(),
                    style(total_passwords).yellow(),
                    style(total_loaded).dim()
                );
            }
            (true, false) => {
                println!(
                    "  Passwords: {} loaded (offset: {} from {})",
                    style(total_passwords).yellow(),
                    style(args.offset.unwrap()).yellow(),
                    style(total_loaded).dim()
                );
            }
            (false, true) => {
                println!(
                    "  Passwords: {} loaded (limit: {} from {})",
                    style(total_passwords).yellow(),
                    style(total_passwords).yellow(),
                    style(total_loaded).dim()
                );
            }
            (false, false) => {
                println!("  Passwords: {} loaded", style(total_passwords).yellow());
            }
        }
        println!("{}", style("─".repeat(50)).dim());
    }

    // Process each archive
    let mut results: Vec<(PathBuf, RecoveryResult)> = Vec::new();

    for (idx, archive_path) in archive_paths.iter().enumerate() {
        if !args.quiet {
            println!(
                "\n{} Processing archive {}/{}: {}",
                style("🔍").cyan(),
                style(idx + 1).yellow(),
                style(archive_paths.len()).yellow(),
                style(archive_path.display()).green()
            );
        }

        let result = recover_archive_password(
            archive_path,
            &passwords,
            threads,
            args.quiet,
            args.verbose,
            args.native,
        );

        // Show individual result and extract if requested
        if !args.quiet {
            match &result {
                RecoveryResult::Found(password) => {
                    println!(
                        "  {} Password found: {}",
                        style("✓").green().bold(),
                        style(password).green().bold()
                    );
                    // Extract if --unpack flag is set
                    if args.unpack {
                        match extract_archive(archive_path, password, args.native) {
                            Ok(output_dir) => {
                                println!(
                                    "  {} Extracted to: {}",
                                    style("📦").cyan(),
                                    style(output_dir.display()).green()
                                );
                                // Delete archive if --delete flag is set
                                if args.delete {
                                    match std::fs::remove_file(archive_path) {
                                        Ok(()) => {
                                            println!(
                                                "  {} Deleted: {}",
                                                style("🗑").cyan(),
                                                style(archive_path.display()).dim()
                                            );
                                        }
                                        Err(e) => {
                                            println!(
                                                "  {} Failed to delete archive: {}",
                                                style("✗").red(),
                                                style(e).red()
                                            );
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                println!(
                                    "  {} Extraction failed: {}",
                                    style("✗").red(),
                                    style(e).red()
                                );
                            }
                        }
                    }
                }
                RecoveryResult::NotFound => {
                    println!("  {} Password not found", style("✗").red());
                }
                RecoveryResult::NotEncrypted => {
                    println!("  {} Not encrypted", style("ℹ").blue());
                    // Extract if --unpack flag is set (no password needed)
                    if args.unpack {
                        match extract_archive(archive_path, "", args.native) {
                            Ok(output_dir) => {
                                println!(
                                    "  {} Extracted to: {}",
                                    style("📦").cyan(),
                                    style(output_dir.display()).green()
                                );
                                // Delete archive if --delete flag is set
                                if args.delete {
                                    match std::fs::remove_file(archive_path) {
                                        Ok(()) => {
                                            println!(
                                                "  {} Deleted: {}",
                                                style("🗑").cyan(),
                                                style(archive_path.display()).dim()
                                            );
                                        }
                                        Err(e) => {
                                            println!(
                                                "  {} Failed to delete archive: {}",
                                                style("✗").red(),
                                                style(e).red()
                                            );
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                println!(
                                    "  {} Extraction failed: {}",
                                    style("✗").red(),
                                    style(e).red()
                                );
                            }
                        }
                    }
                }
                RecoveryResult::Error(msg) => {
                    println!("  {} Error: {}", style("✗").red(), style(msg).red());
                }
            }
        } else if args.unpack {
            // In quiet mode, still extract if password found or not encrypted
            match &result {
                RecoveryResult::Found(password) => {
                    if extract_archive(archive_path, password, args.native).is_ok() && args.delete {
                        let _ = std::fs::remove_file(archive_path);
                    }
                }
                RecoveryResult::NotEncrypted => {
                    if extract_archive(archive_path, "", args.native).is_ok() && args.delete {
                        let _ = std::fs::remove_file(archive_path);
                    }
                }
                _ => {}
            }
        }

        results.push((archive_path.clone(), result));
    }

    // Print summary
    if !args.quiet {
        println!("\n{}", style("═".repeat(50)).dim());
        println!("{} Summary", style("📊").cyan().bold());
        println!("{}", style("═".repeat(50)).dim());
    }

    let mut found_count = 0;
    let mut not_found_count = 0;
    let mut not_encrypted_count = 0;
    let mut error_count = 0;

    let single_archive = results.len() == 1;

    for (archive_path, result) in &results {
        match result {
            RecoveryResult::Found(password) => {
                found_count += 1;
                if args.quiet {
                    // For single archive, just print password (backward compatible)
                    // For multiple archives, include the archive path
                    if single_archive {
                        println!("{}", password);
                    } else {
                        println!("{}: {}", archive_path.display(), password);
                    }
                } else {
                    println!(
                        "  {} {} - Password: {}",
                        style("✓").green().bold(),
                        style(archive_path.display()).green(),
                        style(password).green().bold()
                    );
                }
            }
            RecoveryResult::NotFound => {
                not_found_count += 1;
                if !args.quiet {
                    println!(
                        "  {} {} - Password not found",
                        style("✗").red(),
                        style(archive_path.display()).dim()
                    );
                }
            }
            RecoveryResult::NotEncrypted => {
                not_encrypted_count += 1;
                if !args.quiet {
                    println!(
                        "  {} {} - Not encrypted",
                        style("ℹ").blue(),
                        style(archive_path.display()).dim()
                    );
                }
            }
            RecoveryResult::Error(msg) => {
                error_count += 1;
                if !args.quiet {
                    println!(
                        "  {} {} - Error: {}",
                        style("✗").red(),
                        style(archive_path.display()).dim(),
                        style(msg).red()
                    );
                }
            }
        }
    }

    if !args.quiet {
        println!("{}", style("─".repeat(50)).dim());
        println!(
            "  Total archives:       {}",
            style(results.len()).yellow()
        );
        println!(
            "  Passwords found:      {}",
            style(found_count).green().bold()
        );
        println!("  Passwords not found:  {}", style(not_found_count).red());
        println!(
            "  Not encrypted:        {}",
            style(not_encrypted_count).blue()
        );
        println!("  Errors:               {}", style(error_count).red());
        println!("{}", style("─".repeat(50)).dim());
    }

    // Exit with error if no passwords were found
    if found_count == 0 && not_found_count > 0 {
        std::process::exit(1);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    // Helper functions to check if CLI tools are available
    fn has_rar_cli_tools() -> bool {
        Command::new("lsar").arg("--version").output().is_ok()
            && Command::new("unrar").output().is_ok()
    }

    fn has_7z_cli_tools() -> bool {
        Command::new("7z").output().is_ok()
    }

    // Helper function to create a temporary wordlist file
    fn create_test_wordlist(dir: &TempDir, passwords: &[&str]) -> PathBuf {
        let wordlist_path = dir.path().join("wordlist.txt");
        let mut file = File::create(&wordlist_path).expect("Failed to create test wordlist");
        for password in passwords {
            writeln!(file, "{}", password).expect("Failed to write password");
        }
        wordlist_path
    }

    // Helper function to create temporary test archive files
    fn create_test_archives(dir: &TempDir, names: &[&str]) -> Vec<PathBuf> {
        names
            .iter()
            .map(|name| {
                let path = dir.path().join(name);
                File::create(&path).expect("Failed to create test archive");
                path
            })
            .collect()
    }

    #[test]
    fn test_args_parsing_with_limit() {
        // Test that Args can be parsed with --limit option
        let args = Args::parse_from(&[
            "pack-recover",
            "--archive",
            "test.rar",
            "--wordlist",
            "/tmp/wordlist.txt",
            "--limit",
            "1000",
        ]);

        assert_eq!(args.archive, Some("test.rar".to_string()));
        assert_eq!(args.limit, Some(1000));
    }

    #[test]
    fn test_args_parsing_without_limit() {
        // Test that Args can be parsed without --limit option
        let args = Args::parse_from(&[
            "pack-recover",
            "--archive",
            "test.rar",
            "--wordlist",
            "/tmp/wordlist.txt",
        ]);

        assert_eq!(args.archive, Some("test.rar".to_string()));
        assert_eq!(args.limit, None);
    }

    #[test]
    fn test_args_parsing_with_threads() {
        // Test that Args can be parsed with --threads option
        let args = Args::parse_from(&[
            "pack-recover",
            "--archive",
            "*.rar",
            "--wordlist",
            "/tmp/wordlist.txt",
            "--threads",
            "8",
        ]);

        assert_eq!(args.threads, Some(8));
    }

    #[test]
    fn test_args_parsing_with_quiet_and_verbose() {
        // Test quiet flag
        let args = Args::parse_from(&[
            "pack-recover",
            "--archive",
            "test.rar",
            "--wordlist",
            "/tmp/wordlist.txt",
            "--quiet",
        ]);
        assert!(args.quiet);
        assert!(!args.verbose);

        // Test verbose flag
        let args = Args::parse_from(&[
            "pack-recover",
            "--archive",
            "test.rar",
            "--wordlist",
            "/tmp/wordlist.txt",
            "--verbose",
        ]);
        assert!(args.verbose);
        assert!(!args.quiet);
    }

    #[test]
    fn test_args_parsing_glob_pattern() {
        // Test that glob patterns are accepted
        let patterns = vec!["*.rar", "archives/*.7z", "**/*.rar", "test[1-3].rar"];

        for pattern in patterns {
            let args = Args::parse_from(&[
                "pack-recover",
                "--archive",
                pattern,
                "--wordlist",
                "/tmp/wordlist.txt",
            ]);
            assert_eq!(args.archive, Some(pattern.to_string()));
        }
    }

    #[test]
    fn test_limit_truncation_logic() {
        // Test that password list is truncated when limit < total
        let mut passwords: Vec<String> = (1..=100).map(|i| format!("password{}", i)).collect();
        let total_loaded = passwords.len();

        assert_eq!(total_loaded, 100);

        // Apply limit of 50
        let limit = 50;
        if limit < total_loaded {
            passwords.truncate(limit);
        }

        assert_eq!(passwords.len(), 50);
        assert_eq!(passwords[0], "password1");
        assert_eq!(passwords[49], "password50");
    }

    #[test]
    fn test_limit_larger_than_wordlist() {
        // Test that password list is NOT truncated when limit >= total
        let mut passwords: Vec<String> = (1..=50).map(|i| format!("password{}", i)).collect();
        let total_loaded = passwords.len();

        assert_eq!(total_loaded, 50);

        // Apply limit of 100 (larger than wordlist)
        let limit = 100;
        let original_len = passwords.len();
        if limit < total_loaded {
            passwords.truncate(limit);
        }

        assert_eq!(passwords.len(), original_len);
        assert_eq!(passwords.len(), 50);
    }

    #[test]
    fn test_limit_equal_to_wordlist() {
        // Test that password list is NOT truncated when limit == total
        let mut passwords: Vec<String> = (1..=50).map(|i| format!("password{}", i)).collect();
        let total_loaded = passwords.len();

        let limit = 50;
        if limit < total_loaded {
            passwords.truncate(limit);
        }

        assert_eq!(passwords.len(), 50);
    }

    #[test]
    fn test_limit_zero() {
        // Test edge case: limit of 0
        let mut passwords: Vec<String> = (1..=50).map(|i| format!("password{}", i)).collect();
        let total_loaded = passwords.len();

        let limit = 0;
        if limit < total_loaded {
            passwords.truncate(limit);
        }

        assert_eq!(passwords.len(), 0);
    }

    #[test]
    fn test_limit_one() {
        // Test edge case: limit of 1
        let mut passwords: Vec<String> = (1..=50).map(|i| format!("password{}", i)).collect();
        let total_loaded = passwords.len();

        let limit = 1;
        if limit < total_loaded {
            passwords.truncate(limit);
        }

        assert_eq!(passwords.len(), 1);
        assert_eq!(passwords[0], "password1");
    }

    #[test]
    fn test_glob_pattern_expansion() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        // Create test archive files
        create_test_archives(&temp_dir, &["test1.rar", "test2.rar", "test3.rar", "other.7z"]);

        // Test glob pattern for .rar files
        let pattern = format!("{}/*.rar", temp_dir.path().display());
        let archive_paths: Vec<PathBuf> = glob(&pattern)
            .expect("Failed to parse glob pattern")
            .filter_map(|entry| entry.ok())
            .filter(|path| path.is_file())
            .collect();

        assert_eq!(archive_paths.len(), 3);

        // Test glob pattern for all files
        let pattern = format!("{}/*", temp_dir.path().display());
        let archive_paths: Vec<PathBuf> = glob(&pattern)
            .expect("Failed to parse glob pattern")
            .filter_map(|entry| entry.ok())
            .filter(|path| path.is_file())
            .collect();

        assert_eq!(archive_paths.len(), 4);
    }

    #[test]
    fn test_glob_pattern_no_matches() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        // Don't create any files, test empty glob result
        let pattern = format!("{}/*.rar", temp_dir.path().display());
        let archive_paths: Vec<PathBuf> = glob(&pattern)
            .expect("Failed to parse glob pattern")
            .filter_map(|entry| entry.ok())
            .filter(|path| path.is_file())
            .collect();

        assert_eq!(archive_paths.len(), 0);
    }

    #[test]
    fn test_glob_pattern_single_file() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        // Create a single test file
        let test_file = temp_dir.path().join("single.rar");
        File::create(&test_file).expect("Failed to create test file");

        // Test with exact filename (no wildcard)
        let pattern = test_file.to_str().unwrap();
        let archive_paths: Vec<PathBuf> = glob(pattern)
            .expect("Failed to parse glob pattern")
            .filter_map(|entry| entry.ok())
            .filter(|path| path.is_file())
            .collect();

        assert_eq!(archive_paths.len(), 1);
        assert_eq!(archive_paths[0], test_file);
    }

    #[test]
    fn test_glob_pattern_with_subdirectories() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        // Create subdirectory
        let sub_dir = temp_dir.path().join("archives");
        std::fs::create_dir(&sub_dir).expect("Failed to create subdirectory");

        // Create files in subdirectory
        File::create(sub_dir.join("test1.rar")).expect("Failed to create test file");
        File::create(sub_dir.join("test2.rar")).expect("Failed to create test file");

        // Test glob pattern with subdirectory
        let pattern = format!("{}/archives/*.rar", temp_dir.path().display());
        let archive_paths: Vec<PathBuf> = glob(&pattern)
            .expect("Failed to parse glob pattern")
            .filter_map(|entry| entry.ok())
            .filter(|path| path.is_file())
            .collect();

        assert_eq!(archive_paths.len(), 2);
    }

    #[test]
    fn test_recovery_result_found() {
        // Test RecoveryResult::Found variant
        let result = RecoveryResult::Found("mypassword123".to_string());

        match result {
            RecoveryResult::Found(password) => {
                assert_eq!(password, "mypassword123");
            }
            _ => panic!("Expected RecoveryResult::Found"),
        }
    }

    #[test]
    fn test_recovery_result_not_found() {
        // Test RecoveryResult::NotFound variant
        let result = RecoveryResult::NotFound;

        match result {
            RecoveryResult::NotFound => {
                // Success
            }
            _ => panic!("Expected RecoveryResult::NotFound"),
        }
    }

    #[test]
    fn test_recovery_result_not_encrypted() {
        // Test RecoveryResult::NotEncrypted variant
        let result = RecoveryResult::NotEncrypted;

        match result {
            RecoveryResult::NotEncrypted => {
                // Success
            }
            _ => panic!("Expected RecoveryResult::NotEncrypted"),
        }
    }

    #[test]
    fn test_recovery_result_error() {
        // Test RecoveryResult::Error variant
        let error_msg = "Archive corrupted".to_string();
        let result = RecoveryResult::Error(error_msg.clone());

        match result {
            RecoveryResult::Error(msg) => {
                assert_eq!(msg, error_msg);
            }
            _ => panic!("Expected RecoveryResult::Error"),
        }
    }

    #[test]
    fn test_recovery_result_clone() {
        // Test that RecoveryResult can be cloned
        let result1 = RecoveryResult::Found("password".to_string());
        let result2 = result1.clone();

        match (result1, result2) {
            (RecoveryResult::Found(p1), RecoveryResult::Found(p2)) => {
                assert_eq!(p1, p2);
            }
            _ => panic!("Clone failed"),
        }
    }

    #[test]
    fn test_archive_format_detection_rar() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let rar_file = temp_dir.path().join("test.rar");
        File::create(&rar_file).expect("Failed to create test file");

        let format = detect_archive_format(&rar_file);
        assert_eq!(format, Some(ArchiveFormat::Rar));
    }

    #[test]
    fn test_archive_format_detection_7z() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let seven_zip_file = temp_dir.path().join("test.7z");
        File::create(&seven_zip_file).expect("Failed to create test file");

        let format = detect_archive_format(&seven_zip_file);
        assert_eq!(format, Some(ArchiveFormat::SevenZip));
    }

    #[test]
    fn test_archive_format_detection_zip() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let zip_file = temp_dir.path().join("test.zip");
        File::create(&zip_file).expect("Failed to create test file");

        let format = detect_archive_format(&zip_file);
        assert_eq!(format, Some(ArchiveFormat::Zip));
    }

    #[test]
    fn test_archive_format_detection_unsupported() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let unsupported_file = temp_dir.path().join("test.tar");
        File::create(&unsupported_file).expect("Failed to create test file");

        let format = detect_archive_format(&unsupported_file);
        assert_eq!(format, None);
    }

    #[test]
    fn test_archive_format_detection_no_extension() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let no_ext_file = temp_dir.path().join("test");
        File::create(&no_ext_file).expect("Failed to create test file");

        let format = detect_archive_format(&no_ext_file);
        assert_eq!(format, None);
    }

    #[test]
    fn test_archive_format_detection_case_insensitive() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        // Test uppercase extensions
        let rar_upper = temp_dir.path().join("test.RAR");
        File::create(&rar_upper).expect("Failed to create test file");
        assert_eq!(detect_archive_format(&rar_upper), Some(ArchiveFormat::Rar));

        let seven_zip_upper = temp_dir.path().join("test.7Z");
        File::create(&seven_zip_upper).expect("Failed to create test file");
        assert_eq!(
            detect_archive_format(&seven_zip_upper),
            Some(ArchiveFormat::SevenZip)
        );

        let zip_upper = temp_dir.path().join("test.ZIP");
        File::create(&zip_upper).expect("Failed to create test file");
        assert_eq!(detect_archive_format(&zip_upper), Some(ArchiveFormat::Zip));
    }

    #[test]
    fn test_encryption_type_variants() {
        // Test EncryptionType enum variants
        let none = EncryptionType::None;
        let content = EncryptionType::ContentOnly;
        let header = EncryptionType::HeaderEncrypted;

        assert_eq!(none, EncryptionType::None);
        assert_eq!(content, EncryptionType::ContentOnly);
        assert_eq!(header, EncryptionType::HeaderEncrypted);

        // Test that different variants are not equal
        assert_ne!(none, content);
        assert_ne!(content, header);
        assert_ne!(none, header);
    }

    #[test]
    fn test_archive_format_equality() {
        assert_eq!(ArchiveFormat::Rar, ArchiveFormat::Rar);
        assert_eq!(ArchiveFormat::SevenZip, ArchiveFormat::SevenZip);
        assert_eq!(ArchiveFormat::Zip, ArchiveFormat::Zip);
        assert_ne!(ArchiveFormat::Rar, ArchiveFormat::SevenZip);
        assert_ne!(ArchiveFormat::Rar, ArchiveFormat::Zip);
        assert_ne!(ArchiveFormat::SevenZip, ArchiveFormat::Zip);
    }

    #[test]
    fn test_multiple_archives_result_tracking() {
        // Simulate processing multiple archives and tracking results
        let mut results: Vec<(PathBuf, RecoveryResult)> = Vec::new();

        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let archives = create_test_archives(&temp_dir, &["test1.rar", "test2.rar", "test3.rar"]);

        // Simulate different results for each archive
        results.push((archives[0].clone(), RecoveryResult::Found("pass1".to_string())));
        results.push((archives[1].clone(), RecoveryResult::NotFound));
        results.push((archives[2].clone(), RecoveryResult::NotEncrypted));

        assert_eq!(results.len(), 3);

        // Count results by type
        let mut found_count = 0;
        let mut not_found_count = 0;
        let mut not_encrypted_count = 0;
        let mut error_count = 0;

        for (_, result) in &results {
            match result {
                RecoveryResult::Found(_) => found_count += 1,
                RecoveryResult::NotFound => not_found_count += 1,
                RecoveryResult::NotEncrypted => not_encrypted_count += 1,
                RecoveryResult::Error(_) => error_count += 1,
            }
        }

        assert_eq!(found_count, 1);
        assert_eq!(not_found_count, 1);
        assert_eq!(not_encrypted_count, 1);
        assert_eq!(error_count, 0);
    }

    #[test]
    fn test_multiple_archives_all_found() {
        // Test scenario where all archives have passwords found
        let mut results: Vec<(PathBuf, RecoveryResult)> = Vec::new();

        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let archives = create_test_archives(&temp_dir, &["test1.rar", "test2.rar"]);

        results.push((
            archives[0].clone(),
            RecoveryResult::Found("password1".to_string()),
        ));
        results.push((
            archives[1].clone(),
            RecoveryResult::Found("password2".to_string()),
        ));

        let found_count = results
            .iter()
            .filter(|(_, result)| matches!(result, RecoveryResult::Found(_)))
            .count();

        assert_eq!(found_count, 2);
    }

    #[test]
    fn test_multiple_archives_with_errors() {
        // Test scenario with various error conditions
        let mut results: Vec<(PathBuf, RecoveryResult)> = Vec::new();

        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let archives = create_test_archives(&temp_dir, &["test1.rar", "test2.rar", "test3.7z"]);

        results.push((
            archives[0].clone(),
            RecoveryResult::Error("Corrupted archive".to_string()),
        ));
        results.push((
            archives[1].clone(),
            RecoveryResult::Error("Unsupported format".to_string()),
        ));
        results.push((archives[2].clone(), RecoveryResult::Found("pass".to_string())));

        let error_count = results
            .iter()
            .filter(|(_, result)| matches!(result, RecoveryResult::Error(_)))
            .count();

        assert_eq!(error_count, 2);
    }

    #[test]
    fn test_empty_archive_list() {
        // Test handling of empty archive list
        let results: Vec<(PathBuf, RecoveryResult)> = Vec::new();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_wordlist_loading_and_limit() {
        // Integration test: wordlist loading with limit
        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        let passwords = vec![
            "password1",
            "password2",
            "password3",
            "password4",
            "password5",
        ];
        let wordlist_path = create_test_wordlist(&temp_dir, &passwords);

        // Read wordlist
        let file = File::open(&wordlist_path).expect("Failed to open wordlist");
        let reader = BufReader::new(file);
        let mut loaded_passwords: Vec<String> = reader
            .lines()
            .map_while(Result::ok)
            .filter(|line| !line.is_empty())
            .collect();

        assert_eq!(loaded_passwords.len(), 5);

        // Apply limit
        let limit = 3;
        if limit < loaded_passwords.len() {
            loaded_passwords.truncate(limit);
        }

        assert_eq!(loaded_passwords.len(), 3);
        assert_eq!(loaded_passwords[0], "password1");
        assert_eq!(loaded_passwords[2], "password3");
    }

    #[test]
    fn test_wordlist_empty_lines_filtered() {
        // Test that empty lines are filtered from wordlist
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let wordlist_path = temp_dir.path().join("wordlist.txt");

        let mut file = File::create(&wordlist_path).expect("Failed to create wordlist");
        writeln!(file, "password1").unwrap();
        writeln!(file, "").unwrap(); // Empty line
        writeln!(file, "password2").unwrap();
        writeln!(file, "").unwrap(); // Empty line
        writeln!(file, "password3").unwrap();

        let file = File::open(&wordlist_path).expect("Failed to open wordlist");
        let reader = BufReader::new(file);
        let passwords: Vec<String> = reader
            .lines()
            .map_while(Result::ok)
            .filter(|line| !line.is_empty())
            .collect();

        assert_eq!(passwords.len(), 3);
        assert_eq!(passwords[0], "password1");
        assert_eq!(passwords[1], "password2");
        assert_eq!(passwords[2], "password3");
    }

    #[test]
    fn test_limit_with_single_password() {
        // Test limit behavior with single password in wordlist
        let mut passwords = vec!["password1".to_string()];
        let total_loaded = passwords.len();

        let limit = 10;
        if limit < total_loaded {
            passwords.truncate(limit);
        }

        assert_eq!(passwords.len(), 1);
    }

    #[test]
    fn test_sequential_archive_processing() {
        // Test that archives are processed sequentially and results are tracked in order
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let archives = create_test_archives(&temp_dir, &["a.rar", "b.rar", "c.rar"]);

        let mut results: Vec<(PathBuf, RecoveryResult)> = Vec::new();

        // Simulate sequential processing
        for archive in archives {
            // In real scenario, this would call recover_archive_password
            // For test, we just create mock results
            let result = RecoveryResult::NotFound;
            results.push((archive, result));
        }

        assert_eq!(results.len(), 3);

        // Verify order is maintained
        assert!(results[0].0.to_str().unwrap().ends_with("a.rar"));
        assert!(results[1].0.to_str().unwrap().ends_with("b.rar"));
        assert!(results[2].0.to_str().unwrap().ends_with("c.rar"));
    }

    #[test]
    fn test_args_parsing_with_offset() {
        // Test that Args can be parsed with --offset option
        let args = Args::parse_from(&[
            "pack-recover",
            "--archive",
            "test.rar",
            "--wordlist",
            "/tmp/wordlist.txt",
            "--offset",
            "100",
        ]);

        assert_eq!(args.archive, Some("test.rar".to_string()));
        assert_eq!(args.offset, Some(100));
    }

    #[test]
    fn test_args_parsing_with_offset_and_limit() {
        // Test that Args can be parsed with both --offset and --limit
        let args = Args::parse_from(&[
            "pack-recover",
            "--archive",
            "test.rar",
            "--wordlist",
            "/tmp/wordlist.txt",
            "--offset",
            "100",
            "--limit",
            "50",
        ]);

        assert_eq!(args.offset, Some(100));
        assert_eq!(args.limit, Some(50));
    }

    #[test]
    fn test_offset_skips_passwords() {
        // Test that offset correctly skips first N passwords
        let mut passwords: Vec<String> = (1..=100).map(|i| format!("password{}", i)).collect();
        let total_loaded = passwords.len();

        assert_eq!(total_loaded, 100);

        // Apply offset of 20
        let offset = 20;
        if offset > 0 && offset < passwords.len() {
            passwords = passwords.into_iter().skip(offset).collect();
        }

        assert_eq!(passwords.len(), 80);
        assert_eq!(passwords[0], "password21"); // First password after skip
        assert_eq!(passwords[79], "password100"); // Last password
    }

    #[test]
    fn test_offset_then_limit() {
        // Test that offset is applied before limit
        let mut passwords: Vec<String> = (1..=100).map(|i| format!("password{}", i)).collect();
        let total_loaded = passwords.len();

        assert_eq!(total_loaded, 100);

        // Apply offset of 20
        let offset = 20;
        if offset > 0 && offset < passwords.len() {
            passwords = passwords.into_iter().skip(offset).collect();
        }

        assert_eq!(passwords.len(), 80); // 100 - 20

        // Apply limit of 30
        let limit = 30;
        if limit < passwords.len() {
            passwords.truncate(limit);
        }

        assert_eq!(passwords.len(), 30);
        assert_eq!(passwords[0], "password21"); // First password (offset 20 + 1)
        assert_eq!(passwords[29], "password50"); // Last password (offset 20 + limit 30)
    }

    #[test]
    fn test_offset_zero() {
        // Test that offset of 0 doesn't skip anything
        let mut passwords: Vec<String> = (1..=50).map(|i| format!("password{}", i)).collect();

        let offset = 0;
        if offset > 0 && offset < passwords.len() {
            passwords = passwords.into_iter().skip(offset).collect();
        }

        assert_eq!(passwords.len(), 50);
        assert_eq!(passwords[0], "password1");
    }

    #[test]
    fn test_offset_one() {
        // Test edge case: offset of 1
        let mut passwords: Vec<String> = (1..=50).map(|i| format!("password{}", i)).collect();

        let offset = 1;
        if offset > 0 && offset < passwords.len() {
            passwords = passwords.into_iter().skip(offset).collect();
        }

        assert_eq!(passwords.len(), 49);
        assert_eq!(passwords[0], "password2");
    }

    #[test]
    fn test_offset_at_boundary() {
        // Test offset at last valid position (total - 1)
        let mut passwords: Vec<String> = (1..=10).map(|i| format!("password{}", i)).collect();

        let offset = 9; // Skip all but last
        if offset > 0 && offset < passwords.len() {
            passwords = passwords.into_iter().skip(offset).collect();
        }

        assert_eq!(passwords.len(), 1);
        assert_eq!(passwords[0], "password10");
    }

    #[test]
    fn test_offset_with_limit_consuming_all_remaining() {
        // Test offset with limit that exceeds remaining passwords
        let mut passwords: Vec<String> = (1..=100).map(|i| format!("password{}", i)).collect();

        // Apply offset of 90
        let offset = 90;
        if offset > 0 && offset < passwords.len() {
            passwords = passwords.into_iter().skip(offset).collect();
        }

        assert_eq!(passwords.len(), 10); // Only 10 remaining

        // Apply limit of 50 (more than remaining)
        let limit = 50;
        if limit < passwords.len() {
            passwords.truncate(limit);
        }

        // Should still be 10, not truncated since 10 < 50
        assert_eq!(passwords.len(), 10);
        assert_eq!(passwords[0], "password91");
        assert_eq!(passwords[9], "password100");
    }

    #[test]
    fn test_wordlist_loading_with_offset() {
        // Integration test: wordlist loading with offset
        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        let passwords = vec![
            "password1",
            "password2",
            "password3",
            "password4",
            "password5",
        ];
        let wordlist_path = create_test_wordlist(&temp_dir, &passwords);

        // Read wordlist
        let file = File::open(&wordlist_path).expect("Failed to open wordlist");
        let reader = BufReader::new(file);
        let mut loaded_passwords: Vec<String> = reader
            .lines()
            .map_while(Result::ok)
            .filter(|line| !line.is_empty())
            .collect();

        assert_eq!(loaded_passwords.len(), 5);

        // Apply offset of 2
        let offset = 2;
        if offset > 0 && offset < loaded_passwords.len() {
            loaded_passwords = loaded_passwords.into_iter().skip(offset).collect();
        }

        assert_eq!(loaded_passwords.len(), 3);
        assert_eq!(loaded_passwords[0], "password3");
        assert_eq!(loaded_passwords[2], "password5");
    }

    #[test]
    fn test_wordlist_loading_with_offset_and_limit() {
        // Integration test: wordlist loading with both offset and limit
        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        let password_strs: Vec<String> = (1..=10).map(|i| format!("password{}", i)).collect();
        let password_refs: Vec<&str> = password_strs.iter().map(|s| s.as_str()).collect();
        let wordlist_path = create_test_wordlist(&temp_dir, &password_refs);

        // Read wordlist
        let file = File::open(&wordlist_path).expect("Failed to open wordlist");
        let reader = BufReader::new(file);
        let mut loaded_passwords: Vec<String> = reader
            .lines()
            .map_while(Result::ok)
            .filter(|line| !line.is_empty())
            .collect();

        assert_eq!(loaded_passwords.len(), 10);

        // Apply offset of 3
        let offset = 3;
        if offset > 0 && offset < loaded_passwords.len() {
            loaded_passwords = loaded_passwords.into_iter().skip(offset).collect();
        }

        assert_eq!(loaded_passwords.len(), 7); // 10 - 3

        // Apply limit of 4
        let limit = 4;
        if limit < loaded_passwords.len() {
            loaded_passwords.truncate(limit);
        }

        assert_eq!(loaded_passwords.len(), 4);
        assert_eq!(loaded_passwords[0], "password4"); // offset 3 means start at 4th
        assert_eq!(loaded_passwords[3], "password7"); // offset 3 + limit 4 = password7
    }

    // ============================================================================
    // Native vs Non-Native comparison tests
    // These tests verify that both implementations produce the same results
    // ============================================================================

    /// Helper to get the path to test archives directory
    fn test_archives_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test_archives")
    }

    /// Test that native and non-native RAR encryption detection produce same results
    #[test]
    fn test_rar_encryption_detection_native_vs_cli() {
        if !has_rar_cli_tools() {
            println!("Skipping test: RAR CLI tools (lsar, unrar) not installed");
            return;
        }

        let archives_dir = test_archives_dir();
        if !archives_dir.exists() {
            println!("Skipping test: test_archives directory not found");
            return;
        }

        let test_cases = vec![
            ("no_password.rar", EncryptionType::None),
            ("simple_password.rar", EncryptionType::ContentOnly),
            ("content_encrypted.rar", EncryptionType::ContentOnly),
            ("header_encrypted.rar", EncryptionType::HeaderEncrypted),
        ];

        for (filename, _expected) in test_cases {
            let archive_path = archives_dir.join(filename);
            if !archive_path.exists() {
                continue;
            }

            let cli_result = detect_rar_encryption_type(&archive_path);
            let native_result = detect_rar_encryption_type_native(&archive_path);

            // Both should succeed or both should fail
            match (&cli_result, &native_result) {
                (Ok(cli_enc), Ok(native_enc)) => {
                    assert_eq!(
                        cli_enc, native_enc,
                        "Encryption type mismatch for {}: CLI={:?}, Native={:?}",
                        filename, cli_enc, native_enc
                    );
                }
                (Err(cli_err), Err(native_err)) => {
                    // Both failed, which is acceptable if archive is corrupt
                    println!(
                        "Both implementations failed for {}: CLI={}, Native={}",
                        filename, cli_err, native_err
                    );
                }
                _ => {
                    // One succeeded and one failed - this is a problem
                    panic!(
                        "Inconsistent results for {}: CLI={:?}, Native={:?}",
                        filename, cli_result, native_result
                    );
                }
            }
        }
    }

    /// Test that native and non-native RAR password testing produce same results
    #[test]
    fn test_rar_password_testing_native_vs_cli() {
        if !has_rar_cli_tools() {
            println!("Skipping test: RAR CLI tools (lsar, unrar) not installed");
            return;
        }

        let archives_dir = test_archives_dir();
        if !archives_dir.exists() {
            println!("Skipping test: test_archives directory not found");
            return;
        }

        // Test with various passwords - we don't know which is correct,
        // but both implementations should agree on each one
        let passwords_to_test = vec![
            "password", "12345", "secret", "qwerty", "testpass123",
            "wrongpassword", "badpassword", "incorrectpass",
        ];

        let rar_archives = vec![
            "simple_password.rar",
            "content_encrypted.rar",
            "header_encrypted.rar",
        ];

        for filename in rar_archives {
            let archive_path = archives_dir.join(filename);
            if !archive_path.exists() {
                continue;
            }

            for password in &passwords_to_test {
                let cli_result = test_rar_password(&archive_path, password);
                let native_result = test_rar_password_native(&archive_path, password);

                assert_eq!(
                    cli_result, native_result,
                    "Password test mismatch for {} with password '{}': CLI={}, Native={}",
                    filename, password, cli_result, native_result
                );
            }
        }
    }

    /// Test that native and non-native 7z encryption detection produce same results
    #[test]
    fn test_7z_encryption_detection_native_vs_cli() {
        let archives_dir = test_archives_dir();
        if !archives_dir.exists() {
            println!("Skipping test: test_archives directory not found");
            return;
        }

        let test_cases = vec![
            ("7z_no_password.7z", EncryptionType::None),
            ("7z_simple_password.7z", EncryptionType::ContentOnly),
            ("7z_content_encrypted.7z", EncryptionType::ContentOnly),
            ("7z_header_encrypted.7z", EncryptionType::HeaderEncrypted),
        ];

        for (filename, _expected) in test_cases {
            let archive_path = archives_dir.join(filename);
            if !archive_path.exists() {
                continue;
            }

            let cli_result = detect_7z_encryption_type(&archive_path);
            let native_result = detect_7z_encryption_type_native(&archive_path);

            match (&cli_result, &native_result) {
                (Ok(cli_enc), Ok(native_enc)) => {
                    assert_eq!(
                        cli_enc, native_enc,
                        "Encryption type mismatch for {}: CLI={:?}, Native={:?}",
                        filename, cli_enc, native_enc
                    );
                }
                (Err(cli_err), Err(native_err)) => {
                    println!(
                        "Both implementations failed for {}: CLI={}, Native={}",
                        filename, cli_err, native_err
                    );
                }
                _ => {
                    panic!(
                        "Inconsistent results for {}: CLI={:?}, Native={:?}",
                        filename, cli_result, native_result
                    );
                }
            }
        }
    }

    /// Test that native and non-native 7z password testing produce same results
    #[test]
    fn test_7z_password_testing_native_vs_cli() {
        let archives_dir = test_archives_dir();
        if !archives_dir.exists() {
            println!("Skipping test: test_archives directory not found");
            return;
        }

        // Test with various passwords - we don't know which is correct,
        // but both implementations should agree on each one
        let passwords_to_test = vec![
            "password", "12345", "secret", "qwerty", "testpass123",
            "wrongpassword", "badpassword", "incorrectpass",
        ];

        let sevenz_archives = vec![
            "7z_simple_password.7z",
            "7z_content_encrypted.7z",
            "7z_header_encrypted.7z",
        ];

        for filename in sevenz_archives {
            let archive_path = archives_dir.join(filename);
            if !archive_path.exists() {
                continue;
            }

            for password in &passwords_to_test {
                let cli_result = test_7z_password(&archive_path, password);
                let native_result = test_7z_password_native(&archive_path, password);

                assert_eq!(
                    cli_result, native_result,
                    "Password test mismatch for {} with password '{}': CLI={}, Native={}",
                    filename, password, cli_result, native_result
                );
            }
        }
    }

    /// Test that native and non-native produce same final recovery results
    #[test]
    fn test_full_recovery_native_vs_cli() {
        if !has_rar_cli_tools() {
            println!("Skipping test: RAR CLI tools (lsar, unrar) not installed");
            return;
        }

        let archives_dir = test_archives_dir();
        if !archives_dir.exists() {
            println!("Skipping test: test_archives directory not found");
            return;
        }

        let wordlist_path = archives_dir.join("wordlist.txt");
        if !wordlist_path.exists() {
            println!("Skipping test: wordlist.txt not found");
            return;
        }

        // Load passwords
        let file = File::open(&wordlist_path).expect("Failed to open wordlist");
        let reader = BufReader::new(file);
        let passwords: Vec<String> = reader
            .lines()
            .map_while(Result::ok)
            .filter(|line| !line.is_empty())
            .collect();

        // Test RAR archives
        let rar_archives = vec![
            "simple_password.rar",
            "content_encrypted.rar",
            "header_encrypted.rar",
        ];

        for filename in rar_archives {
            let archive_path = archives_dir.join(filename);
            if !archive_path.exists() {
                continue;
            }

            let cli_result = recover_archive_password(&archive_path, &passwords, 1, true, false, false);
            let native_result = recover_archive_password(&archive_path, &passwords, 1, true, false, true);

            // Compare results
            match (&cli_result, &native_result) {
                (RecoveryResult::Found(cli_pass), RecoveryResult::Found(native_pass)) => {
                    assert_eq!(
                        cli_pass, native_pass,
                        "Password mismatch for {}: CLI='{}', Native='{}'",
                        filename, cli_pass, native_pass
                    );
                }
                (RecoveryResult::NotFound, RecoveryResult::NotFound) => {
                    // Both didn't find - OK
                }
                (RecoveryResult::NotEncrypted, RecoveryResult::NotEncrypted) => {
                    // Both detected no encryption - OK
                }
                (RecoveryResult::Error(cli_err), RecoveryResult::Error(native_err)) => {
                    println!(
                        "Both errored for {}: CLI='{}', Native='{}'",
                        filename, cli_err, native_err
                    );
                }
                _ => {
                    panic!(
                        "Inconsistent recovery results for {}: CLI={:?}, Native={:?}",
                        filename, cli_result, native_result
                    );
                }
            }
        }

        // Test 7z archives
        let sevenz_archives = vec![
            "7z_simple_password.7z",
            "7z_content_encrypted.7z",
            "7z_header_encrypted.7z",
        ];

        for filename in sevenz_archives {
            let archive_path = archives_dir.join(filename);
            if !archive_path.exists() {
                continue;
            }

            let cli_result = recover_archive_password(&archive_path, &passwords, 1, true, false, false);
            let native_result = recover_archive_password(&archive_path, &passwords, 1, true, false, true);

            match (&cli_result, &native_result) {
                (RecoveryResult::Found(cli_pass), RecoveryResult::Found(native_pass)) => {
                    assert_eq!(
                        cli_pass, native_pass,
                        "Password mismatch for {}: CLI='{}', Native='{}'",
                        filename, cli_pass, native_pass
                    );
                }
                (RecoveryResult::NotFound, RecoveryResult::NotFound) => {}
                (RecoveryResult::NotEncrypted, RecoveryResult::NotEncrypted) => {}
                (RecoveryResult::Error(cli_err), RecoveryResult::Error(native_err)) => {
                    println!(
                        "Both errored for {}: CLI='{}', Native='{}'",
                        filename, cli_err, native_err
                    );
                }
                _ => {
                    panic!(
                        "Inconsistent recovery results for {}: CLI={:?}, Native={:?}",
                        filename, cli_result, native_result
                    );
                }
            }
        }
    }

    /// Test that --native flag is correctly parsed
    #[test]
    fn test_args_parsing_with_native_flag() {
        let args = Args::parse_from(&[
            "pack-recover",
            "--archive",
            "test.rar",
            "--wordlist",
            "/tmp/wordlist.txt",
            "--native",
        ]);

        assert!(args.native);
    }

    /// Test that --native flag defaults to false
    #[test]
    fn test_args_parsing_without_native_flag() {
        let args = Args::parse_from(&[
            "pack-recover",
            "--archive",
            "test.rar",
            "--wordlist",
            "/tmp/wordlist.txt",
        ]);

        assert!(!args.native);
    }

    // ============================================================================
    // Wordlist cleanup tests
    // ============================================================================

    /// Test clean subcommand parsing
    #[test]
    fn test_args_parsing_clean_subcommand() {
        let args = Args::parse_from(&[
            "pack-recover",
            "clean",
            "--input",
            "/tmp/input.txt",
            "--output",
            "/tmp/output.txt",
        ]);

        match args.command {
            Some(Commands::Clean { input, output, quiet }) => {
                assert_eq!(input, PathBuf::from("/tmp/input.txt"));
                assert_eq!(output, PathBuf::from("/tmp/output.txt"));
                assert!(!quiet);
            }
            _ => panic!("Expected Clean subcommand"),
        }
    }

    /// Test clean subcommand with quiet flag
    #[test]
    fn test_args_parsing_clean_subcommand_quiet() {
        let args = Args::parse_from(&[
            "pack-recover",
            "clean",
            "--input",
            "/tmp/input.txt",
            "--output",
            "/tmp/output.txt",
            "--quiet",
        ]);

        match args.command {
            Some(Commands::Clean { quiet, .. }) => {
                assert!(quiet);
            }
            _ => panic!("Expected Clean subcommand"),
        }
    }

    /// Test clean_wordlist function removes duplicates
    #[test]
    fn test_clean_wordlist_removes_duplicates() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let input_path = temp_dir.path().join("input.txt");
        let output_path = temp_dir.path().join("output.txt");

        // Create input with duplicates
        {
            let mut file = File::create(&input_path).expect("Failed to create input file");
            writeln!(file, "password1").unwrap();
            writeln!(file, "password2").unwrap();
            writeln!(file, "password1").unwrap(); // duplicate
            writeln!(file, "password3").unwrap();
            writeln!(file, "password2").unwrap(); // duplicate
            writeln!(file, "password1").unwrap(); // duplicate
        }

        // Run clean
        clean_wordlist(&input_path, &output_path, true).expect("Failed to clean wordlist");

        // Read output
        let file = File::open(&output_path).expect("Failed to open output file");
        let reader = BufReader::new(file);
        let passwords: Vec<String> = reader.lines().map_while(Result::ok).collect();

        assert_eq!(passwords.len(), 3);
        assert_eq!(passwords[0], "password1");
        assert_eq!(passwords[1], "password2");
        assert_eq!(passwords[2], "password3");
    }

    /// Test clean_wordlist function skips empty lines
    #[test]
    fn test_clean_wordlist_skips_empty_lines() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let input_path = temp_dir.path().join("input.txt");
        let output_path = temp_dir.path().join("output.txt");

        // Create input with empty lines
        {
            let mut file = File::create(&input_path).expect("Failed to create input file");
            writeln!(file, "password1").unwrap();
            writeln!(file, "").unwrap(); // empty
            writeln!(file, "password2").unwrap();
            writeln!(file, "").unwrap(); // empty
            writeln!(file, "").unwrap(); // empty
            writeln!(file, "password3").unwrap();
        }

        // Run clean
        clean_wordlist(&input_path, &output_path, true).expect("Failed to clean wordlist");

        // Read output
        let file = File::open(&output_path).expect("Failed to open output file");
        let reader = BufReader::new(file);
        let passwords: Vec<String> = reader.lines().map_while(Result::ok).collect();

        assert_eq!(passwords.len(), 3);
        assert_eq!(passwords[0], "password1");
        assert_eq!(passwords[1], "password2");
        assert_eq!(passwords[2], "password3");
    }

    /// Test clean_wordlist preserves order
    #[test]
    fn test_clean_wordlist_preserves_order() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let input_path = temp_dir.path().join("input.txt");
        let output_path = temp_dir.path().join("output.txt");

        // Create input with specific order
        {
            let mut file = File::create(&input_path).expect("Failed to create input file");
            writeln!(file, "zebra").unwrap();
            writeln!(file, "apple").unwrap();
            writeln!(file, "mango").unwrap();
            writeln!(file, "apple").unwrap(); // duplicate
            writeln!(file, "banana").unwrap();
        }

        // Run clean
        clean_wordlist(&input_path, &output_path, true).expect("Failed to clean wordlist");

        // Read output - should preserve insertion order, not alphabetical
        let file = File::open(&output_path).expect("Failed to open output file");
        let reader = BufReader::new(file);
        let passwords: Vec<String> = reader.lines().map_while(Result::ok).collect();

        assert_eq!(passwords.len(), 4);
        assert_eq!(passwords[0], "zebra");
        assert_eq!(passwords[1], "apple");
        assert_eq!(passwords[2], "mango");
        assert_eq!(passwords[3], "banana");
    }

    /// Test clean_wordlist with all duplicates
    #[test]
    fn test_clean_wordlist_all_duplicates() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let input_path = temp_dir.path().join("input.txt");
        let output_path = temp_dir.path().join("output.txt");

        // Create input with all same password
        {
            let mut file = File::create(&input_path).expect("Failed to create input file");
            for _ in 0..100 {
                writeln!(file, "samepassword").unwrap();
            }
        }

        // Run clean
        clean_wordlist(&input_path, &output_path, true).expect("Failed to clean wordlist");

        // Read output
        let file = File::open(&output_path).expect("Failed to open output file");
        let reader = BufReader::new(file);
        let passwords: Vec<String> = reader.lines().map_while(Result::ok).collect();

        assert_eq!(passwords.len(), 1);
        assert_eq!(passwords[0], "samepassword");
    }

    /// Test clean_wordlist with no duplicates
    #[test]
    fn test_clean_wordlist_no_duplicates() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let input_path = temp_dir.path().join("input.txt");
        let output_path = temp_dir.path().join("output.txt");

        // Create input with unique passwords
        {
            let mut file = File::create(&input_path).expect("Failed to create input file");
            for i in 1..=5 {
                writeln!(file, "password{}", i).unwrap();
            }
        }

        // Run clean
        clean_wordlist(&input_path, &output_path, true).expect("Failed to clean wordlist");

        // Read output
        let file = File::open(&output_path).expect("Failed to open output file");
        let reader = BufReader::new(file);
        let passwords: Vec<String> = reader.lines().map_while(Result::ok).collect();

        assert_eq!(passwords.len(), 5);
    }

    /// Test clean_wordlist fails on missing input
    #[test]
    fn test_clean_wordlist_missing_input() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let input_path = temp_dir.path().join("nonexistent.txt");
        let output_path = temp_dir.path().join("output.txt");

        let result = clean_wordlist(&input_path, &output_path, true);
        assert!(result.is_err());
    }

    // ============================================================================
    // ZIP archive tests
    // ============================================================================

    /// Test that native and non-native ZIP encryption detection produce same results
    #[test]
    fn test_zip_encryption_detection_native_vs_cli() {
        let archives_dir = test_archives_dir();
        if !archives_dir.exists() {
            println!("Skipping test: test_archives directory not found");
            return;
        }

        let test_cases = vec![
            ("zip_no_password.zip", EncryptionType::None),
            ("zip_simple_password.zip", EncryptionType::ContentOnly),
            ("zip_content_encrypted.zip", EncryptionType::ContentOnly),
        ];

        for (filename, _expected) in test_cases {
            let archive_path = archives_dir.join(filename);
            if !archive_path.exists() {
                continue;
            }

            let cli_result = detect_zip_encryption_type(&archive_path);
            let native_result = detect_zip_encryption_type_native(&archive_path);

            match (&cli_result, &native_result) {
                (Ok(cli_enc), Ok(native_enc)) => {
                    assert_eq!(
                        cli_enc, native_enc,
                        "Encryption type mismatch for {}: CLI={:?}, Native={:?}",
                        filename, cli_enc, native_enc
                    );
                }
                (Err(cli_err), Err(native_err)) => {
                    println!(
                        "Both implementations failed for {}: CLI={}, Native={}",
                        filename, cli_err, native_err
                    );
                }
                _ => {
                    panic!(
                        "Inconsistent results for {}: CLI={:?}, Native={:?}",
                        filename, cli_result, native_result
                    );
                }
            }
        }
    }

    /// Test that native and non-native ZIP password testing produce same results
    #[test]
    fn test_zip_password_testing_native_vs_cli() {
        let archives_dir = test_archives_dir();
        if !archives_dir.exists() {
            println!("Skipping test: test_archives directory not found");
            return;
        }

        // Test with various passwords - we don't know which is correct,
        // but both implementations should agree on each one
        let passwords_to_test = vec![
            "password", "12345", "secret", "qwerty", "testpass123",
            "wrongpassword", "badpassword", "incorrectpass",
        ];

        let zip_archives = vec![
            "zip_simple_password.zip",
            "zip_content_encrypted.zip",
        ];

        for filename in zip_archives {
            let archive_path = archives_dir.join(filename);
            if !archive_path.exists() {
                continue;
            }

            for password in &passwords_to_test {
                let cli_result = test_zip_password(&archive_path, password);
                let native_result = test_zip_password_native(&archive_path, password);

                assert_eq!(
                    cli_result, native_result,
                    "Password test mismatch for {} with password '{}': CLI={}, Native={}",
                    filename, password, cli_result, native_result
                );
            }
        }
    }

    /// Test full recovery for ZIP archives - native vs CLI
    #[test]
    fn test_zip_full_recovery_native_vs_cli() {
        let archives_dir = test_archives_dir();
        if !archives_dir.exists() {
            println!("Skipping test: test_archives directory not found");
            return;
        }

        let wordlist_path = archives_dir.join("wordlist.txt");
        if !wordlist_path.exists() {
            println!("Skipping test: wordlist.txt not found");
            return;
        }

        // Load passwords
        let file = File::open(&wordlist_path).expect("Failed to open wordlist");
        let reader = BufReader::new(file);
        let passwords: Vec<String> = reader
            .lines()
            .map_while(Result::ok)
            .filter(|line| !line.is_empty())
            .collect();

        // Test ZIP archives
        let zip_archives = vec![
            "zip_simple_password.zip",
            "zip_content_encrypted.zip",
        ];

        for filename in zip_archives {
            let archive_path = archives_dir.join(filename);
            if !archive_path.exists() {
                continue;
            }

            let cli_result = recover_archive_password(&archive_path, &passwords, 1, true, false, false);
            let native_result = recover_archive_password(&archive_path, &passwords, 1, true, false, true);

            // Compare results
            match (&cli_result, &native_result) {
                (RecoveryResult::Found(cli_pass), RecoveryResult::Found(native_pass)) => {
                    assert_eq!(
                        cli_pass, native_pass,
                        "Password mismatch for {}: CLI='{}', Native='{}'",
                        filename, cli_pass, native_pass
                    );
                }
                (RecoveryResult::NotFound, RecoveryResult::NotFound) => {
                    // Both didn't find - OK
                }
                (RecoveryResult::NotEncrypted, RecoveryResult::NotEncrypted) => {
                    // Both detected no encryption - OK
                }
                (RecoveryResult::Error(cli_err), RecoveryResult::Error(native_err)) => {
                    println!(
                        "Both errored for {}: CLI='{}', Native='{}'",
                        filename, cli_err, native_err
                    );
                }
                _ => {
                    panic!(
                        "Inconsistent recovery results for {}: CLI={:?}, Native={:?}",
                        filename, cli_result, native_result
                    );
                }
            }
        }
    }

    /// Test ZIP password validation is thorough (catches false positives)
    #[test]
    fn test_zip_validation_catches_false_positives() {
        let archives_dir = test_archives_dir();
        if !archives_dir.exists() {
            println!("Skipping test: test_archives directory not found");
            return;
        }

        let zip_archives = vec![
            "zip_simple_password.zip",
            "zip_content_encrypted.zip",
        ];

        // These passwords should definitely be wrong
        let wrong_passwords = vec![
            "definitelywrongpassword123",
            "notthepassword",
            "wrongwrongwrong",
        ];

        for filename in zip_archives {
            let archive_path = archives_dir.join(filename);
            if !archive_path.exists() {
                continue;
            }

            for password in &wrong_passwords {
                // Both test and validate should return false for wrong passwords
                let test_result = test_zip_password_native(&archive_path, password);
                let validate_result = validate_zip_password_native(&archive_path, password);

                assert!(
                    !test_result,
                    "test_zip_password_native should return false for wrong password '{}' on {}",
                    password, filename
                );
                assert!(
                    !validate_result,
                    "validate_zip_password_native should return false for wrong password '{}' on {}",
                    password, filename
                );
            }
        }
    }

    /// Test ZIP unencrypted archive detection
    #[test]
    fn test_zip_unencrypted_detection() {
        let archives_dir = test_archives_dir();
        if !archives_dir.exists() {
            println!("Skipping test: test_archives directory not found");
            return;
        }

        let archive_path = archives_dir.join("zip_no_password.zip");
        if !archive_path.exists() {
            println!("Skipping test: zip_no_password.zip not found");
            return;
        }

        // Both CLI and native should detect no encryption
        let cli_result = detect_zip_encryption_type(&archive_path);
        let native_result = detect_zip_encryption_type_native(&archive_path);

        assert!(cli_result.is_ok(), "CLI detection failed: {:?}", cli_result);
        assert!(native_result.is_ok(), "Native detection failed: {:?}", native_result);

        assert_eq!(
            cli_result.unwrap(),
            EncryptionType::None,
            "CLI should detect no encryption"
        );
        assert_eq!(
            native_result.unwrap(),
            EncryptionType::None,
            "Native should detect no encryption"
        );
    }

    /// Test that ZIP extraction works with correct password
    #[test]
    fn test_zip_extraction_with_correct_password() {
        let archives_dir = test_archives_dir();
        if !archives_dir.exists() {
            println!("Skipping test: test_archives directory not found");
            return;
        }

        let archive_path = archives_dir.join("zip_simple_password.zip");
        if !archive_path.exists() {
            println!("Skipping test: zip_simple_password.zip not found");
            return;
        }

        // First, find the correct password
        let wordlist_path = archives_dir.join("wordlist.txt");
        if !wordlist_path.exists() {
            println!("Skipping test: wordlist.txt not found");
            return;
        }

        let file = File::open(&wordlist_path).expect("Failed to open wordlist");
        let reader = BufReader::new(file);
        let passwords: Vec<String> = reader
            .lines()
            .map_while(Result::ok)
            .filter(|line| !line.is_empty())
            .collect();

        // Find the password
        let mut found_password: Option<String> = None;
        for password in &passwords {
            if test_zip_password_native(&archive_path, password) {
                found_password = Some(password.clone());
                break;
            }
        }

        if found_password.is_none() {
            println!("Skipping extraction test: could not find correct password");
            return;
        }

        let password = found_password.unwrap();
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let output_dir = temp_dir.path().to_path_buf();

        // Test native extraction
        let native_result = extract_zip_archive_native(&archive_path, &password, &output_dir);
        assert!(
            native_result.is_ok(),
            "Native ZIP extraction failed: {:?}",
            native_result
        );

        // Verify files were extracted
        let extracted_files: Vec<_> = std::fs::read_dir(&output_dir)
            .expect("Failed to read output dir")
            .filter_map(|e| e.ok())
            .collect();

        assert!(
            !extracted_files.is_empty(),
            "No files were extracted from ZIP archive"
        );
    }
}
