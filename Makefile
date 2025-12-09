# Makefile for pack-recover
# Archive Password Recovery Tool (RAR and 7zip)

BINARY_NAME = pack-recover
INSTALL_DIR = /usr/local/bin
TEST_DIR = test_archives
CARGO = cargo

# Default target
.PHONY: all
all: build

# Build release binary
.PHONY: build
build:
	$(CARGO) build --release

# Build debug binary
.PHONY: debug
debug:
	$(CARGO) build

# Install to system (requires sudo)
.PHONY: install
install: build
	@echo "Installing $(BINARY_NAME) to $(INSTALL_DIR)..."
	@if [ ! -d "$(INSTALL_DIR)" ]; then \
		sudo mkdir -p "$(INSTALL_DIR)"; \
	fi
	sudo cp target/release/$(BINARY_NAME) $(INSTALL_DIR)/$(BINARY_NAME)
	sudo chmod 755 $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "Installation complete!"
	@echo "You can now run '$(BINARY_NAME)' from anywhere."

# Uninstall from system
.PHONY: uninstall
uninstall:
	@echo "Removing $(BINARY_NAME) from $(INSTALL_DIR)..."
	sudo rm -f $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "Uninstallation complete!"

# Clean build artifacts
.PHONY: clean
clean:
	$(CARGO) clean
	rm -rf $(TEST_DIR)

# Run tests
.PHONY: test
test: build test-setup test-run test-cleanup
	@echo ""
	@echo "========================================"
	@echo "All tests passed!"
	@echo "========================================"

# Create test directory and archives
.PHONY: test-setup
test-setup:
	@echo "========================================"
	@echo "Setting up test environment..."
	@echo "========================================"
	@# Check for required tools
	@command -v rar >/dev/null 2>&1 || { echo "Error: 'rar' command not found. Install with: brew install --cask rar"; exit 1; }
	@command -v unrar >/dev/null 2>&1 || { echo "Error: 'unrar' command not found. Install with: brew install --cask rar"; exit 1; }
	@command -v lsar >/dev/null 2>&1 || { echo "Error: 'lsar' command not found. Install with: brew install unar"; exit 1; }
	@command -v 7z >/dev/null 2>&1 || { echo "Error: '7z' command not found. Install with: brew install p7zip"; exit 1; }
	@# Create test directory
	@rm -rf $(TEST_DIR)
	@mkdir -p $(TEST_DIR)
	@# Create test file content
	@echo "This is a test file for RAR password recovery testing." > $(TEST_DIR)/testfile.txt
	@echo "It contains some sample content to verify extraction works correctly." >> $(TEST_DIR)/testfile.txt
	@echo "Line 3 of the test file." >> $(TEST_DIR)/testfile.txt
	@# Create wordlist with test passwords
	@echo "password" > $(TEST_DIR)/wordlist.txt
	@echo "12345" >> $(TEST_DIR)/wordlist.txt
	@echo "secret" >> $(TEST_DIR)/wordlist.txt
	@echo "qwerty" >> $(TEST_DIR)/wordlist.txt
	@echo "testpass123" >> $(TEST_DIR)/wordlist.txt
	@echo "wrongpassword1" >> $(TEST_DIR)/wordlist.txt
	@echo "wrongpassword2" >> $(TEST_DIR)/wordlist.txt
	@echo "wrongpassword3" >> $(TEST_DIR)/wordlist.txt
	@echo "admin" >> $(TEST_DIR)/wordlist.txt
	@echo "letmein" >> $(TEST_DIR)/wordlist.txt
	@# Create wordlist that won't contain the password (for failure test)
	@echo "wrongpassword1" > $(TEST_DIR)/wordlist_fail.txt
	@echo "wrongpassword2" >> $(TEST_DIR)/wordlist_fail.txt
	@echo "wrongpassword3" >> $(TEST_DIR)/wordlist_fail.txt
	@echo "notthepassword" >> $(TEST_DIR)/wordlist_fail.txt
	@echo ""
	@echo "Creating test RAR archives..."
	@echo ""
	@# Test 1: RAR with content-only encryption (password: secret)
	@echo "  [1/9] Creating content-encrypted RAR (password: secret)..."
	@cd $(TEST_DIR) && rar a -p"secret" -ep content_encrypted.rar testfile.txt >/dev/null
	@# Test 2: RAR with header encryption (password: testpass123)
	@echo "  [2/9] Creating header-encrypted RAR (password: testpass123)..."
	@cd $(TEST_DIR) && rar a -hp"testpass123" -ep header_encrypted.rar testfile.txt >/dev/null
	@# Test 3: RAR with simple password (password: 12345)
	@echo "  [3/9] Creating simple password RAR (password: 12345)..."
	@cd $(TEST_DIR) && rar a -p"12345" -ep simple_password.rar testfile.txt >/dev/null
	@# Test 4: Unencrypted RAR (no password)
	@echo "  [4/9] Creating unencrypted RAR (no password)..."
	@cd $(TEST_DIR) && rar a -ep no_password.rar testfile.txt >/dev/null
	@# Test 5: RAR5 format with encryption (password: qwerty)
	@echo "  [5/9] Creating RAR5 encrypted archive (password: qwerty)..."
	@cd $(TEST_DIR) && rar a -ma5 -p"qwerty" -ep rar5_encrypted.rar testfile.txt >/dev/null
	@echo ""
	@echo "Creating test 7zip archives..."
	@echo ""
	@# Test 6: 7zip with content-only encryption (password: secret)
	@echo "  [6/9] Creating content-encrypted 7z (password: secret)..."
	@cd $(TEST_DIR) && 7z a -p"secret" -mhe=off 7z_content_encrypted.7z testfile.txt >/dev/null
	@# Test 7: 7zip with header encryption (password: testpass123)
	@echo "  [7/9] Creating header-encrypted 7z (password: testpass123)..."
	@cd $(TEST_DIR) && 7z a -p"testpass123" -mhe=on 7z_header_encrypted.7z testfile.txt >/dev/null
	@# Test 8: 7zip with simple password (password: 12345)
	@echo "  [8/9] Creating simple password 7z (password: 12345)..."
	@cd $(TEST_DIR) && 7z a -p"12345" 7z_simple_password.7z testfile.txt >/dev/null
	@# Test 9: Unencrypted 7zip (no password)
	@echo "  [9/9] Creating unencrypted 7z (no password)..."
	@cd $(TEST_DIR) && 7z a 7z_no_password.7z testfile.txt >/dev/null
	@echo ""
	@echo "Test archives created successfully!"
	@echo ""

# Run all tests
.PHONY: test-run
test-run:
	@echo "========================================"
	@echo "Running tests..."
	@echo "========================================"
	@echo ""
	@echo "----------------------------------------"
	@echo "RAR Archive Tests"
	@echo "----------------------------------------"
	@echo ""
	@# Test 1: Content-only encrypted RAR
	@echo "[TEST 1/11] Testing content-encrypted RAR recovery..."
	@RESULT=$$(./target/release/$(BINARY_NAME) -a $(TEST_DIR)/content_encrypted.rar -w $(TEST_DIR)/wordlist.txt -q 2>&1) && \
		if [ "$$RESULT" = "secret" ]; then \
			echo "  PASSED: Found correct password 'secret'"; \
		else \
			echo "  FAILED: Expected 'secret', got '$$RESULT'"; \
			exit 1; \
		fi
	@echo ""
	@# Test 2: Header-encrypted RAR
	@echo "[TEST 2/11] Testing header-encrypted RAR recovery..."
	@RESULT=$$(./target/release/$(BINARY_NAME) -a $(TEST_DIR)/header_encrypted.rar -w $(TEST_DIR)/wordlist.txt -q 2>&1) && \
		if [ "$$RESULT" = "testpass123" ]; then \
			echo "  PASSED: Found correct password 'testpass123'"; \
		else \
			echo "  FAILED: Expected 'testpass123', got '$$RESULT'"; \
			exit 1; \
		fi
	@echo ""
	@# Test 3: Simple password RAR
	@echo "[TEST 3/11] Testing simple password RAR recovery..."
	@RESULT=$$(./target/release/$(BINARY_NAME) -a $(TEST_DIR)/simple_password.rar -w $(TEST_DIR)/wordlist.txt -q 2>&1) && \
		if [ "$$RESULT" = "12345" ]; then \
			echo "  PASSED: Found correct password '12345'"; \
		else \
			echo "  FAILED: Expected '12345', got '$$RESULT'"; \
			exit 1; \
		fi
	@echo ""
	@# Test 4: Unencrypted RAR (should detect no encryption)
	@echo "[TEST 4/11] Testing unencrypted RAR detection..."
	@RESULT=$$(./target/release/$(BINARY_NAME) -a $(TEST_DIR)/no_password.rar -w $(TEST_DIR)/wordlist.txt 2>&1) && \
		if echo "$$RESULT" | grep -q "not password-protected"; then \
			echo "  PASSED: Correctly detected archive is not password-protected"; \
		else \
			echo "  FAILED: Should have detected no encryption"; \
			echo "  Output: $$RESULT"; \
			exit 1; \
		fi
	@echo ""
	@# Test 5: RAR5 format encrypted
	@echo "[TEST 5/11] Testing RAR5 encrypted archive recovery..."
	@RESULT=$$(./target/release/$(BINARY_NAME) -a $(TEST_DIR)/rar5_encrypted.rar -w $(TEST_DIR)/wordlist.txt -q 2>&1) && \
		if [ "$$RESULT" = "qwerty" ]; then \
			echo "  PASSED: Found correct password 'qwerty' (RAR5 format)"; \
		else \
			echo "  FAILED: Expected 'qwerty', got '$$RESULT'"; \
			exit 1; \
		fi
	@echo ""
	@# Test 6: Password not in wordlist (should fail gracefully)
	@echo "[TEST 6/11] Testing graceful failure when password not in wordlist (RAR)..."
	@if ./target/release/$(BINARY_NAME) -a $(TEST_DIR)/content_encrypted.rar -w $(TEST_DIR)/wordlist_fail.txt -q 2>&1; then \
		echo "  FAILED: Should have exited with error when password not found"; \
		exit 1; \
	else \
		echo "  PASSED: Correctly reported password not found"; \
	fi
	@echo ""
	@# 7zip Tests
	@echo "----------------------------------------"
	@echo "7zip Archive Tests"
	@echo "----------------------------------------"
	@echo ""
	@# Test 7: 7zip content-only encrypted
	@echo "[TEST 7/11] Testing content-encrypted 7z recovery..."
	@RESULT=$$(./target/release/$(BINARY_NAME) -a $(TEST_DIR)/7z_content_encrypted.7z -w $(TEST_DIR)/wordlist.txt -q 2>&1) && \
		if [ "$$RESULT" = "secret" ]; then \
			echo "  PASSED: Found correct password 'secret'"; \
		else \
			echo "  FAILED: Expected 'secret', got '$$RESULT'"; \
			exit 1; \
		fi
	@echo ""
	@# Test 8: 7zip header-encrypted
	@echo "[TEST 8/11] Testing header-encrypted 7z recovery..."
	@RESULT=$$(./target/release/$(BINARY_NAME) -a $(TEST_DIR)/7z_header_encrypted.7z -w $(TEST_DIR)/wordlist.txt -q 2>&1) && \
		if [ "$$RESULT" = "testpass123" ]; then \
			echo "  PASSED: Found correct password 'testpass123'"; \
		else \
			echo "  FAILED: Expected 'testpass123', got '$$RESULT'"; \
			exit 1; \
		fi
	@echo ""
	@# Test 9: 7zip simple password
	@echo "[TEST 9/11] Testing simple password 7z recovery..."
	@RESULT=$$(./target/release/$(BINARY_NAME) -a $(TEST_DIR)/7z_simple_password.7z -w $(TEST_DIR)/wordlist.txt -q 2>&1) && \
		if [ "$$RESULT" = "12345" ]; then \
			echo "  PASSED: Found correct password '12345'"; \
		else \
			echo "  FAILED: Expected '12345', got '$$RESULT'"; \
			exit 1; \
		fi
	@echo ""
	@# Test 10: Unencrypted 7zip (should detect no encryption)
	@echo "[TEST 10/11] Testing unencrypted 7z detection..."
	@RESULT=$$(./target/release/$(BINARY_NAME) -a $(TEST_DIR)/7z_no_password.7z -w $(TEST_DIR)/wordlist.txt 2>&1) && \
		if echo "$$RESULT" | grep -q "not password-protected"; then \
			echo "  PASSED: Correctly detected archive is not password-protected"; \
		else \
			echo "  FAILED: Should have detected no encryption"; \
			echo "  Output: $$RESULT"; \
			exit 1; \
		fi
	@echo ""
	@# Test 11: 7zip password not in wordlist (should fail gracefully)
	@echo "[TEST 11/11] Testing graceful failure when password not in wordlist (7z)..."
	@if ./target/release/$(BINARY_NAME) -a $(TEST_DIR)/7z_content_encrypted.7z -w $(TEST_DIR)/wordlist_fail.txt -q 2>&1; then \
		echo "  FAILED: Should have exited with error when password not found"; \
		exit 1; \
	else \
		echo "  PASSED: Correctly reported password not found"; \
	fi
	@echo ""

# Cleanup test files
.PHONY: test-cleanup
test-cleanup:
	@echo "========================================"
	@echo "Cleaning up test files..."
	@echo "========================================"
	@rm -rf $(TEST_DIR)
	@echo "Cleanup complete!"

# Run cargo tests (unit tests)
.PHONY: cargo-test
cargo-test:
	$(CARGO) test

# Format code
.PHONY: fmt
fmt:
	$(CARGO) fmt

# Lint code
.PHONY: lint
lint:
	$(CARGO) clippy -- -D warnings

# Check code without building
.PHONY: check
check:
	$(CARGO) check

# Show help
.PHONY: help
help:
	@echo "pack-recover Makefile"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all          Build release binary (default)"
	@echo "  build        Build release binary"
	@echo "  debug        Build debug binary"
	@echo "  install      Install to $(INSTALL_DIR) (requires sudo)"
	@echo "  uninstall    Remove from $(INSTALL_DIR) (requires sudo)"
	@echo "  clean        Remove build artifacts and test files"
	@echo "  test         Run integration tests with various RAR and 7zip formats"
	@echo "  test-setup   Create test archives only"
	@echo "  test-run     Run tests only (requires test-setup first)"
	@echo "  test-cleanup Remove test files only"
	@echo "  cargo-test   Run cargo unit tests"
	@echo "  fmt          Format code with rustfmt"
	@echo "  lint         Run clippy linter"
	@echo "  check        Check code without building"
	@echo "  help         Show this help message"
	@echo ""
	@echo "Requirements:"
	@echo "  - Rust/Cargo (rustup.rs)"
	@echo "  - rar command (brew install --cask rar)"
	@echo "  - unrar command (included with rar)"
	@echo "  - lsar/unar (brew install unar)"
	@echo "  - 7z command (brew install p7zip)"
