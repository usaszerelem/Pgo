#include "../Include/PgoEngine.h"

#include <fstream>
#include <stdexcept>
#include <vector>

extern "C" {
#include <sodium.h>
}

/**
 * @file PgoEngine.cpp
 * @brief Implementation of password-based authenticated file encryption.
 *
 * On-disk payload layout produced by obfuscateFile and consumed by reverseFile:
 *
 * @code
 *   [ salt (kSaltSize bytes) | nonce (kNonceSize bytes) | ciphertext + AEAD tag ]
 * @endcode
 *
 * The salt and nonce are not secret -- they are stored in plaintext so that reverseFile
 * can re-derive the same key and decrypt without any side channel. They only need to be
 * unique per encryption, so that the same password never reuses the same keystream.
 * Confidentiality and integrity both come from the password: the salt feeds Argon2id key
 * derivation (deriveKey), and the AEAD tag (checked in parsePayload) detects a wrong
 * password or a tampered/corrupted file.
 *
 * The derived key and any recovered plaintext are scrubbed from memory as soon as they
 * are no longer needed, via the ScopedZero RAII guard, so they don't linger in freed
 * heap memory for longer than necessary.
 */

namespace pgo {
namespace {

/// Size, in bytes, of the random salt used for Argon2id key derivation.
constexpr std::size_t kSaltSize = 16;
/// Size, in bytes, of the random nonce used for XChaCha20-Poly1305.
constexpr std::size_t kNonceSize = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
/// Size, in bytes, of the derived symmetric key.
constexpr std::size_t kKeySize = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
/// Size, in bytes, of the AEAD authentication tag appended to the ciphertext.
constexpr std::size_t kTagSize = crypto_aead_xchacha20poly1305_ietf_ABYTES;

/**
 * @brief RAII guard that zeroes a buffer's contents when it goes out of scope.
 *
 * Used to scrub key material and plaintext from memory as soon as they are no longer
 * needed, including on exception-unwind paths, rather than leaving them to linger in
 * freed heap memory until overwritten by something else.
 */
class ScopedZero {
public:
    explicit ScopedZero(std::vector<unsigned char>& buffer) : buffer_(buffer) {}
    ~ScopedZero() { sodium_memzero(buffer_.data(), buffer_.size()); }

    ScopedZero(const ScopedZero&) = delete;
    ScopedZero& operator=(const ScopedZero&) = delete;

private:
    std::vector<unsigned char>& buffer_;
};

/**
 * @brief Ensures libsodium's internal state is initialized before any other sodium call.
 *
 * sodium_init() is safe and cheap to call repeatedly (later calls are a no-op), so this
 * is invoked once at the start of every obfuscateFile/reverseFile call rather than
 * requiring callers of this library to initialize libsodium themselves.
 *
 * @throws std::runtime_error if libsodium failed to initialize.
 */
void ensureSodiumInitialized() {
    if (sodium_init() < 0) {
        throw std::runtime_error("failed to initialize libsodium");
    }
}

/**
 * @brief Fills @p bytes with cryptographically secure random data, in place.
 *
 * Uses libsodium's CSPRNG (randombytes_buf) rather than a platform-specific API
 * directly, so this works unmodified on every platform libsodium supports.
 *
 * @param bytes Buffer to fill; its existing size determines how many bytes are written.
 */
void generateRandomBytes(std::vector<unsigned char>& bytes) {
    if (!bytes.empty()) {
        randombytes_buf(bytes.data(), bytes.size());
    }
}

/**
 * @brief Generates a fresh random salt for Argon2id key derivation.
 * @return A newly generated salt of length kSaltSize.
 */
std::string generateSalt() {
    std::vector<unsigned char> bytes(kSaltSize);
    generateRandomBytes(bytes);
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

/**
 * @brief Extracts the salt from the start of an encrypted payload.
 *
 * The salt lives in plaintext at the start of every obfuscated file so reverseFile can
 * re-derive the same key from just the password, without needing the salt stored
 * separately elsewhere.
 *
 * @param payload Full contents of a file previously written by obfuscateFile.
 * @return The kSaltSize-byte salt found at the start of @p payload.
 * @throws std::runtime_error if @p payload is smaller than kSaltSize.
 */
std::string readSalt(const std::vector<unsigned char>& payload) {

    if (payload.size() < kSaltSize) {
        throw std::runtime_error("payload too small for salt");
    }

    return std::string(payload.begin(), payload.begin() + kSaltSize);
}

/**
 * @brief Derives a symmetric encryption key from a password and salt using Argon2id.
 *
 * Using Argon2id (a memory-hard KDF) rather than a plain hash means recovering the key
 * from a guessed password costs the attacker the same Argon2id time/memory budget per
 * guess as it costs a legitimate caller, rather than a cheap single hash evaluation.
 *
 * crypto_pwhash expects its memory limit in bytes, while @p config.mCost is expressed
 * in KiB per Argon2 convention, hence the `* 1024` conversion below. Note that
 * libsodium's crypto_pwhash always runs single-lane (parallelism is not configurable
 * through this API), unlike the standalone Argon2 reference implementation.
 *
 * @param config Supplies the password and Argon2id time/memory cost parameters.
 * @param salt   The salt to derive the key with; must be kSaltSize bytes.
 * @return The derived key, kKeySize bytes long.
 * @throws std::runtime_error if Argon2id key derivation fails (e.g. cost parameters
 *         below libsodium's minimums).
 */
std::vector<unsigned char> deriveKey(const EngineConfig& config, const std::string& salt) {
    std::vector<unsigned char> out(kKeySize);

    const int rc = crypto_pwhash(
        out.data(), out.size(),
        config.password.data(), config.password.size(),
        reinterpret_cast<const unsigned char*>(salt.data()),
        config.tCost,
        static_cast<std::size_t>(config.mCost) * 1024,
        crypto_pwhash_ALG_ARGON2ID13);

    if (rc != 0) {
        throw std::runtime_error("crypto_pwhash failed");
    }

    return out;
}

/**
 * @brief Reads an entire file into memory as raw bytes.
 * @param path Path to the file to read.
 * @return The full contents of the file.
 * @throws std::runtime_error if the file cannot be opened.
 */
std::vector<unsigned char> readFileBytes(const std::string& path) {
    std::ifstream input(path, std::ios::binary);

    if (!input) {
        throw std::runtime_error("unable to open input file");
    }

    return std::vector<unsigned char>(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

/**
 * @brief Writes raw bytes to a file, overwriting it if it already exists.
 * @param path Path to write to.
 * @param data Bytes to write.
 * @throws std::runtime_error if the file cannot be created/opened for writing.
 */
void writeFileBytes(const std::string& path, const std::vector<unsigned char>& data) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);

    if (!output) {
        throw std::runtime_error("unable to create output file");
    }

    output.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

/**
 * @brief Encrypts @p plaintext and assembles it into the on-disk payload layout.
 *
 * Generates a fresh random nonce, encrypts @p plaintext with XChaCha20-Poly1305 under
 * @p key and that nonce, then concatenates `salt | nonce | ciphertext+tag`. No
 * additional authenticated data (AAD) is used, since the whole point of these files is
 * that only the salt/nonce/ciphertext are ever stored -- there is no separate metadata
 * to bind to the ciphertext.
 *
 * @param plaintext The file contents to encrypt.
 * @param key       The AEAD key, as produced by deriveKey.
 * @param salt      The salt used to derive @p key; prepended verbatim to the output so
 *                  reverseFile can find it again.
 * @return The full payload: salt | nonce | ciphertext+tag.
 */
std::vector<unsigned char> buildPayload(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key, const std::string& salt) {
    std::vector<unsigned char> nonce(kNonceSize);
    generateRandomBytes(nonce);

    std::vector<unsigned char> ciphertext(plaintext.size() + kTagSize);
    unsigned long long ciphertextLen = 0;

    crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext.data(), &ciphertextLen,
        plaintext.data(), plaintext.size(),
        nullptr, 0,
        nullptr,
        nonce.data(), key.data());

    std::vector<unsigned char> payload;
    payload.reserve(kSaltSize + kNonceSize + ciphertextLen);
    payload.insert(payload.end(), salt.begin(), salt.end());
    payload.insert(payload.end(), nonce.begin(), nonce.end());
    payload.insert(payload.end(), ciphertext.begin(), ciphertext.begin() + static_cast<std::size_t>(ciphertextLen));

    return payload;
}

/**
 * @brief Reverses buildPayload: verifies and decrypts a payload back to plaintext.
 *
 * @p key must already have been derived using the salt read from this same @p payload
 * (see readSalt). Decryption failing here (a thrown exception) is the expected outcome
 * for a wrong password or a corrupted/tampered file -- there is no separate integrity
 * check beyond the AEAD tag itself, so a wrong key simply fails authentication.
 *
 * @param payload The full on-disk payload: salt | nonce | ciphertext+tag.
 * @param key     The AEAD key, derived from the same salt found in @p payload.
 * @return The recovered plaintext.
 * @throws std::runtime_error if @p payload is too small to contain a valid nonce/tag,
 *         or if authentication fails (wrong password or corrupted/tampered data).
 */
std::vector<unsigned char> parsePayload(const std::vector<unsigned char>& payload, const std::vector<unsigned char>& key) {

    if (payload.size() < kSaltSize + kNonceSize + kTagSize) {
        throw std::runtime_error("payload too small");
    }

    const unsigned char* nonce = payload.data() + kSaltSize;
    const unsigned char* ciphertext = payload.data() + kSaltSize + kNonceSize;
    const std::size_t ciphertextLen = payload.size() - kSaltSize - kNonceSize;

    std::vector<unsigned char> plaintext(ciphertextLen - kTagSize);
    unsigned long long plaintextLen = 0;

    const int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext.data(), &plaintextLen,
        nullptr,
        ciphertext, ciphertextLen,
        nullptr, 0,
        nonce, key.data());

    if (rc != 0) {
        throw std::runtime_error("integrity check failed");
    }

    plaintext.resize(static_cast<std::size_t>(plaintextLen));
    return plaintext;
}

} // namespace

/**
 * @copydoc pgo::obfuscateFile
 *
 * Implementation note: all failure modes (I/O errors, libsodium init failure, Argon2id
 * failure) are funneled through the same try/catch and reported uniformly via @p error,
 * so callers only need to check the boolean return value.
 */
bool obfuscateFile(const std::string& inputPath, const std::string& outputPath, const EngineConfig& config, std::string& error) {
    bool bSuccess = true;

    try {
        ensureSodiumInitialized();
        auto input = readFileBytes(inputPath);
        ScopedZero zeroInput(input);
        const auto salt = generateSalt();
        auto key = deriveKey(config, salt);
        ScopedZero zeroKey(key);
        auto payload = buildPayload(input, key, salt);
        writeFileBytes(outputPath, payload);
    } catch (const std::exception& ex) {
        error = ex.what();
        bSuccess = false;
    }

    return bSuccess;
}

/**
 * @copydoc pgo::reverseFile
 *
 * Implementation note: the salt is read from @p inputPath itself (see readSalt) before
 * key derivation, so the caller only ever needs to supply the password.
 */
bool reverseFile(const std::string& inputPath, const std::string& outputPath, const EngineConfig& config, std::string& error) {
    bool bSuccess = true;

    try {
        ensureSodiumInitialized();
        auto input = readFileBytes(inputPath);
        const auto salt = readSalt(input);
        auto key = deriveKey(config, salt);
        ScopedZero zeroKey(key);
        auto payload = parsePayload(input, key);
        ScopedZero zeroPayload(payload);
        writeFileBytes(outputPath, payload);
    } catch (const std::exception& ex) {
        error = ex.what();
        bSuccess = false;
    }

    return bSuccess;
}

} // namespace pgo
