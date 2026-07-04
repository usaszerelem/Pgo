#include "../Include/PgoEngine.h"

#include <filesystem>
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
 *   [ salt (kSaltSize bytes) | stream header (kHeaderSize bytes) | chunk 1 | chunk 2 | ... | final chunk ]
 * @endcode
 *
 * Each chunk is `plaintext (up to kChunkSize bytes) + kStreamTagSize bytes of AEAD tag`,
 * produced by libsodium's crypto_secretstream_xchacha20poly1305 API. The file is read and
 * written one chunk at a time (encryption and decryption both run in O(kChunkSize)
 * memory), rather than loading the whole file into a single buffer, so file size is no
 * longer bounded by available memory.
 *
 * The salt and stream header are not secret -- they are stored in plaintext so that
 * reverseFile can re-derive the same key and re-initialize the stream without any side
 * channel. Confidentiality and integrity both come from the password: the salt feeds
 * Argon2id key derivation (deriveKey), and crypto_secretstream authenticates each chunk
 * (detecting a wrong password or a tampered/corrupted file) and binds every chunk to its
 * position in the stream and to whether it is the last one, so truncating a file (e.g.
 * dropping the final chunk) is detected rather than silently accepted.
 *
 * The derived key and any decrypted plaintext chunk are scrubbed from memory as soon as
 * they are no longer needed, via the ScopedZero RAII guard, so they don't linger in freed
 * heap memory for longer than necessary.
 */

namespace pgo {
namespace {

namespace fs = std::filesystem;

/// Size, in bytes, of the random salt used for Argon2id key derivation.
constexpr std::size_t kSaltSize = 16;
/// Size, in bytes, of the derived symmetric key.
constexpr std::size_t kKeySize = crypto_secretstream_xchacha20poly1305_KEYBYTES;
/// Size, in bytes, of the per-stream header written once at the start of the ciphertext.
constexpr std::size_t kHeaderSize = crypto_secretstream_xchacha20poly1305_HEADERBYTES;
/// Size, in bytes, of the AEAD tag appended to every chunk's ciphertext.
constexpr std::size_t kStreamTagSize = crypto_secretstream_xchacha20poly1305_ABYTES;
/// Number of plaintext bytes read/encrypted (or decrypted/written) per chunk.
constexpr std::size_t kChunkSize = 64 * 1024;

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
 * @brief Writes to a temporary file alongside the destination and only replaces it with
 *        that temporary file's contents once the caller confirms the write succeeded.
 *
 * Chunked streaming encryption/decryption authenticates each chunk as it goes, so a
 * failure partway through a large file (wrong password, corrupted/tampered data) is only
 * detected after some earlier chunks have already been written out. Writing directly to
 * @p finalPath would leave a truncated, unusable file behind on failure; writing to a
 * sibling temp file and renaming it into place on success (see commit()) keeps that
 * failure from disturbing whatever was previously at @p finalPath.
 */
class AtomicOutputFile {
public:
    explicit AtomicOutputFile(const std::string& finalPath)
        : finalPath_(finalPath), tempPath_(finalPath + ".pgotmp") {
        stream_.open(tempPath_, std::ios::binary | std::ios::trunc);
        if (!stream_) {
            throw std::runtime_error("unable to create output file");
        }
    }

    ~AtomicOutputFile() {
        if (!committed_) {
            stream_.close();
            std::error_code ec;
            fs::remove(tempPath_, ec);
        }
    }

    AtomicOutputFile(const AtomicOutputFile&) = delete;
    AtomicOutputFile& operator=(const AtomicOutputFile&) = delete;

    std::ofstream& stream() { return stream_; }

    /// Finalizes the write by moving the temp file into place at finalPath.
    void commit() {
        stream_.close();
        if (!stream_) {
            throw std::runtime_error("failed to finalize output file");
        }

        std::error_code ec;
        fs::rename(tempPath_, finalPath_, ec);
        if (ec) {
            // rename() fails across filesystem boundaries on some platforms; fall back to
            // copy+remove so this still works if outputPath is on another device/mount.
            fs::copy_file(tempPath_, finalPath_, fs::copy_options::overwrite_existing, ec);
            if (ec) {
                throw std::runtime_error("unable to write to output file");
            }
            fs::remove(tempPath_, ec);
        }

        committed_ = true;
    }

private:
    std::string finalPath_;
    std::string tempPath_;
    std::ofstream stream_;
    bool committed_ = false;
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
 * @brief Reads the salt from the start of an encrypted payload's input stream.
 *
 * Consumes exactly kSaltSize bytes from @p input, leaving the stream positioned at the
 * start of the stream header that follows.
 *
 * @param input Stream open on a file previously written by obfuscateFile.
 * @return The kSaltSize-byte salt found at the start of the payload.
 * @throws std::runtime_error if fewer than kSaltSize bytes are available.
 */
std::string readSalt(std::ifstream& input) {
    std::vector<unsigned char> bytes(kSaltSize);
    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));

    if (static_cast<std::size_t>(input.gcount()) != bytes.size()) {
        throw std::runtime_error("payload too small for salt");
    }

    return std::string(bytes.begin(), bytes.end());
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
 * @brief Encrypts @p input to @p output as a sequence of authenticated chunks.
 *
 * Writes a fresh stream header, then repeatedly reads up to kChunkSize plaintext bytes
 * from @p input, encrypts them, and writes `ciphertext + tag` to @p output. The chunk
 * containing the last of the input (including a single empty chunk for an empty input)
 * is marked with TAG_FINAL so reverseFile can detect truncation; every other chunk is
 * marked TAG_MESSAGE.
 *
 * @param input  Plaintext stream, positioned at the start of the data to encrypt.
 * @param output Stream to append the stream header and encrypted chunks to.
 * @param key    The AEAD key, as produced by deriveKey.
 * @throws std::runtime_error if stream initialization fails or a write fails.
 */
void encryptStream(std::ifstream& input, std::ofstream& output, const std::vector<unsigned char>& key) {
    crypto_secretstream_xchacha20poly1305_state state;
    std::vector<unsigned char> header(kHeaderSize);

    if (crypto_secretstream_xchacha20poly1305_init_push(&state, header.data(), key.data()) != 0) {
        throw std::runtime_error("failed to initialize encryption stream");
    }

    output.write(reinterpret_cast<const char*>(header.data()), static_cast<std::streamsize>(header.size()));

    std::vector<unsigned char> plainChunk(kChunkSize);
    ScopedZero zeroPlainChunk(plainChunk);
    std::vector<unsigned char> cipherChunk(kChunkSize + kStreamTagSize);

    bool isFinalChunk = false;
    while (!isFinalChunk) {
        input.read(reinterpret_cast<char*>(plainChunk.data()), static_cast<std::streamsize>(plainChunk.size()));
        const auto bytesRead = static_cast<std::size_t>(input.gcount());

        // Peeking here (rather than checking input.eof() after the read above) is what
        // lets us mark the last chunk TAG_FINAL even when the input size is an exact
        // multiple of kChunkSize, in which case the read above fills the buffer fully
        // without tripping eofbit.
        isFinalChunk = input.peek() == std::char_traits<char>::eof();
        const unsigned char tag = isFinalChunk ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
                                                : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

        unsigned long long cipherLen = 0;
        crypto_secretstream_xchacha20poly1305_push(
            &state, cipherChunk.data(), &cipherLen,
            plainChunk.data(), bytesRead,
            nullptr, 0, tag);

        output.write(reinterpret_cast<const char*>(cipherChunk.data()), static_cast<std::streamsize>(cipherLen));
        if (!output) {
            throw std::runtime_error("failed to write encrypted output");
        }
    }
}

/**
 * @brief Reverses encryptStream: verifies and decrypts a chunked payload back to plaintext.
 *
 * @p input must be positioned immediately after the salt, at the start of the stream
 * header. Each chunk is authenticated as it is read, and its tag is checked against
 * whether it is actually the last chunk in @p input, so both tampering with any chunk and
 * truncating the file (dropping the real final chunk, or appending data after it) are
 * detected.
 *
 * @param input  Ciphertext stream, positioned at the start of the stream header.
 * @param output Stream to write the recovered plaintext to, one chunk at a time.
 * @param key    The AEAD key, derived from the same salt this payload was written with.
 * @throws std::runtime_error if the header is missing/invalid, a chunk fails
 *         authentication, the payload ends before a TAG_FINAL chunk is seen, or data
 *         follows the TAG_FINAL chunk.
 */
void decryptStream(std::ifstream& input, std::ofstream& output, const std::vector<unsigned char>& key) {
    std::vector<unsigned char> header(kHeaderSize);
    input.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size()));
    if (static_cast<std::size_t>(input.gcount()) != header.size()) {
        throw std::runtime_error("payload too small for stream header");
    }

    crypto_secretstream_xchacha20poly1305_state state;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header.data(), key.data()) != 0) {
        throw std::runtime_error("invalid stream header");
    }

    std::vector<unsigned char> cipherChunk(kChunkSize + kStreamTagSize);
    std::vector<unsigned char> plainChunk(kChunkSize);
    ScopedZero zeroPlainChunk(plainChunk);

    bool sawFinalChunk = false;
    while (!sawFinalChunk) {
        input.read(reinterpret_cast<char*>(cipherChunk.data()), static_cast<std::streamsize>(cipherChunk.size()));
        const auto bytesRead = static_cast<std::size_t>(input.gcount());

        if (bytesRead == 0) {
            throw std::runtime_error("truncated payload: missing final chunk");
        }

        unsigned char tag = 0;
        unsigned long long plainLen = 0;
        const int rc = crypto_secretstream_xchacha20poly1305_pull(
            &state, plainChunk.data(), &plainLen, &tag,
            cipherChunk.data(), static_cast<unsigned long long>(bytesRead),
            nullptr, 0);

        if (rc != 0) {
            throw std::runtime_error("integrity check failed");
        }

        sawFinalChunk = (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL);
        if (!sawFinalChunk && bytesRead < cipherChunk.size()) {
            throw std::runtime_error("truncated payload: missing final chunk");
        }

        output.write(reinterpret_cast<const char*>(plainChunk.data()), static_cast<std::streamsize>(plainLen));
        if (!output) {
            throw std::runtime_error("failed to write decrypted output");
        }
    }

    if (input.peek() != std::char_traits<char>::eof()) {
        throw std::runtime_error("unexpected trailing data after final chunk");
    }
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

        std::ifstream input(inputPath, std::ios::binary);
        if (!input) {
            throw std::runtime_error("unable to open input file");
        }

        const auto salt = generateSalt();
        auto key = deriveKey(config, salt);
        ScopedZero zeroKey(key);

        AtomicOutputFile output(outputPath);
        output.stream().write(salt.data(), static_cast<std::streamsize>(salt.size()));
        encryptStream(input, output.stream(), key);
        output.commit();
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

        std::ifstream input(inputPath, std::ios::binary);
        if (!input) {
            throw std::runtime_error("unable to open input file");
        }

        const auto salt = readSalt(input);
        auto key = deriveKey(config, salt);
        ScopedZero zeroKey(key);

        AtomicOutputFile output(outputPath);
        decryptStream(input, output.stream(), key);
        output.commit();
    } catch (const std::exception& ex) {
        error = ex.what();
        bSuccess = false;
    }

    return bSuccess;
}

} // namespace pgo
