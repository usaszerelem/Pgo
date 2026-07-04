#pragma once

#include <cstdint>
#include <string>
#include <vector>

/**
 * @file PgoEngine.h
 * @brief Public API for password-based authenticated file encryption.
 *
 * The engine encrypts a file with a key derived from a password (via Argon2id) and an
 * authenticated stream cipher (XChaCha20-Poly1305 via libsodium's secretstream API), so
 * that the output cannot be decrypted or tampered with undetected without knowing the
 * password. Files are processed in fixed-size chunks rather than read into memory in
 * full, so encrypting/decrypting a file requires only O(chunk size) memory regardless of
 * file size. See PgoEngine.cpp for the on-disk payload layout and the implementation
 * details of key derivation, chunking, and encryption.
 */

namespace pgo {

/**
 * @brief Parameters controlling how the encryption key is derived from a password.
 *
 * tCost and mCost are passed to libsodium's crypto_pwhash (Argon2id) to control how
 * expensive key derivation is, which in turn controls how expensive an offline
 * password-guessing attack against an encrypted file would be.
 *
 * @var EngineConfig::password
 *   The password used to derive the encryption key. Required.
 * @var EngineConfig::salt
 *   Unused by obfuscateFile/reverseFile; each call generates or reads its own salt
 *   from the file itself. Reserved for callers that need to track it separately.
 * @var EngineConfig::tCost
 *   Argon2id time cost (number of iterations/passes over memory).
 * @var EngineConfig::mCost
 *   Argon2id memory cost, in KiB (Argon2 convention). Converted to bytes internally
 *   before being passed to crypto_pwhash.
 */
struct EngineConfig {
    std::string password;
    std::string salt;
    uint32_t tCost = 2;
    uint32_t mCost = 1u << 16;
};

/**
 * @brief Encrypts a file with a key derived from @p config.password.
 *
 * Streams @p inputPath in fixed-size chunks rather than reading it into memory in full,
 * derives a key using Argon2id with a freshly generated random salt, encrypts each chunk
 * with XChaCha20-Poly1305 (via libsodium's secretstream API), and writes
 * `salt | stream header | chunk 1 | chunk 2 | ... | final chunk` to @p outputPath.
 *
 * @param inputPath  Path to the plaintext file to encrypt.
 * @param outputPath Path to write the encrypted output to (overwritten if it exists).
 * @param config     Password and Argon2id cost parameters to use for key derivation.
 * @param error      Set to a human-readable message if this function returns false.
 * @return true on success, false on failure (see @p error for the reason).
 */
bool obfuscateFile(const std::string& inputPath,
                   const std::string& outputPath,
                   const EngineConfig& config,
                   std::string& error);

/**
 * @brief Decrypts a file previously produced by obfuscateFile.
 *
 * Reads the salt and stream header from the start of @p inputPath, re-derives the key
 * using @p config.password, and streams the remaining chunks, decrypting and
 * authenticating each one in turn rather than reading the whole file into memory. Since
 * every chunk is authenticated (and tagged with whether it is the last one), this fails
 * safely (returns false) rather than silently producing garbage or truncated output when
 * the password is wrong or the file has been corrupted, tampered with, or truncated.
 *
 * @param inputPath  Path to a file previously written by obfuscateFile.
 * @param outputPath Path to write the recovered plaintext to (overwritten if it exists).
 * @param config     Must contain the same password and Argon2id cost parameters that
 *                   were used to produce @p inputPath.
 * @param error      Set to a human-readable message if this function returns false.
 * @return true on success, false on failure (see @p error for the reason).
 */
bool reverseFile(const std::string& inputPath,
                 const std::string& outputPath,
                 const EngineConfig& config,
                 std::string& error);

} // namespace pgo
