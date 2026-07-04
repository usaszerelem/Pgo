#include "../Include/PgoEngine.h"

#include <array>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>

extern "C" {
#include <argon2.h>
}

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <sys/random.h>
#endif

namespace pgo {
namespace {

constexpr std::size_t kSaltSize = 16;
constexpr std::size_t kChecksumSize = 32;

struct Sha256Hash {
    std::array<unsigned char, 32> bytes{};
};

static const std::array<unsigned int, 64> k = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

std::string toHex(const std::array<unsigned char, 32>& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char b : bytes) {
        oss << std::setw(2) << static_cast<unsigned int>(b);
    }
    return oss.str();
}

std::array<unsigned int, 8> initialState() {
    return {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
            0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
}

void transform(std::array<unsigned int, 8>& state, const std::array<unsigned int, 64>& block) {
    std::array<unsigned int, 64> w{};

    for (size_t i = 0; i < 16; ++i) {
        w[i] = block[i];
    }

    for (size_t i = 16; i < 64; ++i) {
        const unsigned int s0 = ((w[i - 15] >> 7) | (w[i - 15] << 25)) ^ ((w[i - 15] >> 18) | (w[i - 15] << 14)) ^ (w[i - 15] >> 3);
        const unsigned int s1 = ((w[i - 2] >> 17) | (w[i - 2] << 15)) ^ ((w[i - 2] >> 19) | (w[i - 2] << 13)) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    std::array<unsigned int, 8> working = state;

    for (size_t i = 0; i < 64; ++i) {
        const unsigned int ch = (working[4] & working[5]) ^ (~working[4] & working[6]);
        const unsigned int maj = (working[0] & working[1]) ^ (working[0] & working[2]) ^ (working[1] & working[2]);
        const unsigned int sum0 = ((working[0] >> 2) | (working[0] << 30)) ^ ((working[0] >> 13) | (working[0] << 19)) ^ ((working[0] >> 22) | (working[0] << 10));
        const unsigned int sum1 = ((working[4] >> 6) | (working[4] << 26)) ^ ((working[4] >> 11) | (working[4] << 21)) ^ ((working[4] >> 25) | (working[4] << 7));
        const unsigned int temp1 = working[7] + sum1 + ch + k[i] + w[i];
        const unsigned int temp2 = sum0 + maj;

        working[7] = working[6];
        working[6] = working[5];
        working[5] = working[4];
        working[4] = working[3] + temp1;
        working[3] = working[2];
        working[2] = working[1];
        working[1] = working[0];
        working[0] = temp1 + temp2;
    }

    for (size_t i = 0; i < 8; ++i) {
        state[i] += working[i];
    }
}

Sha256Hash sha256(const std::vector<unsigned char>& data) {
    std::array<unsigned int, 8> state = initialState();
    std::vector<unsigned char> message = data;
    message.push_back(0x80);

    while ((message.size() * 8) % 512 != 448) {
        message.push_back(0x00);
    }

    uint64_t bitLength = static_cast<uint64_t>(data.size()) * 8;

    for (int i = 7; i >= 0; --i) {
        message.push_back(static_cast<unsigned char>((bitLength >> (i * 8)) & 0xFF));
    }

    for (size_t offset = 0; offset < message.size(); offset += 64) {
        std::array<unsigned int, 64> block{};

        for (size_t i = 0; i < 64; ++i) {
            block[i] = (i + offset < message.size()) ? static_cast<unsigned int>(message[offset + i]) : 0;
        }

        transform(state, block);
    }

    Sha256Hash result{};

    for (size_t i = 0; i < 8; ++i) {
        uint32_t value = state[i];
        result.bytes[i * 4 + 0] = static_cast<unsigned char>((value >> 24) & 0xFF);
        result.bytes[i * 4 + 1] = static_cast<unsigned char>((value >> 16) & 0xFF);
        result.bytes[i * 4 + 2] = static_cast<unsigned char>((value >> 8) & 0xFF);
        result.bytes[i * 4 + 3] = static_cast<unsigned char>(value & 0xFF);
    }
    return result;
}

bool generateRandomBytes(std::vector<unsigned char>& bytes) {

    if (bytes.empty()) {
        return true;
    }

#ifdef _WIN32
    return BCryptGenRandom(
        nullptr,
        bytes.data(),
        static_cast<ULONG>(bytes.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#else
    return getentropy(bytes.data(), bytes.size()) == 0;
#endif
}

std::string generateSalt() {
    std::vector<unsigned char> bytes(kSaltSize);

    if (!generateRandomBytes(bytes)) {
        throw std::runtime_error("failed to generate salt");
    }

    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

std::string readSalt(const std::vector<unsigned char>& payload) {

    if (payload.size() < kSaltSize) {
        throw std::runtime_error("payload too small for salt");
    }

    return std::string(payload.begin(), payload.begin() + kSaltSize);
}

std::vector<unsigned char> deriveKey(const EngineConfig& config, const std::string& salt) {
    std::vector<unsigned char> out(32);

    const int rc = argon2id_hash_raw(
        static_cast<unsigned int>(config.tCost),
        static_cast<unsigned int>(config.mCost),
        static_cast<unsigned int>(config.parallelism),
        config.password.data(),
        config.password.size(),
        salt.data(),
        salt.size(),
        out.data(),
        out.size());

    if (rc != ARGON2_OK) {
        throw std::runtime_error("argon2id_hash_raw failed");
    }

    return out;
}

void applyObfuscation(std::vector<unsigned char>& buffer, const std::vector<unsigned char>& key) {

    for (size_t i = 0; i < buffer.size(); ++i) {
        buffer[i] = static_cast<unsigned char>(buffer[i] ^ key[i % key.size()] ^ static_cast<unsigned char>(i + 1));
    }
}

std::vector<unsigned char> readFileBytes(const std::string& path) {
    std::ifstream input(path, std::ios::binary);

    if (!input) {
        throw std::runtime_error("unable to open input file");
    }

    return std::vector<unsigned char>(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

void writeFileBytes(const std::string& path, const std::vector<unsigned char>& data) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);

    if (!output) {
        throw std::runtime_error("unable to create output file");
    }

    output.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

std::vector<unsigned char> buildPayload(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key, const std::string& salt) {
    std::vector<unsigned char> payload;
    payload.reserve(kSaltSize + kChecksumSize + plaintext.size());
    payload.insert(payload.end(), salt.begin(), salt.end());

    auto checksum = sha256(plaintext);
    payload.insert(payload.end(), checksum.bytes.begin(), checksum.bytes.end());

    std::vector<unsigned char> body = plaintext;
    applyObfuscation(body, key);
    payload.insert(payload.end(), body.begin(), body.end());

    return payload;
}

std::vector<unsigned char> parsePayload(const std::vector<unsigned char>& payload, const std::vector<unsigned char>& key) {

    if (payload.size() < kSaltSize + kChecksumSize) {
        throw std::runtime_error("payload too small");
    }

    std::vector<unsigned char> header(payload.begin() + kSaltSize, payload.begin() + kSaltSize + kChecksumSize);
    std::vector<unsigned char> body(payload.begin() + kSaltSize + kChecksumSize, payload.end());
    applyObfuscation(body, key);
    auto checksum = sha256(body);

    std::vector<unsigned char> expected(checksum.bytes.begin(), checksum.bytes.end());

    if (expected != header) {
        throw std::runtime_error("integrity check failed");
    }

    return body;
}

} // namespace

bool obfuscateFile(const std::string& inputPath, const std::string& outputPath, const EngineConfig& config, std::string& error) {
    bool bSuccess = true;

    try {
        auto input = readFileBytes(inputPath);
        const auto salt = generateSalt();
        auto key = deriveKey(config, salt);
        auto payload = buildPayload(input, key, salt);
        writeFileBytes(outputPath, payload);
    } catch (const std::exception& ex) {
        error = ex.what();
        bSuccess = false;
    }

    return bSuccess;
}

bool reverseFile(const std::string& inputPath, const std::string& outputPath, const EngineConfig& config, std::string& error) {
    bool bSuccess = true;

    try {
        auto input = readFileBytes(inputPath);
        const auto salt = readSalt(input);
        auto key = deriveKey(config, salt);
        auto payload = parsePayload(input, key);
        writeFileBytes(outputPath, payload);
    } catch (const std::exception& ex) {
        error = ex.what();
        bSuccess = false;
    }

    return bSuccess;
}

} // namespace pgo
