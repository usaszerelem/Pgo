//#include <iostream>
//#include <cstring>
//#include <cstdint>
//#include <cstdio>
//#include "argon2.h"

#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <random>
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include "argon2.h"

namespace {
    std::vector<uint8_t> sha256(const std::vector<uint8_t>& input) {
        static const std::array<uint32_t, 64> k = {
            0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
            0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
            0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
            0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
            0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
            0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
            0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
            0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
            0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
            0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
            0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
            0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
            0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
            0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
            0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
            0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
        };

        auto rotr = [](uint32_t value, uint32_t amount) -> uint32_t {
            return (value >> amount) | (value << (32 - amount));
        };

        auto ch = [](uint32_t x, uint32_t y, uint32_t z) -> uint32_t {
            return (x & y) ^ (~x & z);
        };

        auto maj = [](uint32_t x, uint32_t y, uint32_t z) -> uint32_t {
            return (x & y) ^ (x & z) ^ (y & z);
        };

        auto sigmoid0 = [&](uint32_t x) -> uint32_t {
            return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
        };

        auto sigmoid1 = [&](uint32_t x) -> uint32_t {
            return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
        };

        uint32_t h0 = 0x6a09e667U;
        uint32_t h1 = 0xbb67ae85U;
        uint32_t h2 = 0x3c6ef372U;
        uint32_t h3 = 0xa54ff53aU;
        uint32_t h4 = 0x510e527fU;
        uint32_t h5 = 0x9b05688cU;
        uint32_t h6 = 0x1f83d9abU;
        uint32_t h7 = 0x5be0cd19U;

        std::vector<uint8_t> message(input.begin(), input.end());
        message.push_back(0x80);

        while ((message.size() % 64) != 56) {
            message.push_back(0x00);
        }

        uint64_t bitLength = static_cast<uint64_t>(input.size()) * 8U;
        for (int shift = 7; shift >= 0; --shift) {
            message.push_back(static_cast<uint8_t>((bitLength >> (shift * 8)) & 0xFFU));
        }

        for (size_t offset = 0; offset < message.size(); offset += 64) {
            std::array<uint32_t, 64> w{};
            for (size_t i = 0; i < 16; ++i) {
                const size_t index = offset + i * 4;
                w[i] = ((uint32_t)message[index] << 24) |
                       ((uint32_t)message[index + 1] << 16) |
                       ((uint32_t)message[index + 2] << 8) |
                       (uint32_t)message[index + 3];
            }

            for (size_t i = 16; i < 64; ++i) {
                w[i] = sigmoid1(w[i - 2]) + w[i - 7] + sigmoid0(w[i - 15]) + w[i - 16];
            }

            uint32_t a = h0;
            uint32_t b = h1;
            uint32_t c = h2;
            uint32_t d = h3;
            uint32_t e = h4;
            uint32_t f = h5;
            uint32_t g = h6;
            uint32_t h = h7;

            for (size_t i = 0; i < 64; ++i) {
                uint32_t temp1 = h + ((rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ch(e, f, g) + k[i] + w[i]);
                uint32_t temp2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;
            h5 += f;
            h6 += g;
            h7 += h;
        }

        std::vector<uint8_t> digest(32);
        auto append32 = [&](uint32_t value, size_t index) {
            digest[index] = static_cast<uint8_t>((value >> 24) & 0xFFU);
            digest[index + 1] = static_cast<uint8_t>((value >> 16) & 0xFFU);
            digest[index + 2] = static_cast<uint8_t>((value >> 8) & 0xFFU);
            digest[index + 3] = static_cast<uint8_t>(value & 0xFFU);
        };

        append32(h0, 0);
        append32(h1, 4);
        append32(h2, 8);
        append32(h3, 12);
        append32(h4, 16);
        append32(h5, 20);
        append32(h6, 24);
        append32(h7, 28);

        return digest;
    }
}

class DiffusedRollingCipher {
private:
    std::vector<uint8_t> table;
    int i;
    int j;

    // Initializes the 256-byte table using a mixed Key + IV combination
    void initializeTable(const std::string& key, const std::vector<uint8_t>& iv) {
        table.resize(256);
        for (int k = 0; k < 256; ++k) {
            table[k] = static_cast<uint8_t>(k);
        }

        // Mix the key and IV together to create a unique compound key
        std::vector<uint8_t> compoundKey(key.begin(), key.end());
        compoundKey.insert(compoundKey.end(), iv.begin(), iv.end());

        int keyLength = static_cast<int>(compoundKey.size());
        if (keyLength == 0) return;

        int shuffleJ = 0;
        for (int k = 0; k < 256; ++k) {
            shuffleJ = (shuffleJ + table[k] + compoundKey[k % keyLength]) % 256;
            std::swap(table[k], table[shuffleJ]);
        }

        i = 0;
        j = 0;
    }

    // Generates a dynamic pseudo-random byte and morphs the state table
    uint8_t getNextRollingByte() {
        i = (i + 1) % 256;
        j = (j + table[i]) % 256;
        std::swap(table[i], table[j]);
        return table[(table[i] + table[j]) % 256];
    }

public:
    // Generates cryptographically secure random bytes via hardware entropy
    std::vector<uint8_t> generateSecureIV(size_t size) {
        std::random_device rd;
        std::vector<uint8_t> iv(size);
        std::generate(iv.begin(), iv.end(), [&rd]() {
            return static_cast<uint8_t>(rd() & 0xFF);
            });
        return iv;
    }

    // High-level Obfuscation: Double-Pass Diffusion (Forward then Backward)
    std::vector<uint8_t> obfuscate(const std::vector<uint8_t>& inputData, const std::string& key) {
        if (inputData.empty()) return {};

        // 1. Generate a brand new unique 16-byte IV
        std::vector<uint8_t> iv = generateSecureIV(16);

        // 2. Initialize state for Pass 1
        initializeTable(key, iv);
        std::vector<uint8_t> pass1Data(inputData.size());

        // PASS 1: Forward Processing (First byte to last byte)
        for (size_t k = 0; k < inputData.size(); ++k) {
            pass1Data[k] = inputData[k] ^ getNextRollingByte();
        }

        // PASS 2: Backward Processing (Last byte to first byte)
        std::vector<uint8_t> pass2Data(pass1Data.size());
        for (size_t k = pass1Data.size(); k > 0; --k) {
            size_t index = k - 1;
            pass2Data[index] = pass1Data[index] ^ getNextRollingByte();
        }

        // 3. Assemble final package: [ 16-byte IV ] + [ 32-byte SHA-256 ] + [ Diffused Payload ]
        std::vector<uint8_t> integrityInput;
        integrityInput.reserve(iv.size() + pass2Data.size());
        integrityInput.insert(integrityInput.end(), iv.begin(), iv.end());
        integrityInput.insert(integrityInput.end(), pass2Data.begin(), pass2Data.end());
        std::vector<uint8_t> checksum = sha256(integrityInput);

        std::vector<uint8_t> output;
        output.reserve(iv.size() + checksum.size() + pass2Data.size());
        output.insert(output.end(), iv.begin(), iv.end());
        output.insert(output.end(), checksum.begin(), checksum.end());
        output.insert(output.end(), pass2Data.begin(), pass2Data.end());

        return output;
    }

    // High-level De-obfuscation: Reverses steps exactly in opposite order
    std::vector<uint8_t> reverse(const std::vector<uint8_t>& packedData, const std::string& key) {
        if (packedData.size() < 16 + 32) {
            std::cerr << "Error: Packed data is too short to contain a valid IV and checksum.\n";
            return {};
        }

        // 1. Extract the 16-byte IV and 32-byte SHA-256 checksum from the front
        std::vector<uint8_t> iv(packedData.begin(), packedData.begin() + 16);
        std::vector<uint8_t> checksum(packedData.begin() + 16, packedData.begin() + 48);

        // 2. Isolate the payload data
        std::vector<uint8_t> payload(packedData.begin() + 48, packedData.end());
        if (payload.empty()) return {};

        std::vector<uint8_t> integrityInput;
        integrityInput.reserve(iv.size() + payload.size());
        integrityInput.insert(integrityInput.end(), iv.begin(), iv.end());
        integrityInput.insert(integrityInput.end(), payload.begin(), payload.end());

        std::vector<uint8_t> expectedChecksum = sha256(integrityInput);
        if (checksum != expectedChecksum) {
            std::cerr << "Error: Integrity check failed. The data appears to have been tampered with.\n";
            return {};
        }

        // 3. Generate the identical keystream sequence chronologically
        initializeTable(key, iv);
        size_t totalStreamBytes = payload.size() * 2;
        std::vector<uint8_t> keystream(totalStreamBytes);
        for (size_t k = 0; k < totalStreamBytes; ++k) {
            keystream[k] = getNextRollingByte();
        }

        // 4. Reverse Pass 2 (Backward Obfuscation)
        // Pass 2 consumed keystream indices [N] to [2N-1] sequentially as it looped down.
        std::vector<uint8_t> pass1Data(payload.size());
        size_t keystreamIndex = payload.size(); // Start at index N
        for (size_t k = payload.size(); k > 0; --k) {
            size_t index = k - 1;
            pass1Data[index] = payload[index] ^ keystream[keystreamIndex];
            keystreamIndex++;
        }

        // 5. Reverse Pass 1 (Forward Obfuscation)
        // Pass 1 consumed keystream indices [0] to [N-1] sequentially.
        std::vector<uint8_t> originalData(pass1Data.size());
        for (size_t k = 0; k < pass1Data.size(); ++k) {
            originalData[k] = pass1Data[k] ^ keystream[k];
        }

        return originalData;
    }
};

void printHex(const std::string& label, const std::vector<uint8_t>& data) {
    std::cout << std::left << std::setw(15) << label << ": ";
    for (uint8_t byte : data) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << "\n";
}

struct CommandLineOptions {
    std::string password;
    std::string salt;
    std::string inputPath;
    std::string outputPath;
    std::string mode;
};

void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " -input=<path> -output=<path> -mode=<obfuscate|reverse> [-password=value] [-salt=value] [-help]\n";
}

bool readFile(const std::string& path, std::vector<uint8_t>& data, std::string& error) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        error = "Unable to open input file: " + path;
        return false;
    }

    input.seekg(0, std::ios::end);
    const std::streamoff size = input.tellg();
    input.seekg(0, std::ios::beg);

    data.resize(static_cast<size_t>(size));
    if (size > 0 && !input.read(reinterpret_cast<char*>(data.data()), size)) {
        error = "Unable to read input file: " + path;
        return false;
    }

    return true;
}

bool writeFile(const std::string& path, const std::vector<uint8_t>& data, std::string& error) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        error = "Unable to open output file for writing: " + path;
        return false;
    }

    if (!data.empty() && !output.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()))) {
        error = "Unable to write output file: " + path;
        return false;
    }

    return true;
}

CommandLineOptions parseCommandLine(int argc, char* argv[]) {
    CommandLineOptions options;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-help") {
            printUsage(argv[0]);
            std::exit(0);
        }

        if (arg == "-input" || arg == "-output" || arg == "-mode" || arg == "-password" || arg == "-salt") {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for argument: " << arg << "\n";
                continue;
            }

            const std::string value = argv[++i];
            if (arg == "-input") {
                options.inputPath = value;
            } else if (arg == "-output") {
                options.outputPath = value;
            } else if (arg == "-mode") {
                options.mode = value;
            } else if (arg == "-password") {
                options.password = value;
            } else if (arg == "-salt") {
                options.salt = value;
            }
            continue;
        }

        if (arg.rfind("-", 0) != 0 || arg.find('=') == std::string::npos) {
            std::cerr << "Invalid argument format: " << arg << ". Use -command=value.\n";
            continue;
        }

        const std::size_t separator = arg.find('=');
        const std::string key = arg.substr(1, separator - 1);
        const std::string value = arg.substr(separator + 1);

        if (key == "password") {
            options.password = value;
        } else if (key == "salt") {
            options.salt = value;
        } else if (key == "input") {
            options.inputPath = value;
        } else if (key == "output") {
            options.outputPath = value;
        } else if (key == "mode") {
            options.mode = value;
        } else {
            std::cerr << "Unknown argument: " << key << "\n";
        }
    }

    return options;
}

int main(int argc, char* argv[]) {
    CommandLineOptions options = parseCommandLine(argc, argv);

    if (options.inputPath.empty() || options.outputPath.empty() || options.mode.empty()) {
        printUsage(argv[0]);
        std::cerr << "Input, output, and mode are required.\n";
        return 1;
    }

    std::string mode = options.mode;
    std::transform(mode.begin(), mode.end(), mode.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    if (mode != "obfuscate" && mode != "reverse") {
        std::cerr << "Mode must be either 'obfuscate' or 'reverse'.\n";
        return 1;
    }

    if (options.inputPath == options.outputPath) {
        std::cerr << "Input and output paths must be different.\n";
        return 1;
    }

    std::string secretPassword = options.password.empty() ? "SuperSecretPassword123" : options.password;
    std::string salt = options.salt.empty() ? "pixiedust" : options.salt;
    if (salt.size() < 8) {
        while (salt.size() < 8) {
            salt.append(salt);
        }
    }

    uint8_t hash[32];

#ifdef _DEBUG
    const uint32_t t_cost = 2;
    const uint32_t m_cost = 1 << 16;
    const uint32_t parallelism = 1;
#else
    const uint32_t t_cost = 4;
    const uint32_t m_cost = 1 << 18;
    const uint32_t parallelism = 2;
#endif

    int ret = argon2id_hash_raw(
        t_cost,
        m_cost,
        parallelism,
        secretPassword.c_str(), secretPassword.length(),
        salt.c_str(), salt.length(),
        hash, sizeof(hash)
    );

    if (ret != ARGON2_OK) {
        std::cerr << argon2_error_message(ret) << std::endl;
        return 1;
    }

    std::vector<uint8_t> hashBytes(hash, hash + sizeof(hash));
    std::string derivedKey = secretPassword;
    derivedKey.append(reinterpret_cast<const char*>(hash), sizeof(hash));

    std::vector<uint8_t> inputData;
    std::string fileError;
    if (!readFile(options.inputPath, inputData, fileError)) {
        std::cerr << fileError << std::endl;
        return 1;
    }

    DiffusedRollingCipher cipher;
    std::vector<uint8_t> outputData;
    if (mode == "obfuscate") {
        outputData = cipher.obfuscate(inputData, derivedKey);
    } else {
        outputData = cipher.reverse(inputData, derivedKey);
        if (outputData.empty() && !inputData.empty()) {
            std::cerr << "Reverse operation failed. The input data may be invalid or tampered with." << std::endl;
            return 1;
        }
    }

    if (!writeFile(options.outputPath, outputData, fileError)) {
        std::cerr << fileError << std::endl;
        return 1;
    }

    std::cout << "Processed " << inputData.size() << " bytes using mode '" << mode << "'.\n";
    std::cout << "Input:  " << options.inputPath << "\n";
    std::cout << "Output: " << options.outputPath << "\n";

    return 0;
}
