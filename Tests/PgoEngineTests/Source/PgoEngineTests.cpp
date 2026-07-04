#include <gtest/gtest.h>

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <string>

#include "PgoEngine.h"

namespace {

namespace fs = std::filesystem;

std::string readFile(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

void writeFile(const fs::path& path, const std::string& contents) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
}

// Uses libsodium's minimum accepted Argon2id cost parameters (rather than
// EngineConfig's production defaults) so these tests run in milliseconds, not seconds.
pgo::EngineConfig makeFastConfig(const std::string& password) {
    pgo::EngineConfig config;
    config.password = password;
    config.tCost = 1;
    config.mCost = 8; // KiB; 8192 bytes is crypto_pwhash_argon2id's MEMLIMIT_MIN.
    return config;
}

class PgoEngineTest : public ::testing::Test {
protected:
    void SetUp() override {
        const auto* testInfo = ::testing::UnitTest::GetInstance()->current_test_info();
        tempDir_ = fs::path(::testing::TempDir()) /
            (std::string("PgoEngineTests_") + testInfo->test_suite_name() + "_" + testInfo->name());
        std::error_code ec;
        fs::remove_all(tempDir_, ec);
        fs::create_directories(tempDir_);
    }

    void TearDown() override {
        std::error_code ec;
        fs::remove_all(tempDir_, ec);
    }

    fs::path path(const std::string& name) const { return tempDir_ / name; }

    fs::path tempDir_;
};

} // namespace

TEST_F(PgoEngineTest, RoundTripRecoversOriginalContent) {
    const std::string plaintext = "The quick brown fox jumps over the lazy dog.";
    writeFile(path("input.txt"), plaintext);

    auto config = makeFastConfig("correct horse battery staple");
    std::string error;

    ASSERT_TRUE(pgo::obfuscateFile(path("input.txt").string(), path("encrypted.bin").string(), config, error)) << error;
    ASSERT_TRUE(pgo::reverseFile(path("encrypted.bin").string(), path("output.txt").string(), config, error)) << error;

    EXPECT_EQ(readFile(path("output.txt")), plaintext);
}

TEST_F(PgoEngineTest, RoundTripHandlesEmptyFile) {
    writeFile(path("input.txt"), "");

    auto config = makeFastConfig("password");
    std::string error;

    ASSERT_TRUE(pgo::obfuscateFile(path("input.txt").string(), path("encrypted.bin").string(), config, error)) << error;
    ASSERT_TRUE(pgo::reverseFile(path("encrypted.bin").string(), path("output.txt").string(), config, error)) << error;

    EXPECT_EQ(readFile(path("output.txt")), "");
}

TEST_F(PgoEngineTest, EncryptedOutputDoesNotContainPlaintext) {
    const std::string plaintext = "super secret contents that must not leak";
    writeFile(path("input.txt"), plaintext);

    auto config = makeFastConfig("password");
    std::string error;

    ASSERT_TRUE(pgo::obfuscateFile(path("input.txt").string(), path("encrypted.bin").string(), config, error)) << error;

    const std::string encrypted = readFile(path("encrypted.bin"));
    EXPECT_EQ(encrypted.find(plaintext), std::string::npos);
}

TEST_F(PgoEngineTest, RepeatedObfuscationOfSamePlaintextProducesDifferentCiphertext) {
    writeFile(path("input.txt"), "identical content");

    auto config = makeFastConfig("password");
    std::string error;

    ASSERT_TRUE(pgo::obfuscateFile(path("input.txt").string(), path("encrypted1.bin").string(), config, error)) << error;
    ASSERT_TRUE(pgo::obfuscateFile(path("input.txt").string(), path("encrypted2.bin").string(), config, error)) << error;

    EXPECT_NE(readFile(path("encrypted1.bin")), readFile(path("encrypted2.bin")));
}

TEST_F(PgoEngineTest, ReverseFailsWithWrongPassword) {
    writeFile(path("input.txt"), "some content");

    auto config = makeFastConfig("correct-password");
    std::string error;
    ASSERT_TRUE(pgo::obfuscateFile(path("input.txt").string(), path("encrypted.bin").string(), config, error)) << error;

    auto wrongConfig = makeFastConfig("wrong-password");
    EXPECT_FALSE(pgo::reverseFile(path("encrypted.bin").string(), path("output.txt").string(), wrongConfig, error));
    EXPECT_FALSE(error.empty());
}

TEST_F(PgoEngineTest, ReverseFailsWithTamperedCiphertext) {
    writeFile(path("input.txt"), "some content that is long enough to tamper with");

    auto config = makeFastConfig("password");
    std::string error;
    ASSERT_TRUE(pgo::obfuscateFile(path("input.txt").string(), path("encrypted.bin").string(), config, error)) << error;

    std::string encrypted = readFile(path("encrypted.bin"));
    ASSERT_FALSE(encrypted.empty());
    encrypted.back() ^= 0x01; // Flip a bit in the trailing AEAD tag.
    writeFile(path("tampered.bin"), encrypted);

    EXPECT_FALSE(pgo::reverseFile(path("tampered.bin").string(), path("output.txt").string(), config, error));
    EXPECT_FALSE(error.empty());
}

TEST_F(PgoEngineTest, ReverseFailsOnTruncatedPayload) {
    writeFile(path("input.txt"), "content");

    auto config = makeFastConfig("password");
    std::string error;
    ASSERT_TRUE(pgo::obfuscateFile(path("input.txt").string(), path("encrypted.bin").string(), config, error)) << error;

    const std::string encrypted = readFile(path("encrypted.bin"));
    ASSERT_GT(encrypted.size(), std::size_t{4});
    writeFile(path("truncated.bin"), encrypted.substr(0, 4));

    EXPECT_FALSE(pgo::reverseFile(path("truncated.bin").string(), path("output.txt").string(), config, error));
    EXPECT_FALSE(error.empty());
}

TEST_F(PgoEngineTest, ObfuscateFailsWhenInputFileMissing) {
    auto config = makeFastConfig("password");
    std::string error;

    EXPECT_FALSE(pgo::obfuscateFile(path("does_not_exist.txt").string(), path("encrypted.bin").string(), config, error));
    EXPECT_FALSE(error.empty());
}

TEST_F(PgoEngineTest, ReverseFailsWhenInputFileMissing) {
    auto config = makeFastConfig("password");
    std::string error;

    EXPECT_FALSE(pgo::reverseFile(path("does_not_exist.bin").string(), path("output.txt").string(), config, error));
    EXPECT_FALSE(error.empty());
}

TEST_F(PgoEngineTest, ObfuscateOverwritesExistingOutputFile) {
    writeFile(path("input.txt"), "new content");
    writeFile(path("encrypted.bin"), "stale leftover content");

    auto config = makeFastConfig("password");
    std::string error;
    ASSERT_TRUE(pgo::obfuscateFile(path("input.txt").string(), path("encrypted.bin").string(), config, error)) << error;
    ASSERT_TRUE(pgo::reverseFile(path("encrypted.bin").string(), path("output.txt").string(), config, error)) << error;

    EXPECT_EQ(readFile(path("output.txt")), "new content");
}
