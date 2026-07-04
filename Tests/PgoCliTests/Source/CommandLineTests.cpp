#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "CommandLine.h"

namespace {

namespace fs = std::filesystem;

void writeFile(const fs::path& path, const std::string& contents) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
}

// Builds an argv[]-shaped view over `args` (with a synthetic argv[0]) and forwards to
// pgocli::expandArgs, since that's the only interface main() actually calls with.
std::vector<std::string> callExpandArgs(std::vector<std::string> args) {
    std::vector<std::string> withProgramName;
    withProgramName.push_back("PgoCli");
    for (auto& arg : args) {
        withProgramName.push_back(std::move(arg));
    }

    std::vector<char*> argv;
    argv.reserve(withProgramName.size());
    for (auto& arg : withProgramName) {
        argv.push_back(arg.data());
    }

    return pgocli::expandArgs(static_cast<int>(argv.size()), argv.data());
}

} // namespace

// --- parseCommandLine ---------------------------------------------------------------

TEST(ParseCommandLineTest, EqualsSyntaxParsesAllOptions) {
    const std::vector<std::string> args = {
        "-mode=obfuscate", "-input=in.txt", "-output=out.bin",
        "-passwordfile=pw.txt", "-passwordoffset=10", "-passwordlength=5"};

    const auto options = pgocli::parseCommandLine(args, "PgoCli");

    EXPECT_EQ(options.mode, "obfuscate");
    EXPECT_EQ(options.inputPath, "in.txt");
    EXPECT_EQ(options.outputPath, "out.bin");
    EXPECT_EQ(options.passwordFilePath, "pw.txt");
    EXPECT_EQ(options.passwordOffset, 10u);
    EXPECT_EQ(options.passwordLength, 5u);
    EXPECT_TRUE(options.passwordLengthSpecified);
}

TEST(ParseCommandLineTest, SpacedSyntaxParsesAllOptions) {
    const std::vector<std::string> args = {
        "-mode", "reverse", "-input", "in.txt", "-output", "out.bin"};

    const auto options = pgocli::parseCommandLine(args, "PgoCli");

    EXPECT_EQ(options.mode, "reverse");
    EXPECT_EQ(options.inputPath, "in.txt");
    EXPECT_EQ(options.outputPath, "out.bin");
}

TEST(ParseCommandLineTest, LastOccurrenceOfAnOptionWins) {
    const std::vector<std::string> args = {"-mode=obfuscate", "-mode=reverse"};

    const auto options = pgocli::parseCommandLine(args, "PgoCli");

    EXPECT_EQ(options.mode, "reverse");
}

TEST(ParseCommandLineTest, MixedSyntaxBothFormsApply) {
    const std::vector<std::string> args = {"-mode=obfuscate", "-input", "in.txt"};

    const auto options = pgocli::parseCommandLine(args, "PgoCli");

    EXPECT_EQ(options.mode, "obfuscate");
    EXPECT_EQ(options.inputPath, "in.txt");
}

TEST(ParseCommandLineTest, SpacedOptionMissingValueIsIgnoredWithoutCrashing) {
    const std::vector<std::string> args = {"-input"};

    const auto options = pgocli::parseCommandLine(args, "PgoCli");

    EXPECT_TRUE(options.inputPath.empty());
}

TEST(ParseCommandLineTest, UnknownEqualsKeyIsIgnored) {
    const std::vector<std::string> args = {"-mode=obfuscate", "-bogus=value"};

    const auto options = pgocli::parseCommandLine(args, "PgoCli");

    EXPECT_EQ(options.mode, "obfuscate");
}

TEST(ParseCommandLineTest, MalformedArgumentIsIgnored) {
    const std::vector<std::string> args = {"-mode=obfuscate", "notanoption"};

    const auto options = pgocli::parseCommandLine(args, "PgoCli");

    EXPECT_EQ(options.mode, "obfuscate");
}

TEST(ParseCommandLineTest, DefaultOptionsAreEmpty) {
    const auto options = pgocli::parseCommandLine({}, "PgoCli");

    EXPECT_TRUE(options.mode.empty());
    EXPECT_TRUE(options.inputPath.empty());
    EXPECT_TRUE(options.outputPath.empty());
    EXPECT_TRUE(options.passwordFilePath.empty());
    EXPECT_EQ(options.passwordOffset, 0u);
    EXPECT_FALSE(options.passwordLengthSpecified);
}

TEST(ParseCommandLineTest, HelpFlagPrintsUsageAndExitsWithZero) {
    const std::vector<std::string> args = {"-help"};

    EXPECT_EXIT(pgocli::parseCommandLine(args, "PgoCli"), ::testing::ExitedWithCode(0), "");
}

// --- printUsage -----------------------------------------------------------------------

TEST(PrintUsageTest, MentionsUsageAndProgramName) {
    testing::internal::CaptureStdout();
    pgocli::printUsage("PgoCli");
    const std::string output = testing::internal::GetCapturedStdout();

    EXPECT_NE(output.find("Usage: PgoCli"), std::string::npos);
}

// --- extractPasswordFromFile ------------------------------------------------------------

class ExtractPasswordFromFileTest : public ::testing::Test {
protected:
    void SetUp() override {
        const auto* testInfo = ::testing::UnitTest::GetInstance()->current_test_info();
        tempDir_ = fs::path(::testing::TempDir()) /
            (std::string("PgoCliTests_") + testInfo->test_suite_name() + "_" + testInfo->name());
        std::error_code ec;
        fs::remove_all(tempDir_, ec);
        fs::create_directories(tempDir_);

        passwordFile_ = tempDir_ / "password_source.bin";
        writeFile(passwordFile_, "0123456789ABCDEF");
    }

    void TearDown() override {
        std::error_code ec;
        fs::remove_all(tempDir_, ec);
    }

    fs::path tempDir_;
    fs::path passwordFile_;
};

TEST_F(ExtractPasswordFromFileTest, NoLengthSpecifiedReadsToEndOfFile) {
    std::string error;
    const std::string result = pgocli::extractPasswordFromFile(passwordFile_.string(), 10, 0, false, error);

    EXPECT_TRUE(error.empty());
    EXPECT_EQ(result, "ABCDEF");
}

TEST_F(ExtractPasswordFromFileTest, OffsetAndLengthExtractASlice) {
    std::string error;
    const std::string result = pgocli::extractPasswordFromFile(passwordFile_.string(), 2, 4, true, error);

    EXPECT_TRUE(error.empty());
    EXPECT_EQ(result, "2345");
}

TEST_F(ExtractPasswordFromFileTest, OffsetAtEndOfFileWithNoLengthReturnsEmptyNoError) {
    std::string error;
    const std::string result = pgocli::extractPasswordFromFile(passwordFile_.string(), 16, 0, false, error);

    EXPECT_TRUE(error.empty());
    EXPECT_TRUE(result.empty());
}

TEST_F(ExtractPasswordFromFileTest, OffsetBeyondEndOfFileReturnsError) {
    std::string error;
    const std::string result = pgocli::extractPasswordFromFile(passwordFile_.string(), 100, 0, false, error);

    EXPECT_FALSE(error.empty());
    EXPECT_TRUE(result.empty());
}

TEST_F(ExtractPasswordFromFileTest, LengthExceedingAvailableBytesReturnsError) {
    std::string error;
    const std::string result = pgocli::extractPasswordFromFile(passwordFile_.string(), 10, 100, true, error);

    EXPECT_FALSE(error.empty());
    EXPECT_TRUE(result.empty());
}

TEST_F(ExtractPasswordFromFileTest, ZeroLengthReturnsEmptyStringNoError) {
    std::string error;
    const std::string result = pgocli::extractPasswordFromFile(passwordFile_.string(), 0, 0, true, error);

    EXPECT_TRUE(error.empty());
    EXPECT_TRUE(result.empty());
}

TEST_F(ExtractPasswordFromFileTest, NonexistentFileReturnsError) {
    std::string error;
    const std::string result = pgocli::extractPasswordFromFile((tempDir_ / "missing.bin").string(), 0, 0, false, error);

    EXPECT_FALSE(error.empty());
    EXPECT_TRUE(result.empty());
}

// --- readArgFile / expandArgs ----------------------------------------------------------

class ExpandArgsTest : public ::testing::Test {
protected:
    void SetUp() override {
        originalCwd_ = fs::current_path();

        const auto* testInfo = ::testing::UnitTest::GetInstance()->current_test_info();
        tempDir_ = fs::path(::testing::TempDir()) /
            (std::string("PgoCliExpandArgsTests_") + testInfo->test_suite_name() + "_" + testInfo->name());
        std::error_code ec;
        fs::remove_all(tempDir_, ec);
        fs::create_directories(tempDir_);
        fs::current_path(tempDir_);
    }

    void TearDown() override {
        fs::current_path(originalCwd_);
        std::error_code ec;
        fs::remove_all(tempDir_, ec);
    }

    fs::path originalCwd_;
    fs::path tempDir_;
};

TEST_F(ExpandArgsTest, ReadArgFileTokenizesOnWhitespace) {
    writeFile(tempDir_ / "args.txt", "-mode=obfuscate\n-input=in.txt -output=out.bin\n");

    const auto tokens = pgocli::readArgFile((tempDir_ / "args.txt").string());

    ASSERT_EQ(tokens.size(), 3u);
    EXPECT_EQ(tokens[0], "-mode=obfuscate");
    EXPECT_EQ(tokens[1], "-input=in.txt");
    EXPECT_EQ(tokens[2], "-output=out.bin");
}

TEST_F(ExpandArgsTest, ReadArgFileReturnsEmptyForMissingFile) {
    const auto tokens = pgocli::readArgFile((tempDir_ / "missing.txt").string());

    EXPECT_TRUE(tokens.empty());
}

TEST_F(ExpandArgsTest, PassesArgumentsThroughWhenNoArgFileRequested) {
    const auto expanded = callExpandArgs({"-mode=obfuscate", "-input=in.txt"});

    ASSERT_EQ(expanded.size(), 2u);
    EXPECT_EQ(expanded[0], "-mode=obfuscate");
    EXPECT_EQ(expanded[1], "-input=in.txt");
}

TEST_F(ExpandArgsTest, ExplicitArgFileWithPathIsExpandedInPlace) {
    writeFile(tempDir_ / "custom_args.txt", "-mode=reverse -input=custom.bin");

    const auto expanded = callExpandArgs({"-output=out.bin", "-argfile=custom_args.txt"});

    ASSERT_EQ(expanded.size(), 3u);
    EXPECT_EQ(expanded[0], "-output=out.bin");
    EXPECT_EQ(expanded[1], "-mode=reverse");
    EXPECT_EQ(expanded[2], "-input=custom.bin");
}

TEST_F(ExpandArgsTest, BareArgFileFlagUsesDefaultFileName) {
    writeFile(tempDir_ / pgocli::kDefaultArgFileName, "-mode=obfuscate");

    const auto expanded = callExpandArgs({"-argfile"});

    ASSERT_EQ(expanded.size(), 1u);
    EXPECT_EQ(expanded[0], "-mode=obfuscate");
}

TEST_F(ExpandArgsTest, ExpandedArgFileTokensParseCorrectly) {
    writeFile(tempDir_ / "custom_args.txt", "-mode=obfuscate -input=in.txt -output=out.bin");

    const auto expanded = callExpandArgs({"-argfile=custom_args.txt"});
    const auto options = pgocli::parseCommandLine(expanded, "PgoCli");

    EXPECT_EQ(options.mode, "obfuscate");
    EXPECT_EQ(options.inputPath, "in.txt");
    EXPECT_EQ(options.outputPath, "out.bin");
}
