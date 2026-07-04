#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "CommandLine.h"
#include "PgoEngine.h"

extern "C" {
#include <sodium.h>
}

#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

/**
 * @file main.cpp
 * @brief Command-line entry point for PgoCli, a front end for pgo::obfuscateFile /
 *        pgo::reverseFile (see PgoEngine.h).
 *
 * Supports two argument syntaxes for every option ("-key value" and "-key=value"),
 * expanding arguments from a file via -argfile (see CommandLine.h). The password itself
 * is never accepted as a literal CLI argument (that would leak it into shell history and
 * to anyone running `ps`); it is instead either sliced out of a file (-passwordfile[/
 * -passwordoffset/-passwordlength]) or entered interactively with echo disabled (see
 * promptForPassword). Password strings are scrubbed from memory (see ScopedZeroString)
 * once no longer needed.
 */

using pgocli::CommandLineOptions;
using pgocli::expandArgs;
using pgocli::extractPasswordFromFile;
using pgocli::parseCommandLine;
using pgocli::printUsage;

namespace {

/**
 * @brief RAII guard that zeroes a std::string's contents when it goes out of scope.
 *
 * Used to scrub password material from memory as soon as it is no longer needed,
 * including on exception-unwind paths, rather than leaving it to linger in freed heap
 * memory until overwritten by something else.
 */
class ScopedZeroString {
public:
    explicit ScopedZeroString(std::string& value) : value_(value) {}
    ~ScopedZeroString() {
        if (!value_.empty()) {
            sodium_memzero(&value_[0], value_.size());
        }
    }

    ScopedZeroString(const ScopedZeroString&) = delete;
    ScopedZeroString& operator=(const ScopedZeroString&) = delete;

private:
    std::string& value_;
};

/**
 * @brief RAII guard that disables terminal echo for its lifetime and restores the
 *        original mode on destruction (including on exception-unwind paths), so a
 *        password typed at promptForPassword's prompt is not displayed on screen.
 */
#ifdef _WIN32
class ScopedEchoDisabled {
public:
    ScopedEchoDisabled() : handle_(GetStdHandle(STD_INPUT_HANDLE)) {
        GetConsoleMode(handle_, &originalMode_);
        SetConsoleMode(handle_, originalMode_ & ~ENABLE_ECHO_INPUT);
    }
    ~ScopedEchoDisabled() {
        SetConsoleMode(handle_, originalMode_);
    }

    ScopedEchoDisabled(const ScopedEchoDisabled&) = delete;
    ScopedEchoDisabled& operator=(const ScopedEchoDisabled&) = delete;

private:
    HANDLE handle_;
    DWORD originalMode_ = 0;
};
#else
class ScopedEchoDisabled {
public:
    ScopedEchoDisabled() {
        tcgetattr(STDIN_FILENO, &original_);
        termios noEcho = original_;
        noEcho.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &noEcho);
    }

    ~ScopedEchoDisabled() {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_);
    }

    ScopedEchoDisabled(const ScopedEchoDisabled&) = delete;
    ScopedEchoDisabled& operator=(const ScopedEchoDisabled&) = delete;

private:
    termios original_{};
};
#endif

/**
 * @brief Prompts on stdout and reads a password from stdin without echoing it.
 *
 * If stdin is not an interactive terminal (e.g. piped input in a test/automation
 * context), the echo-disabling is simply a no-op and the line is read normally.
 *
 * @param prompt Text to display before reading input (e.g. "Password: ").
 * @return The line entered by the user, not including the trailing newline.
 */
std::string promptForPassword(const std::string& prompt) {
    std::cout << prompt;
    std::cout.flush();

    std::string password;
    {
        ScopedEchoDisabled noEcho;
        std::getline(std::cin, password);
    }

    std::cout << std::endl;

    return password;
}

} // namespace

/**
 * @brief Program entry point: parses arguments and runs pgo::obfuscateFile/reverseFile.
 *
 * Validation order: required options present -> password obtained (extracted from
 * -passwordfile, or entered interactively if that was not given) -> mode is a
 * recognized value -> input/output paths differ. Any failure along the way throws
 * std::invalid_argument, which is caught below to print usage and the specific error,
 * then exit with status 1.
 *
 * Argon2id cost parameters (EngineConfig::tCost/mCost) are lower in debug builds so
 * that manual testing and debugging isn't slowed down by the full production cost.
 *
 * @param argc Argument count.
 * @param argv Argument vector; argv[0] is the program path.
 * @return 0 on success, 1 if an error occurred.
 */
int main(int argc, char* argv[]) {

    int nRet = 0;

    try
    {
        const std::vector<std::string> args = expandArgs(argc, argv);
        CommandLineOptions options = parseCommandLine(args, argv[0]);
        ScopedZeroString zeroOptionsPassword(options.password);

        if (options.inputPath.empty() || options.outputPath.empty() || options.mode.empty()) {
            throw std::invalid_argument("Input, output, and mode are required.");
        }

        if (options.passwordFilePath.empty()) {
            options.password = promptForPassword("Password: ");

            if (options.password.empty()) {
                throw std::invalid_argument("Password must not be empty.");
            }
        } else {
            std::string extractError;
            options.password = extractPasswordFromFile(options.passwordFilePath,
                                                         options.passwordOffset,
                                                         options.passwordLength,
                                                         options.passwordLengthSpecified,
                                                         extractError);
            if (!extractError.empty()) {
                throw std::invalid_argument(extractError);
            }

            if (options.password.empty()) {
                throw std::invalid_argument("Extracted password from -passwordfile is empty.");
            }
        }

        std::string mode = options.mode;

        std::transform(mode.begin(), mode.end(), mode.begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });

        if (mode != "obfuscate" && mode != "reverse") {
            throw std::invalid_argument("Mode must be either 'obfuscate' or 'reverse'.\n");
        }

        if (options.inputPath == options.outputPath) {
            throw std::invalid_argument("Input and output paths must be different.");
        }

        pgo::EngineConfig config;
        config.password = options.password;
        ScopedZeroString zeroConfigPassword(config.password);

#if defined(_DEBUG) || !defined(NDEBUG)
        config.tCost = 2;
        config.mCost = 1u << 16;
#else
        config.tCost = 4;
        config.mCost = 1u << 18;
#endif

        std::string error;

        const bool success = mode == "obfuscate"
            ? pgo::obfuscateFile(options.inputPath, options.outputPath, config, error)
            : pgo::reverseFile(options.inputPath, options.outputPath, config, error);

        if (success == false) {
            throw std::invalid_argument(error);
        }

        std::cout << "Processed using mode '" << mode << "'.\n";
        std::cout << "Input:  " << options.inputPath << "\n";
        std::cout << "Output: " << options.outputPath << "\n";

    }
    catch(const std::exception& e)
    {
        printUsage(argv[0]);
        std::cerr << e.what() << '\n';
        nRet = 1;
    }

#if defined(_DEBUG) || !defined(NDEBUG)
    std::cout << "Press Enter to exit..." << std::endl;
    std::cin.get(); // Wait for user input before closing the console window.
#endif

    return nRet;
}
