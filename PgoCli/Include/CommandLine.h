#pragma once

#include <cstdint>
#include <string>
#include <vector>

/**
 * @file CommandLine.h
 * @brief Argument parsing and password-file extraction for PgoCli, split out from
 *        main.cpp so it can be exercised directly by automated tests (main.cpp itself
 *        only wires this up to interactive prompting and the actual obfuscate/reverse
 *        calls, neither of which is worth unit testing).
 */

namespace pgocli {

/// Default path used by "-argfile" (with no "=path" suffix) and by the debug-only
/// auto-load behavior in expandArgs.
constexpr const char* kDefaultArgFileName = "CmdLine.txt";

/**
 * @brief Parsed command-line options, populated by parseCommandLine.
 *
 * @var CommandLineOptions::password
 *   The password to use. Populated after parsing, not by any single CLI argument: either
 *   extracted from passwordFilePath, or (if that is empty) filled in later by prompting
 *   the user interactively -- see promptForPassword in main.cpp.
 * @var CommandLineOptions::inputPath
 *   Path to the file to obfuscate/reverse.
 * @var CommandLineOptions::outputPath
 *   Path to write the result to.
 * @var CommandLineOptions::mode
 *   Either "obfuscate" or "reverse" (case-insensitive).
 * @var CommandLineOptions::passwordFilePath
 *   Path to a file to extract the password's raw bytes from, via -passwordfile.
 * @var CommandLineOptions::passwordOffset
 *   Byte offset into passwordFilePath to start reading from (see -passwordoffset).
 * @var CommandLineOptions::passwordLength
 *   Number of bytes to read from passwordFilePath (see -passwordlength). Only used if
 *   passwordLengthSpecified is true; otherwise reads to the end of the file.
 * @var CommandLineOptions::passwordLengthSpecified
 *   Whether -passwordlength was explicitly provided.
 */
struct CommandLineOptions {
    std::string password;
    std::string inputPath;
    std::string outputPath;
    std::string mode;
    std::string passwordFilePath;
    uint64_t passwordOffset = 0;
    uint64_t passwordLength = 0;
    bool passwordLengthSpecified = false;
};

/**
 * @brief Prints command-line usage help to stdout.
 * @param programName Typically argv[0], used to show the invocation syntax.
 */
void printUsage(const char* programName);

/**
 * @brief Reads whitespace-separated tokens (e.g. "-input=foo") from an arg file.
 *
 * On failure to open @p path, logs to stderr and returns an empty list rather than
 * throwing, so callers (expandArgs) can decide how to treat a missing/unreadable file.
 *
 * @param path Path to the argument file.
 * @return The whitespace-separated tokens found in the file, in order.
 */
std::vector<std::string> readArgFile(const std::string& path);

/**
 * @brief Expands "-argfile"/"-argfile=<path>" into the tokens read from that file.
 *
 * Explicit -argfile arguments are expanded in place, preserving relative ordering with
 * any other arguments on the command line. In debug builds, if no -argfile was given
 * explicitly, CmdLine.txt (if present) is silently prepended -- this is purely a
 * development convenience so a debugger launch config doesn't need real CLI args typed
 * in; real command-line arguments are inserted after it and so still take precedence
 * where they conflict (parseCommandLine keeps the last value seen for any given option).
 *
 * @param argc Argument count, as passed to main.
 * @param argv Argument vector, as passed to main.
 * @return The fully expanded argument list (excluding argv[0]).
 */
std::vector<std::string> expandArgs(int argc, char* argv[]);

/**
 * @brief Parses a flat list of argument tokens into CommandLineOptions.
 *
 * Supports two syntaxes per option: a two-token form ("-input foo") and a single-token
 * "-key=value" form. Unrecognized "-key=value" arguments and options missing their value
 * are reported to stderr and skipped rather than aborting, so a single typo doesn't
 * necessarily prevent later validation from producing its own, more specific error. Any
 * option may appear multiple times; the last occurrence wins. "-help" prints usage and
 * exits the process immediately.
 *
 * @param args        Fully expanded argument tokens (see expandArgs).
 * @param programName Typically argv[0], forwarded to printUsage for "-help".
 * @return The parsed options, with defaults for anything not supplied.
 */
CommandLineOptions parseCommandLine(const std::vector<std::string>& args, const char* programName);

/**
 * @brief Reads `length` raw bytes starting at `offset` from `path` to use as a password.
 *
 * This lets a password be sourced from arbitrary bytes of an existing file (e.g. a slice
 * of a binary asset) rather than typed on the command line, which is otherwise visible in
 * shell history and process listings.
 *
 * @param path            File to read password bytes from.
 * @param offset          Byte offset to start reading at.
 * @param length          Number of bytes to read; ignored if lengthSpecified is false.
 * @param lengthSpecified If false, reads from offset to the end of the file instead of
 *                        using length.
 * @param error           Set to a human-readable message on failure; left untouched on
 *                        success.
 * @return The extracted bytes, or an empty string if @p error was set.
 */
std::string extractPasswordFromFile(const std::string& path,
                                     uint64_t offset,
                                     uint64_t length,
                                     bool lengthSpecified,
                                     std::string& error);

} // namespace pgocli
