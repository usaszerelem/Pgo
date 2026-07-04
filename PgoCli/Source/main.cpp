#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "PgoEngine.h"

namespace {

constexpr const char* kDefaultArgFileName = "CmdLine.txt";

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

void printUsage(const char* programName) {
    std::cout << "Usage: " << programName
              << " -mode=<obfuscate|reverse> -input=<path> -output=<path>"
                 " (-password=value | -passwordfile=<path> [-passwordoffset=N] [-passwordlength=N])"
                 " [-argfile[=path]] [-help]\n"
              << "  -argfile reads additional arguments from a file (default: " << kDefaultArgFileName << ")\n"
              << "  -passwordfile extracts the password as raw bytes from another file\n"
              << "  -passwordoffset byte offset into -passwordfile to start reading (default: 0)\n"
              << "  -passwordlength number of bytes to read from -passwordfile (default: rest of file)\n";
}

// Reads `length` raw bytes starting at `offset` from `path` to use as the password.
// If lengthSpecified is false, reads to the end of the file.
std::string extractPasswordFromFile(const std::string& path,
                                     uint64_t offset,
                                     uint64_t length,
                                     bool lengthSpecified,
                                     std::string& error) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        error = "Could not open password file: " + path;
        return {};
    }

    file.seekg(0, std::ios::end);
    const auto fileSize = static_cast<uint64_t>(file.tellg());

    if (offset > fileSize) {
        error = "Password offset is beyond the end of file: " + path;
        return {};
    }

    const uint64_t available = fileSize - offset;
    const uint64_t readLength = lengthSpecified ? length : available;

    if (readLength > available) {
        error = "Password file is too short for the requested offset/length: " + path;
        return {};
    }

    std::string buffer(readLength, '\0');
    file.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    file.read(&buffer[0], static_cast<std::streamsize>(readLength));

    if (static_cast<uint64_t>(file.gcount()) != readLength) {
        error = "Failed to read password bytes from file: " + path;
        return {};
    }

    return buffer;
}

// Reads whitespace-separated tokens (e.g. "-input=foo") from an arg file.
std::vector<std::string> readArgFile(const std::string& path) {
    std::vector<std::string> tokens;
    std::ifstream file(path);
    if (!file) {
        std::cerr << "Could not open argument file: " << path << "\n";
        return tokens;
    }

    std::string token;
    while (file >> token) {
        tokens.push_back(token);
    }

    return tokens;
}

// Expands "-argfile"/"-argfile=<path>" into the tokens read from that file, in place.
std::vector<std::string> expandArgs(int argc, char* argv[]) {
    std::vector<std::string> expanded;
    bool argFileRequested = false;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];

        if (arg == "-argfile" || arg.rfind("-argfile=", 0) == 0) {
            const std::string path = arg == "-argfile" ? kDefaultArgFileName : arg.substr(std::string("-argfile=").size());
            const std::vector<std::string> fileArgs = readArgFile(path);
            expanded.insert(expanded.end(), fileArgs.begin(), fileArgs.end());
            argFileRequested = true;
            continue;
        }

        expanded.push_back(arg);
    }

#if defined(_DEBUG) || !defined(NDEBUG)
    // Debug convenience: silently pick up CmdLine.txt if present and not already loaded,
    // so real command-line arguments still take precedence.
    if (!argFileRequested) {
        std::ifstream defaultFile(kDefaultArgFileName);
        
        if (defaultFile) {
            const std::vector<std::string> fileArgs = readArgFile(kDefaultArgFileName);
            expanded.insert(expanded.begin(), fileArgs.begin(), fileArgs.end());
        }
    }
#endif

    return expanded;
}

CommandLineOptions parseCommandLine(const std::vector<std::string>& args, const char* programName) {
    CommandLineOptions options;

    for (std::size_t i = 0; i < args.size(); ++i) {
        const std::string& arg = args[i];

        if (arg == "-help") {
            printUsage(programName);
            std::exit(0);
        }

        if (arg == "-input" || arg == "-output" || arg == "-mode" || arg == "-password" ||
            arg == "-passwordfile" || arg == "-passwordoffset" || arg == "-passwordlength") {
            if (i + 1 >= args.size()) {
                std::cerr << "Missing value for argument: " << arg << "\n";
                continue;
            }

            const std::string value = args[++i];
            if (arg == "-input") {
                options.inputPath = value;
            } else if (arg == "-output") {
                options.outputPath = value;
            } else if (arg == "-mode") {
                options.mode = value;
            } else if (arg == "-password") {
                options.password = value;
            } else if (arg == "-passwordfile") {
                options.passwordFilePath = value;
            } else if (arg == "-passwordoffset") {
                options.passwordOffset = std::stoull(value);
            } else if (arg == "-passwordlength") {
                options.passwordLength = std::stoull(value);
                options.passwordLengthSpecified = true;
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
        } else if (key == "input") {
            options.inputPath = value;
        } else if (key == "output") {
            options.outputPath = value;
        } else if (key == "mode") {
            options.mode = value;
        } else if (key == "passwordfile") {
            options.passwordFilePath = value;
        } else if (key == "passwordoffset") {
            options.passwordOffset = std::stoull(value);
        } else if (key == "passwordlength") {
            options.passwordLength = std::stoull(value);
            options.passwordLengthSpecified = true;
        } else {
            std::cerr << "Unknown argument: " << key << "\n";
        }
    }

    return options;
}

} // namespace

int main(int argc, char* argv[]) {

    int nRet = 0;

    try
    {
        const std::vector<std::string> args = expandArgs(argc, argv);
        CommandLineOptions options = parseCommandLine(args, argv[0]);

        if (options.inputPath.empty() || options.outputPath.empty() || options.mode.empty()) {
            throw std::invalid_argument("Input, output, and mode are required.");
        }

        const bool passwordFromLiteral = !options.password.empty();
        const bool passwordFromFile = !options.passwordFilePath.empty();

        if (passwordFromLiteral && passwordFromFile) {
            throw std::invalid_argument("Specify either -password or -passwordfile, not both.");
        }

        if (!passwordFromLiteral && !passwordFromFile) {
            throw std::invalid_argument("Either -password or -passwordfile is required.");
        }

        if (passwordFromFile) {
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

#if defined(_DEBUG) || !defined(NDEBUG)
        config.tCost = 2;
        config.mCost = 1u << 16;
        config.parallelism = 1;
#else
        config.tCost = 4;
        config.mCost = 1u << 18;
        config.parallelism = 2;
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
