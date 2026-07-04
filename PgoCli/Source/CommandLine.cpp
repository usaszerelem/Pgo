#include "CommandLine.h"

#include <fstream>
#include <iostream>

namespace pgocli {

void printUsage(const char* programName) {
    std::cout << "Usage: " << programName
              << " -mode=<obfuscate|reverse> -input=<path> -output=<path>"
                 " [-passwordfile=<path> [-passwordoffset=N] [-passwordlength=N]]"
                 " [-argfile[=path]] [-help]\n"
              << "  If -passwordfile is not given, you will be prompted to enter the password"
                 " interactively (input is not echoed).\n"
              << "  -argfile reads additional arguments from a file (default: " << kDefaultArgFileName << ")\n"
              << "  -passwordfile extracts the password as raw bytes from another file\n"
              << "  -passwordoffset byte offset into -passwordfile to start reading (default: 0)\n"
              << "  -passwordlength number of bytes to read from -passwordfile (default: rest of file)\n";
}

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

        if (arg == "-input" || arg == "-output" || arg == "-mode" ||
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

        if (key == "input") {
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

} // namespace pgocli
