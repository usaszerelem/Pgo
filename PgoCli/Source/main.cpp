#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "PgoEngine.h"

namespace {

struct CommandLineOptions {
    std::string password;
    std::string inputPath;
    std::string outputPath;
    std::string mode;
};

void printUsage(const char* programName) {
    std::cout << "Usage: " << programName
              << " -input=<path> -output=<path> -mode=<obfuscate|reverse> [-password=value] [-help]\n";
}

CommandLineOptions parseCommandLine(int argc, char* argv[]) {
    CommandLineOptions options;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-help") {
            printUsage(argv[0]);
            std::exit(0);
        }

        if (arg == "-input" || arg == "-output" || arg == "-mode" || arg == "-password") {
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
        } else {
            std::cerr << "Unknown argument: " << key << "\n";
        }
    }

    return options;
}

} // namespace

int main(int argc, char* argv[]) {
    const CommandLineOptions options = parseCommandLine(argc, argv);

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

    pgo::EngineConfig config;
    config.password = options.password.empty() ? "SuperSecretPassword123" : options.password;

#ifdef _DEBUG
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

    if (!success) {
        std::cerr << error << "\n";
        return 1;
    }

    std::cout << "Processed using mode '" << mode << "'.\n";
    std::cout << "Input:  " << options.inputPath << "\n";
    std::cout << "Output: " << options.outputPath << "\n";

    return 0;
}
