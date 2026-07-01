#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace pgo {

struct EngineConfig {
    std::string password;
    std::string salt;
    uint32_t tCost = 2;
    uint32_t mCost = 1u << 16;
    uint32_t parallelism = 1;
};

bool obfuscateFile(const std::string& inputPath,
                   const std::string& outputPath,
                   const EngineConfig& config,
                   std::string& error);

bool reverseFile(const std::string& inputPath,
                 const std::string& outputPath,
                 const EngineConfig& config,
                 std::string& error);

} // namespace pgo
