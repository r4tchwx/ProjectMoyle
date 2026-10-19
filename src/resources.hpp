#pragma once
#include <filesystem>
#include <vector>
#include <cstdint>

namespace moyle {
// File bytes only. Future format decoders (including BZZ) belong above this layer.
class Resources {
public:
    explicit Resources(std::filesystem::path root);
    std::vector<std::uint8_t> load(const std::filesystem::path& relative) const;
private:
    std::filesystem::path root_;
};
}
