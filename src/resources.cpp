#include "resources.hpp"
#include <fstream>
#include <stdexcept>
#include <utility>

namespace moyle {
Resources::Resources(std::filesystem::path root)
    : root_(std::filesystem::weakly_canonical(std::move(root))) {}

std::vector<std::uint8_t> Resources::load(const std::filesystem::path& relative) const {
    if (relative.empty() || relative.has_root_path())
        throw std::runtime_error("Resource path must be relative");
    // Resolve links and reject traversal outside the resource directory.
    const auto file = std::filesystem::weakly_canonical(root_ / relative);
    auto r = root_.begin();
    auto f = file.begin();
    for (; r != root_.end(); ++r, ++f) {
        if (f == file.end() || *r != *f)
            throw std::runtime_error("Resource path escapes its root");
    }
    std::ifstream input(file, std::ios::binary | std::ios::ate);
    if (!input) throw std::runtime_error("Resource is missing or unreadable: " + relative.string());
    const auto size = input.tellg();
    constexpr std::streamoff maxBytes = 64 * 1024 * 1024;
    if (size < 0 || size > maxBytes)
        throw std::runtime_error("Resource exceeds the Milestone 0 limit (64 MiB)");
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
    input.seekg(0);
    if (!bytes.empty() && !input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size())))
        throw std::runtime_error("Resource read failed: " + relative.string());
    return bytes;
}
}
