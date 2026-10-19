#include "../src/resources.hpp"
#include <chrono>
#include <fstream>
#include <iostream>
#include <stdexcept>

int main() {
    namespace fs = std::filesystem;
    const auto unique = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto root = fs::temp_directory_path() / ("moyle-resource-test-" + std::to_string(unique));
    fs::create_directories(root / "resources");
    try {
        { std::ofstream file(root / "resources" / "sample.bin", std::ios::binary); file.write("A\0B", 3); }
        { std::ofstream file(root / "resources" / "empty.bin", std::ios::binary); }
        { std::ofstream file(root / "outside.txt"); file << "outside"; }
        moyle::Resources resources(root / "resources");
        if (resources.load("sample.bin") != std::vector<std::uint8_t>{65, 0, 66})
            throw std::runtime_error("Binary contents changed");
        if (!resources.load("empty.bin").empty()) throw std::runtime_error("Empty file failed");
        for (const auto& path : {fs::path("missing.bin"), fs::path("../outside.txt"), root / "outside.txt"}) {
            bool rejected = false;
            try { resources.load(path); } catch (const std::exception&) { rejected = true; }
            if (!rejected) throw std::runtime_error("Invalid resource path accepted");
        }
        fs::resize_file(root / "resources" / "empty.bin", 64 * 1024 * 1024 + 1);
        bool rejected = false;
        try { resources.load("empty.bin"); } catch (const std::exception&) { rejected = true; }
        if (!rejected) throw std::runtime_error("Oversized resource accepted");
        fs::remove_all(root); // Only this test's freshly created temporary directory.
        std::cout << "Resource tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        fs::remove_all(root);
        return 1;
    }
}
