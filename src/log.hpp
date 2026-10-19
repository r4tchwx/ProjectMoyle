#pragma once
#include <filesystem>
#include <fstream>
#include <string>

namespace moyle {
class Log {
public:
    explicit Log(const std::filesystem::path& file);
    void write(const char* level, const std::string& message);
private:
    std::ofstream stream_;
};
}
