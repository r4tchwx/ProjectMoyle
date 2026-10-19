#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace moyle {
struct LaunchOptions {
    bool smokeTest = false;
    bool help = false;
    std::optional<std::filesystem::path> bzzPath;
};
// arguments excludes argv[0]. Invalid/ambiguous arguments throw invalid_argument.
LaunchOptions parseLaunchOptions(const std::vector<std::wstring>& arguments);
}
