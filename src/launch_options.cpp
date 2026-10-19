#include "launch_options.hpp"
#include <stdexcept>

namespace moyle {
LaunchOptions parseLaunchOptions(const std::vector<std::wstring>& arguments) {
    LaunchOptions options;
    for (std::size_t i = 0; i < arguments.size(); ++i) {
        const auto& arg = arguments[i];
        if (arg == L"--bzz") {
            if (options.bzzPath) throw std::invalid_argument("--bzz may only be specified once");
            if (++i == arguments.size() || arguments[i].empty() || arguments[i].rfind(L"--", 0) == 0)
                throw std::invalid_argument("--bzz requires a file path; quote paths containing spaces");
            options.bzzPath = std::filesystem::path(arguments[i]);
        } else if (arg == L"--smoke-test" && !options.smokeTest) {
            options.smokeTest = true;
        } else if (arg == L"--help" && !options.help) {
            options.help = true;
        } else {
            throw std::invalid_argument("Unknown or repeated argument; use --help");
        }
    }
    if (options.bzzPath && options.smokeTest)
        throw std::invalid_argument("--bzz inspection and --smoke-test are separate modes");
    if (options.help && arguments.size() != 1)
        throw std::invalid_argument("--help must be used on its own");
    return options;
}
}
