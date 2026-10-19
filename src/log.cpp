#include "log.hpp"
#include <windows.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>

namespace moyle {
Log::Log(const std::filesystem::path& file) : stream_(file, std::ios::app) {
    if (!stream_) throw std::runtime_error("Cannot open ProjectMoyle.log next to the executable");
}
void Log::write(const char* level, const std::string& message) {
    SYSTEMTIME now{};
    GetLocalTime(&now);
    std::ostringstream line;
    line << std::setfill('0') << std::setw(4) << now.wYear << '-'
         << std::setw(2) << now.wMonth << '-' << std::setw(2) << now.wDay << ' '
         << std::setw(2) << now.wHour << ':' << std::setw(2) << now.wMinute << ':'
         << std::setw(2) << now.wSecond << " [" << level << "] " << message << '\n';
    stream_ << line.str() << std::flush;
    OutputDebugStringA(line.str().c_str());
}
}
