#include "integrity.hpp"
#include "paths.hpp"
#include "util.hpp"
#include <sstream>

namespace loguard::integrity {

bool save_manifest() {
    std::ostringstream out;
    out << "loguard=" << util::sha256_file(paths::kMainBinary) << "\n";
    out << "loguard-notify=" << util::sha256_file(paths::kHookBinary) << "\n";
    return util::write_file_atomic(paths::kIntegrityFile, out.str(), 0600);
}

std::vector<std::string> verify() {
    std::vector<std::string> problems;
    auto lines = util::read_lines(paths::kIntegrityFile);
    if (lines.empty()) {
        problems.push_back("integrity manifest missing -- run `loguard enable` again");
        return problems;
    }
    for (auto& line : lines) {
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string name = line.substr(0, eq);
        std::string expected = line.substr(eq + 1);
        std::string path = (name == "loguard") ? paths::kMainBinary : paths::kHookBinary;
        std::string actual = util::sha256_file(path);
        if (actual.empty()) {
            problems.push_back(name + ": binary missing at " + path);
        } else if (actual != expected) {
            problems.push_back(name + ": hash mismatch (binary was replaced/modified)");
        }
    }
    return problems;
}

} // namespace loguard::integrity