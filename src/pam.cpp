#include "pam.hpp"
#include "paths.hpp"
#include "util.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <set>

namespace loguard::pam {

std::string hook_line() {
    return std::string("session optional pam_exec.so ") + paths::kHookBinary;
}

const std::vector<std::string>& candidate_files() {
    static const std::vector<std::string> files = {
        "/etc/pam.d/common-session",
        "/etc/pam.d/common-session-noninteractive",
        "/etc/pam.d/sshd",
        "/etc/pam.d/login",
        "/etc/pam.d/su",
        "/etc/pam.d/sudo",
        "/etc/pam.d/sudo-i",
        "/etc/pam.d/lightdm",
        "/etc/pam.d/gdm-password",
        "/etc/pam.d/gdm-launch-environment",
    };
    return files;
}

namespace {

std::string read_whole(const std::string& path) {
    std::ifstream in(path);
    if (!in.good()) return "";
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

bool contains_hook(const std::string& content) {
    return content.find("loguard-notify") != std::string::npos ||
           content.find("login-alert.sh") != std::string::npos; // legacy v1 line, so upgraders get detected too
}

// Removes any line mentioning our hook (current or legacy v1 name) plus
// the comment line we add above it.
std::string strip_hook(const std::string& content) {
    std::istringstream in(content);
    std::ostringstream out;
    std::string line;
    while (std::getline(in, line)) {
        if (line.find("loguard-notify") != std::string::npos ||
            line.find("login-alert.sh") != std::string::npos ||
            line.find("# Loguard") != std::string::npos) {
            continue;
        }
        out << line << "\n";
    }
    return out.str();
}

void write_manifest(const std::vector<std::string>& files) {
    std::ostringstream out;
    for (auto& f : files) out << f << "\n";
    util::write_file_atomic(paths::kPamManifest, out.str(), 0600);
}

std::vector<std::string> read_manifest() {
    return util::read_lines(paths::kPamManifest);
}

bool file_has_include_common_session(const std::string& content) {
    return content.find("@include") != std::string::npos &&
           content.find("common-session") != std::string::npos;
}

} // namespace

int enable() {
    std::vector<std::string> modified;
    const std::string line = hook_line();

    auto patch = [&](const std::string& path) -> bool {
        if (!util::file_exists(path)) return false;
        std::string content = read_whole(path);
        content = strip_hook(content);
        if (!content.empty() && content.back() != '\n') content += "\n";
        content += "# Loguard - real-time login alert (do not edit this line manually)\n";
        content += line + "\n";
        if (!util::write_file_atomic(path, content, 0644)) return false;
        return true;
    };

    const std::string common = "/etc/pam.d/common-session";
    const std::string common_ni = "/etc/pam.d/common-session-noninteractive";

    if (patch(common)) modified.push_back(common);
    if (patch(common_ni)) modified.push_back(common_ni);

    for (auto& f : candidate_files()) {
        if (f == common || f == common_ni) continue;
        if (!util::file_exists(f)) continue;
        std::string content = read_whole(f);
        if (file_has_include_common_session(content)) continue; // already covered
        if (patch(f)) modified.push_back(f);
    }

    write_manifest(modified);
    return static_cast<int>(modified.size());
}

int disable() {
    std::set<std::string> all(candidate_files().begin(), candidate_files().end());
    for (auto& f : read_manifest()) all.insert(f);

    int removed = 0;
    for (auto& f : all) {
        if (!util::file_exists(f)) continue;
        std::string content = read_whole(f);
        if (!contains_hook(content)) continue;
        std::string stripped = strip_hook(content);
        if (util::write_file_atomic(f, stripped, 0644)) removed++;
    }
    util::write_file_atomic(paths::kPamManifest, "", 0600);
    return removed;
}

std::vector<std::string> active_files() {
    std::vector<std::string> out;
    for (auto& f : read_manifest()) {
        if (!util::file_exists(f)) continue;
        if (contains_hook(read_whole(f))) out.push_back(f);
    }
    return out;
}

std::vector<std::string> tampered_files() {
    std::vector<std::string> out;
    for (auto& f : read_manifest()) {
        if (!util::file_exists(f)) { out.push_back(f + " (deleted)"); continue; }
        if (!contains_hook(read_whole(f))) out.push_back(f);
    }
    return out;
}

} // namespace loguard::pam