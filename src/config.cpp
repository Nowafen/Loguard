#include "config.hpp"
#include "util.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>

namespace loguard {

namespace {
std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

std::string strip_quotes(std::string s) {
    s = trim(s);
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
        s = s.substr(1, s.size() - 2);
    }
    return s;
}
} // namespace

Config load_config(const std::string& path) {
    Config c;
    std::ifstream in(path);
    if (!in.good()) {
        c.missing_reason = "Config file missing (" + path + ")";
        return c;
    }
    std::string line;
    while (std::getline(in, line)) {
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;
        auto eq = t.find('=');
        if (eq == std::string::npos) continue;
        std::string key = trim(t.substr(0, eq));
        std::string val = strip_quotes(t.substr(eq + 1));
        if (key == "bot_token") c.bot_token = val;
        else if (key == "chat_id") c.chat_id = val;
        else if (key == "hostname") c.hostname = val;
        else if (key == "os_info") c.os_info = val;
        else if (key == "heartbeat_minutes") { try { c.heartbeat_minutes = std::stoi(val); } catch (...) {} }
        else if (key == "self_heal_pam") c.self_heal_pam = (val == "true" || val == "1");
    }

    if (c.hostname.empty()) c.hostname = util::hostname_str();

    if (c.bot_token.empty()) { c.missing_reason = "Bot Token is missing"; return c; }
    if (c.chat_id.empty())   { c.missing_reason = "Chat ID is missing"; return c; }
    c.valid = true;
    return c;
}

bool save_config(const std::string& path, const Config& c) {
    std::ostringstream out;
    out << "# Loguard configuration -- generated/edited via `loguard edit` or the installer\n";
    out << "bot_token = \"" << c.bot_token << "\"\n";
    out << "chat_id   = \"" << c.chat_id << "\"\n";
    out << "hostname  = \"" << c.hostname << "\"\n";
    if (!c.os_info.empty())
        out << "os_info   = \"" << c.os_info << "\"\n";
    out << "heartbeat_minutes = " << c.heartbeat_minutes << "\n";
    out << "self_heal_pam = " << (c.self_heal_pam ? "true" : "false") << "\n";
    return util::write_file_atomic(path, out.str(), 0600);
}

std::string mask_token(const std::string& token) {
    if (token.empty()) return "(not set)";
    if (token.size() <= 12) return token;
    return token.substr(0, 8) + "..." + token.substr(token.size() - 4);
}

} // namespace loguard