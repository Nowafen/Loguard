#include "telegram.hpp"
#include "util.hpp"
#include <vector>

namespace loguard::telegram {

bool send_message(const std::string& bot_token,
                   const std::string& chat_id,
                   const std::string& html_text) {
    if (bot_token.empty() || chat_id.empty()) return false;

    std::string url = "https://api.telegram.org/bot" + bot_token + "/sendMessage";

    std::vector<std::string> argv = {
        "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
        "--max-time", "10",
        "--data-urlencode", "chat_id=" + chat_id,
        "--data-urlencode", "text=" + html_text,
        "--data-urlencode", "parse_mode=HTML",
        url
    };

    std::string out;
    int rc = util::run_capture(argv, &out, 15);
    if (rc != 0) return false; // curl itself failed to run/exec/exit nonzero
    return out.find("200") != std::string::npos;
}

} // namespace loguard::telegram