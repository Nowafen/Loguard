#pragma once
#include <string>

namespace loguard::telegram {

// Sends `text` (HTML parse_mode) to the given chat via the Telegram Bot API.
// Implemented by spawning the system `curl` binary with an argv vector
// (never a shell string), so bot tokens / usernames / hostnames can never
// be used for shell injection, and we avoid depending on libcurl-dev
// headers being present at build time on every distro.
// Returns true on HTTP 200.
bool send_message(const std::string& bot_token,
                   const std::string& chat_id,
                   const std::string& html_text);

} // namespace loguard::telegram