#pragma once
#include <string>
#include <vector>

namespace loguard::queue {

struct Event {
    long ts = 0;
    std::string user, service, from, tty;
    std::string msg;      // plain text, human readable (for `loguard queue`/`logs`)
    std::string html_msg; // HTML-formatted, ready to send to Telegram
    int attempts = 0;
};

// Appends one event as a JSONL line (flock-protected -- safe to call
// concurrently from the PAM hook and the daemon).
bool push(const std::string& queue_path, const Event& e);

// Parses every line currently in the queue file into Event structs.
// Malformed lines are skipped (never crashes the daemon).
std::vector<Event> load_all(const std::string& queue_path);

// Rewrites the queue file atomically with only the given events
// (used after a delivery pass to drop what succeeded and keep the rest).
bool rewrite(const std::string& queue_path, const std::vector<Event>& remaining);

std::string serialize(const Event& e);
Event parse_line(const std::string& line);

} // namespace loguard::queue