#include "queue.hpp"
#include "util.hpp"
#include <sstream>

namespace loguard::queue {

std::string serialize(const Event& e) {
    std::ostringstream o;
    o << "{"
      << "\"ts\":" << e.ts << ","
      << "\"user\":\"" << util::json_escape(e.user) << "\","
      << "\"service\":\"" << util::json_escape(e.service) << "\","
      << "\"from\":\"" << util::json_escape(e.from) << "\","
      << "\"tty\":\"" << util::json_escape(e.tty) << "\","
      << "\"msg\":\"" << util::json_escape(e.msg) << "\","
      << "\"html_msg\":\"" << util::json_escape(e.html_msg) << "\","
      << "\"attempts\":" << e.attempts
      << "}";
    return o.str();
}

Event parse_line(const std::string& line) {
    Event e;
    if (auto v = util::json_field_int(line, "ts")) e.ts = *v;
    if (auto v = util::json_field(line, "user")) e.user = *v;
    if (auto v = util::json_field(line, "service")) e.service = *v;
    if (auto v = util::json_field(line, "from")) e.from = *v;
    if (auto v = util::json_field(line, "tty")) e.tty = *v;
    if (auto v = util::json_field(line, "msg")) e.msg = *v;
    if (auto v = util::json_field(line, "html_msg")) e.html_msg = *v;
    if (auto v = util::json_field_int(line, "attempts")) e.attempts = static_cast<int>(*v);
    return e;
}

bool push(const std::string& queue_path, const Event& e) {
    return util::append_line_locked(queue_path, serialize(e));
}

std::vector<Event> load_all(const std::string& queue_path) {
    std::vector<Event> out;
    for (auto& line : util::read_lines(queue_path)) {
        if (line.find("\"ts\"") == std::string::npos) continue; // skip garbage
        out.push_back(parse_line(line));
    }
    return out;
}

bool rewrite(const std::string& queue_path, const std::vector<Event>& remaining) {
    std::ostringstream out;
    for (auto& e : remaining) out << serialize(e) << "\n";
    return util::write_file_atomic(queue_path, out.str(), 0600);
}

} // namespace loguard::queue