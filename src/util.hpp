#pragma once
#include <string>
#include <vector>
#include <optional>

namespace loguard::util {

// Current local time as "YYYY-MM-DD HH:MM:SS"
std::string now_str();

// Append a single line to a log file, creating parent dirs if needed.
// Best-effort: never throws.
void log_line(const std::string& path, const std::string& text);

// Read a whole text file into a vector of lines (no trailing newline kept).
// Returns empty vector if the file does not exist.
std::vector<std::string> read_lines(const std::string& path);

// Overwrite a file atomically: write to <path>.tmp then rename() over it.
// Ensures a crash mid-write never corrupts the real file.
bool write_file_atomic(const std::string& path, const std::string& content, int mode = 0600);

// Append one line to a file, taking an exclusive flock() for the duration
// so the PAM hook (fast path) and the daemon never interleave writes.
bool append_line_locked(const std::string& path, const std::string& line);

// mkdir -p equivalent.
bool make_dirs(const std::string& path, int mode = 0700);

// true if path exists and is readable.
bool file_exists(const std::string& path);

// JSON string escaping for the small hand-rolled JSONL queue format.
std::string json_escape(const std::string& s);
// Very small "extract string field" helper for our fixed JSONL schema.
// Not a general JSON parser -- deliberately, to avoid an external dependency.
std::optional<std::string> json_field(const std::string& line, const std::string& key);
std::optional<long> json_field_int(const std::string& line, const std::string& key);

// Compare two "MAJOR.MINOR.PATCH" version strings numerically.
// Returns <0 if a<b, 0 if equal, >0 if a>b. Non-numeric/missing parts count as 0.
int semver_compare(const std::string& a, const std::string& b);

// Run an external program with an argv vector (NO shell involved --
// arguments are never concatenated into a shell string, so there is no
// injection risk from bot tokens, usernames, hostnames, etc).
// Captures combined stdout into `out_stdout` (optional) and returns the
// process exit code, or -1 if it could not be started/timed out.
int run_capture(const std::vector<std::string>& argv,
                 std::string* out_stdout = nullptr,
                 int timeout_seconds = 15);

// sha256 of a file's contents, as lowercase hex. Empty string on error.
std::string sha256_file(const std::string& path);

bool is_root();
std::string hostname_str();

} // namespace loguard::util