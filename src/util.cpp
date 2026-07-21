#include "util.hpp"

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

namespace loguard::util {

std::string now_str() {
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
    localtime_r(&t, &tmv);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv);
    return std::string(buf);
}

bool make_dirs(const std::string& path, int mode) {
    std::string cur;
    for (size_t i = 0; i < path.size(); ++i) {
        cur += path[i];
        if (path[i] == '/' || i == path.size() - 1) {
            if (cur.size() > 1) {
                mkdir(cur.c_str(), mode);
            }
        }
    }
    struct stat st{};
    return stat(path.c_str(), &st) == 0;
}

bool file_exists(const std::string& path) {
    struct stat st{};
    return stat(path.c_str(), &st) == 0;
}

void log_line(const std::string& path, const std::string& text) {
    auto slash = path.find_last_of('/');
    if (slash != std::string::npos) make_dirs(path.substr(0, slash));
    FILE* f = std::fopen(path.c_str(), "a");
    if (!f) return;
    std::fprintf(f, "%s | %s\n", now_str().c_str(), text.c_str());
    std::fclose(f);
}

std::vector<std::string> read_lines(const std::string& path) {
    std::vector<std::string> out;
    std::ifstream in(path);
    if (!in.good()) return out;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty()) out.push_back(line);
    }
    return out;
}

bool write_file_atomic(const std::string& path, const std::string& content, int mode) {
    std::string tmp = path + ".tmp";
    int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) return false;
    ssize_t written = write(fd, content.data(), content.size());
    fsync(fd);
    close(fd);
    if (written < 0 || static_cast<size_t>(written) != content.size()) {
        unlink(tmp.c_str());
        return false;
    }
    if (rename(tmp.c_str(), path.c_str()) != 0) {
        unlink(tmp.c_str());
        return false;
    }
    chmod(path.c_str(), mode);
    return true;
}

bool append_line_locked(const std::string& path, const std::string& line) {
    auto slash = path.find_last_of('/');
    if (slash != std::string::npos) make_dirs(path.substr(0, slash));
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return false;
    if (flock(fd, LOCK_EX) != 0) { close(fd); return false; }
    std::string out = line;
    if (out.empty() || out.back() != '\n') out += '\n';
    ssize_t w = write(fd, out.data(), out.size());
    flock(fd, LOCK_UN);
    close(fd);
    return w == static_cast<ssize_t>(out.size());
}

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': break;
            case '\t': out += "\\t"; break;
            default:   out += c;
        }
    }
    return out;
}

std::optional<std::string> json_field(const std::string& line, const std::string& key) {
    std::string needle = "\"" + key + "\":\"";
    auto pos = line.find(needle);
    if (pos == std::string::npos) return std::nullopt;
    pos += needle.size();
    std::string val;
    bool esc = false;
    for (size_t i = pos; i < line.size(); ++i) {
        char c = line[i];
        if (esc) {
            if (c == 'n') val += '\n';
            else if (c == 't') val += '\t';
            else val += c;
            esc = false;
        } else if (c == '\\') {
            esc = true;
        } else if (c == '"') {
            break;
        } else {
            val += c;
        }
    }
    return val;
}

std::optional<long> json_field_int(const std::string& line, const std::string& key) {
    std::string needle = "\"" + key + "\":";
    auto pos = line.find(needle);
    if (pos == std::string::npos) return std::nullopt;
    pos += needle.size();
    size_t end = pos;
    while (end < line.size() && (isdigit((unsigned char)line[end]) || line[end] == '-')) end++;
    if (end == pos) return std::nullopt;
    try {
        return std::stol(line.substr(pos, end - pos));
    } catch (...) {
        return std::nullopt;
    }
}

int semver_compare(const std::string& a, const std::string& b) {
    auto parts = [](const std::string& v) {
        std::vector<int> p;
        std::stringstream ss(v);
        std::string tok;
        while (std::getline(ss, tok, '.')) {
            int n = 0;
            try { n = std::stoi(tok); } catch (...) { n = 0; }
            p.push_back(n);
        }
        while (p.size() < 3) p.push_back(0);
        return p;
    };
    auto pa = parts(a), pb = parts(b);
    for (size_t i = 0; i < 3; ++i) {
        if (pa[i] != pb[i]) return pa[i] - pb[i];
    }
    return 0;
}

bool is_root() { return geteuid() == 0; }

std::string hostname_str() {
    char buf[256];
    if (gethostname(buf, sizeof(buf)) == 0) return std::string(buf);
    return "unknown-host";
}

// ---- run_capture: fork/exec with an argv vector, no shell involved ----
int run_capture(const std::vector<std::string>& argv,
                 std::string* out_stdout,
                 int timeout_seconds) {
    if (argv.empty()) return -1;
    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return -1; }

    if (pid == 0) {
        // child
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) dup2(devnull, STDERR_FILENO);

        std::vector<char*> cargv;
        cargv.reserve(argv.size() + 1);
        for (auto& s : argv) cargv.push_back(const_cast<char*>(s.c_str()));
        cargv.push_back(nullptr);
        execvp(cargv[0], cargv.data());
        _exit(127); // exec failed
    }

    // parent
    close(pipefd[1]);
    std::string collected;
    char buf[4096];
    // simple timeout: alarm-based via non-blocking read loop
    fcntl(pipefd[0], F_SETFL, O_NONBLOCK);
    time_t start = time(nullptr);
    int status = -1;
    bool child_done = false;
    while (true) {
        ssize_t n = read(pipefd[0], buf, sizeof(buf));
        if (n > 0) {
            collected.append(buf, n);
        } else if (n == 0) {
            break; // EOF
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            break;
        }
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) { child_done = true; }
        if (time(nullptr) - start > timeout_seconds) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            child_done = true;
            break;
        }
        if (n <= 0) usleep(20000);
        if (child_done && n <= 0) break;
    }
    close(pipefd[0]);
    if (!child_done) waitpid(pid, &status, 0);

    if (out_stdout) *out_stdout = collected;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}

// ---------------- SHA-256 (public-domain style, self-contained) ----------------
namespace {
struct Sha256Ctx {
    uint32_t h[8];
    uint64_t len;
    uint8_t buf[64];
    size_t buflen;
};

constexpr uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

void sha256_transform(Sha256Ctx& ctx, const uint8_t* data) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = (uint32_t(data[i*4]) << 24) | (uint32_t(data[i*4+1]) << 16) |
               (uint32_t(data[i*4+2]) << 8) | uint32_t(data[i*4+3]);
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=ctx.h[0],b=ctx.h[1],c=ctx.h[2],d=ctx.h[3],e=ctx.h[4],f=ctx.h[5],g=ctx.h[6],h=ctx.h[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        h=g; g=f; f=e; e=d+temp1; d=c; c=b; b=a; a=temp1+temp2;
    }
    ctx.h[0]+=a; ctx.h[1]+=b; ctx.h[2]+=c; ctx.h[3]+=d;
    ctx.h[4]+=e; ctx.h[5]+=f; ctx.h[6]+=g; ctx.h[7]+=h;
}

void sha256_init(Sha256Ctx& ctx) {
    static const uint32_t init[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    memcpy(ctx.h, init, sizeof(init));
    ctx.len = 0;
    ctx.buflen = 0;
}

void sha256_update(Sha256Ctx& ctx, const uint8_t* data, size_t n) {
    ctx.len += n;
    while (n > 0) {
        size_t take = std::min(n, size_t(64) - ctx.buflen);
        memcpy(ctx.buf + ctx.buflen, data, take);
        ctx.buflen += take;
        data += take; n -= take;
        if (ctx.buflen == 64) {
            sha256_transform(ctx, ctx.buf);
            ctx.buflen = 0;
        }
    }
}

std::string sha256_final(Sha256Ctx& ctx) {
    uint64_t bitlen = ctx.len * 8;
    uint8_t pad = 0x80;
    sha256_update(ctx, &pad, 1);
    uint8_t zero = 0;
    while (ctx.buflen != 56) sha256_update(ctx, &zero, 1);
    uint8_t lenbytes[8];
    for (int i = 0; i < 8; ++i) lenbytes[i] = (bitlen >> (56 - 8*i)) & 0xff;
    // careful: update() above may have re-entered transform at buflen==56 boundary edge case
    // append length directly without going through update() to avoid recursion issues
    memcpy(ctx.buf + 56, lenbytes, 8);
    sha256_transform(ctx, ctx.buf);

    char out[65];
    for (int i = 0; i < 8; ++i)
        snprintf(out + i*8, 9, "%08x", ctx.h[i]);
    return std::string(out, 64);
}
} // namespace

std::string sha256_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in.good()) return "";
    Sha256Ctx ctx;
    sha256_init(ctx);
    char buf[8192];
    while (in.read(buf, sizeof(buf)) || in.gcount() > 0) {
        sha256_update(ctx, reinterpret_cast<uint8_t*>(buf), in.gcount());
    }
    return sha256_final(ctx);
}

} // namespace loguard::util