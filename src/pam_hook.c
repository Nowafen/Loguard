/* loguard-notify.c
 *
 * Invoked by pam_exec at login (session open). Its ONLY job is to build
 * one JSON line describing the login event and append it to the shared
 * queue file, then exit immediately (never block the login prompt on
 * network I/O). The actual Telegram delivery is done by the loguardd
 * daemon, which is what makes login latency independent of network
 * conditions.
 *
 * Deliberately written in plain C, self-contained, no dependency on the
 * main C++ binary: this keeps the code that runs on every single login
 * as small and auditable as possible.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>

#define CONFIG_FILE "/etc/loguard/config.toml"
#define QUEUE_FILE  "/var/lib/loguard/queue.jsonl"

static void mkdirs(const char *path) {
    char tmp[512];
    size_t len = strlen(path);
    if (len >= sizeof(tmp)) return;
    strcpy(tmp, path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0700);
            *p = '/';
        }
    }
}

static const char *getenv_or(const char *name, const char *def) {
    const char *v = getenv(name);
    return (v && *v) ? v : def;
}

/* Reads a `key = "value"` line out of the config file. Returns 1 on
 * success and writes into out (size n). Very small, deliberately not a
 * general TOML parser. */
static int read_config_value(const char *key, char *out, size_t n) {
    FILE *f = fopen(CONFIG_FILE, "r");
    if (!f) return 0;
    char line[512];
    size_t klen = strlen(key);
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, key, klen) != 0) continue;
        p += klen;
        while (*p == ' ' || *p == '\t') p++;
        if (*p != '=') continue;
        p++;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '"') p++;
        size_t i = 0;
        while (*p && *p != '"' && *p != '\n' && i < n - 1) out[i++] = *p++;
        out[i] = '\0';
        found = 1;
        break;
    }
    fclose(f);
    return found;
}

static void json_escape_into(const char *in, char *out, size_t outsz) {
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 2 < outsz; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '\\' || c == '"') { out[j++] = '\\'; out[j++] = c; }
        else if (c == '\n') { out[j++] = '\\'; out[j++] = 'n'; }
        else if (c == '\r') { /* skip */ }
        else out[j++] = c;
    }
    out[j] = '\0';
}

int main(void) {
    /* Only fire on actual session start, matching the original design. */
    const char *pam_type = getenv("PAM_TYPE");
    if (!pam_type || strcmp(pam_type, "open_session") != 0) return 0;

    if (access(CONFIG_FILE, F_OK) != 0) return 0; /* not configured yet */

    char hostname_cfg[256] = {0};
    char sys_hostname[256] = "unknown-host";
    gethostname(sys_hostname, sizeof(sys_hostname));
    if (!read_config_value("hostname", hostname_cfg, sizeof(hostname_cfg)) || !hostname_cfg[0]) {
        strncpy(hostname_cfg, sys_hostname, sizeof(hostname_cfg) - 1);
    }

    const char *user = getenv_or("PAM_USER", "unknown");
    const char *service = getenv_or("PAM_SERVICE", "unknown");
    const char *rhost = getenv("PAM_RHOST");
    const char *ssh_client = getenv("SSH_CLIENT");
    char from[256] = "local";
    if (rhost && *rhost && strcmp(rhost, "?") != 0) {
        strncpy(from, rhost, sizeof(from) - 1);
    } else if (ssh_client && *ssh_client) {
        char tmp[256]; strncpy(tmp, ssh_client, sizeof(tmp) - 1); tmp[sizeof(tmp)-1]=0;
        char *sp = strchr(tmp, ' ');
        if (sp) *sp = '\0';
        strncpy(from, tmp, sizeof(from) - 1);
    }
    const char *tty = getenv_or("PAM_TTY", "console");

    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    char timestr[32];
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", &tmv);

    char e_host[600], e_user[600], e_service[600], e_from[600], e_tty[600];
    json_escape_into(hostname_cfg, e_host, sizeof(e_host));
    json_escape_into(user, e_user, sizeof(e_user));
    json_escape_into(service, e_service, sizeof(e_service));
    json_escape_into(from, e_from, sizeof(e_from));
    json_escape_into(tty, e_tty, sizeof(e_tty));

    char plain_msg[2200], html_msg[2600], e_plain[2400], e_html[2800];
    snprintf(plain_msg, sizeof(plain_msg),
        "New Login Detected\nHost: %s\nUser: %s\nService: %s\nFrom: %s\nTTY: %s\nTime: %s",
        hostname_cfg, user, service, from, tty, timestr);
    snprintf(html_msg, sizeof(html_msg),
        "<b>New Login Detected</b>\nHost: <code>%s</code>\nUser: <code>%s</code>\n"
        "Service: <code>%s</code>\nFrom: <code>%s</code>\nTTY: <code>%s</code>\nTime: <code>%s</code>",
        e_host, e_user, e_service, e_from, e_tty, timestr);
    json_escape_into(plain_msg, e_plain, sizeof(e_plain));
    json_escape_into(html_msg, e_html, sizeof(e_html));

    char line[6200];
    int len = snprintf(line, sizeof(line),
        "{\"ts\":%ld,\"user\":\"%s\",\"service\":\"%s\",\"from\":\"%s\",\"tty\":\"%s\","
        "\"msg\":\"%s\",\"html_msg\":\"%s\",\"attempts\":0}\n",
        (long)now, e_user, e_service, e_from, e_tty, e_plain, e_html);
    if (len < 0) return 0;

    mkdirs(QUEUE_FILE);
    int fd = open(QUEUE_FILE, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return 0;
    if (flock(fd, LOCK_EX) == 0) {
        ssize_t w = write(fd, line, (size_t)len);
        (void)w;
        flock(fd, LOCK_UN);
    }
    close(fd);
    return 0; /* never fail the PAM stack, regardless of outcome */
}