#pragma once
// Central place for every filesystem path Loguard touches.
// Keeping them in one header means packaging/install.sh and the
// C++ sources can never drift apart.

namespace loguard::paths {

inline constexpr const char* kInstallDir      = "/opt/loguard/bin";
inline constexpr const char* kMainBinary      = "/opt/loguard/bin/loguard";
inline constexpr const char* kHookBinary      = "/opt/loguard/bin/loguard-notify";
inline constexpr const char* kCliSymlink      = "/usr/local/bin/loguard";

inline constexpr const char* kConfigDir       = "/etc/loguard";
inline constexpr const char* kConfigFile      = "/etc/loguard/config.toml";
inline constexpr const char* kPamManifest     = "/etc/loguard/pam_manifest.list";
inline constexpr const char* kIntegrityFile   = "/etc/loguard/integrity.sha256";

inline constexpr const char* kStateDir        = "/var/lib/loguard";
inline constexpr const char* kQueueFile       = "/var/lib/loguard/queue.jsonl";

inline constexpr const char* kLogDir          = "/var/log/loguard";
inline constexpr const char* kAlertLog        = "/var/log/loguard/alert.log";
inline constexpr const char* kTamperLog       = "/var/log/loguard/tamper.log";

inline constexpr const char* kRunDir          = "/run/loguard";
inline constexpr const char* kPidFile         = "/run/loguard/loguard.pid";

inline constexpr const char* kVersion         = "2.0.0";
inline constexpr const char* kGithubRepo      = "OWNER/loguard"; // set by install.sh / maintainer

} // namespace loguard::paths