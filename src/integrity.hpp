#pragma once
#include <string>
#include <vector>

namespace loguard::integrity {

// Computes sha256 of the main binary + the PAM hook binary and stores
// them in paths::kIntegrityFile (0600, root-owned). Call this once,
// right after (re)installing, so later tampering can be detected.
bool save_manifest();

// Returns a list of human-readable problems, e.g.
// "loguard-notify: hash mismatch (rebuilt/replaced?)". Empty = all good.
std::vector<std::string> verify();

} // namespace loguard::integrity