#pragma once
#include <string>
#include <vector>

namespace loguard::pam {

// The exact line Loguard inserts into PAM service files.
std::string hook_line();

// All PAM service files Loguard is willing to touch.
const std::vector<std::string>& candidate_files();

// Adds the hook line to common-session(+noninteractive) and, for any
// service that does not already include common-session, adds it directly
// too. Writes the list of files it actually modified to the PAM manifest
// so `loguard check` can later detect if a file was tampered with.
// Returns the number of files modified.
int enable();

// Removes the hook line from every candidate file (and anything recorded
// in the manifest). Returns number of files it removed the line from.
int disable();

// Files (from the manifest) that currently DO have the hook line.
std::vector<std::string> active_files();
// Files (from the manifest) that are MISSING the hook line
// even though Loguard put it there -- i.e. tampering / manual edit.
std::vector<std::string> tampered_files();

} // namespace loguard::pam