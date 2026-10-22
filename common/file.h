#pragma once

#include <cstdint>
#include <string>
#include <vector>

/// Determine if a file exists.
///
/// NB: this is subject to a TOCTOU race if another process can modify the
///     file between the check and a subsequent open; it is fine for our use
///     case of checking for the presence of a locally-managed key or data
///     file.
///
/// @param filename The name of the file whose existence is being checked
///
/// @return true if the file exists, false otherwise
bool file_exists(const std::string &filename);

/// Load a file and return its contents
///
/// @param filename The name of the file to open
///
/// @return A vector with the file contents.  On error, returns an empty
///         vector
std::vector<uint8_t> load_entire_file(const std::string &filename);

/// Create or truncate a file and populate it with the provided data
///
/// @param filename The name of the file to create/truncate
/// @param data     The data to write
/// @param skip     The number of bytes from the front of `data` that should be
///                 skipped
///
/// @return false on error, true if the file was written in full
bool write_file(const std::string &filename, const std::vector<uint8_t> &data,
                size_t skip);
