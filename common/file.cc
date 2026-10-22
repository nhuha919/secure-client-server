#include <sys/stat.h>

#include "contextmanager.h"
#include "err.h"
#include "file.h"

using namespace std;

/// Determine if a file exists.
///
/// @param filename The name of the file whose existence is being checked
///
/// @return true if the file exists, false otherwise
bool file_exists(const string &filename) {
  struct stat stat_buf;
  return (stat(filename.c_str(), &stat_buf) == 0);
}

/// Load a file and return its contents
///
/// @param filename The name of the file to open
///
/// @return A vector with the file contents.  On error, returns an empty
///         vector
vector<uint8_t> load_entire_file(const string &filename) {
  // Make sure the file exists, then open it.  stat() also gives us its size.
  struct stat stat_buf;
  if (stat(filename.c_str(), &stat_buf) != 0)
    return err<vector<uint8_t>>({}, "File ", filename.c_str(), " not found");
  FILE *f = fopen(filename.c_str(), "rb");
  if (!f)
    return err<vector<uint8_t>>({}, "File ", filename.c_str(), " not found");
  ContextManager closer([&]() { fclose(f); });

  // Reserve space based on the earlier stat().
  vector<uint8_t> res(stat_buf.st_size);

  // Reading one extra byte should mean we get an EOF and only `size` bytes.
  // Since this is a regular file, we don't need to worry about short counts
  // or EINTR.
  unsigned recd = fread(res.data(), sizeof(char), stat_buf.st_size + 1, f);
  if (recd != res.size() || !feof(f))
    return err<vector<uint8_t>>({}, "Incorrect number of bytes read from ",
                                filename.c_str());
  return res;
}

/// Create or truncate a file and populate it with the provided data
///
/// @param filename The name of the file to create/truncate
/// @param data     The data to write
/// @param skip     The number of bytes from the front of `data` that should be
///                 skipped
///
/// @return false on error, true if the file was written in full
bool write_file(const string &filename, const vector<uint8_t> &data,
                size_t skip) {
  FILE *f = fopen(filename.c_str(), "wb");
  if (f == nullptr)
    return err(false, "Unable to open '", filename.c_str(), "' for writing");
  ContextManager closer([&]() { fclose(f); });

  // Since this is a regular file, we don't need to worry about short counts
  // or EINTR.
  if (fwrite(data.data() + skip, sizeof(char), data.size() - skip, f) !=
      data.size() - skip)
    return err(false, "Incorrect number of bytes written to ",
               filename.c_str());
  return true;
}
