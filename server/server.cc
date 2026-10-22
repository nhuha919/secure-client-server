#include <iostream>
#include <libgen.h>
#include <openssl/rsa.h>
#include <unistd.h>

#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/err.h"
#include "../common/file.h"
#include "../common/net.h"

#include "parsing.h"
#include "storage.h"

using namespace std;

/// arg_t represents the command-line arguments to the server
struct arg_t {
  int port;                  // The port to listen on
  string datafile;           // The file for persisting all data
  string keyfile;            // The basename for the server's RSA key files
  size_t num_buckets = 1024; // Number of buckets for the server's hash table

  /// Parse the command-line arguments
  ///
  /// @throw An integer exception (1) if an invalid argument is given, or if
  ///        `-h` is passed in
  arg_t(int argc, char **argv) {
    long opt;
    while ((opt = getopt(argc, argv, "p:f:k:hb:")) != -1) {
      switch (opt) {
      case 'p':
        port = atoi(optarg);
        break;
      case 'f':
        datafile = string(optarg);
        break;
      case 'k':
        keyfile = string(optarg);
        break;
      case 'b':
        num_buckets = atoi(optarg);
        break;
      default: // on any error, print a help message.  This subsumes `-h`.
        throw 1;
        return;
      }
    }
  }

  /// Display a help message explaining the command-line parameters
  static void usage(char *progname) {
    cout << basename(progname) << ": secure user directory server\n"
         << "  -p [int]    Port on which to listen for incoming connections\n"
         << "  -f [string] File for storing all data\n"
         << "  -k [string] Basename of the file for storing the server's RSA keys\n"
         << "  -b [int]    # of buckets for the server's hash table\n"
         << "  -h          Print help (this message)\n";
  }
};

int main(int argc, char **argv) {
  arg_t *args;
  try {
    args = new arg_t(argc, argv);
  } catch (int i) {
    arg_t::usage(argv[0]);
    return 1;
  }

  cout << "Listening on port " << args->port << " using (key/data) = ("
       << args->keyfile << ", " << args->datafile << ")\n";

  // If the key files don't exist, generate them.  Either way, load the
  // private key.
  EVP_PKEY *pri = init_RSA(args->keyfile);
  if (pri == nullptr)
    return 1;
  ContextManager r([&]() { EVP_PKEY_free(pri); });

  auto pub = load_entire_file(args->keyfile + ".pub");
  if (pub.size() == 0)
    return 1;

  // Load existing data into Storage, or start with an empty Storage object.
  Storage *storage = storage_factory(args->datafile, args->num_buckets);
  auto res = storage->load_file();
  if (!res.succeeded)
    return err(1, res.msg.c_str());
  cout << res.msg << endl;

  int sd = create_server_socket(args->port);
  ContextManager csd([&]() { close(sd); });

  accept_client(sd,
                [&](int sd) { return parse_request(sd, pri, pub, storage); });

  delete args;
  delete storage;
  cout << "Server terminated\n";
}
