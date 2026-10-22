#include <iostream>
#include <libgen.h>
#include <openssl/rsa.h>
#include <unistd.h>

#include "../common/constants.h"
#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/file.h"
#include "../common/net.h"

#include "requests.h"

using namespace std;

/// The commands the client supports, paired with a usage description
static vector<pair<string, const char *>> commands = {
    {REQ_BYE, "             Ask the server to stop"},
    {REQ_SAV, "             Ask the server to persist its data"},
    {REQ_REG, "             Register a new user"},
    {REQ_SET, " -1 [file]   Set the user's profile to the contents of a file"},
    {REQ_GET, " -1 [string] Get the profile content for the named user"},
    {REQ_ALL, " -1 [file]   Get all usernames, saved to a file"}};

/// arg_t represents the command-line arguments to the client
struct arg_t {
  string server = "";   // The server's hostname or IP
  int port = 0;         // The server's port
  string keyfile = "";  // The file for caching the server's public key
  string username = ""; // The user's name
  string userpass = ""; // The user's password
  string command = "";  // The command to execute
  string arg1 = "";     // The first argument to the command (if any)

  /// Parse the command-line arguments
  ///
  /// @throw An integer exception (1) if an invalid argument is given, or if
  ///        `-h` is passed in
  arg_t(int argc, char **argv) {
    long opt;
    while ((opt = getopt(argc, argv, "k:u:w:s:p:C:1:h")) != -1) {
      switch (opt) {
      case 'p':
        port = atoi(optarg);
        break;
      case 's':
        server = string(optarg);
        break;
      case 'k':
        keyfile = string(optarg);
        break;
      case 'u':
        username = string(optarg);
        break;
      case 'w':
        userpass = string(optarg);
        break;
      case 'C':
        command = string(optarg);
        break;
      case '1':
        arg1 = string(optarg);
        break;
      default: // on any error, print a help message.  This subsumes `-h`.
        throw 1;
        return;
      }
    }

    // Validate that -C is a known command, and that -1 is present exactly
    // when the command needs it.
    string args0[] = {REQ_BYE, REQ_SAV, REQ_REG};
    string args1[] = {REQ_SET, REQ_GET, REQ_ALL};
    for (auto a : args0) {
      if (command == a) {
        if (arg1 != "")
          throw 1;
        return;
      }
    }
    for (auto a : args1) {
      if (command == a) {
        if (arg1 == "")
          throw 1;
        return;
      }
    }
    throw 1;
  }

  /// Display a help message explaining the command-line parameters
  static void usage(char *progname) {
    cout << basename(progname) << ": secure user directory client\n\n";

    cout << " Required Configuration Parameters:\n";
    cout << "  -k [file]   The filename for caching the server's public key\n"
         << "  -u [string] The username to use for authentication\n"
         << "  -w [string] The password to use for authentication\n"
         << "  -s [string] IP address or hostname of the server\n"
         << "  -p [int]    Port to use to connect to the server\n"
         << "  -C [string] The command to execute (choose one below)\n\n";

    cout << " Admin Commands (pass via -C):\n";
    for (int i = 0; i < 2; ++i)
      cout << "  " << commands[i].first << commands[i].second << endl;
    cout << endl;

    cout << " Auth Table Commands (pass via -C, with an argument as -1)\n";
    for (int i = 2; i < 6; ++i)
      cout << "  " << commands[i].first << commands[i].second << endl;
    cout << endl;

    cout << " Other Options:\n";
    cout << "  -h          Print help (this message)\n";
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

  // Fetch the server's public key if we don't already have it cached.
  if (!file_exists(args->keyfile)) {
    int sd = connect_to_server(args->server, args->port);
    req_key(sd, args->keyfile);
    close(sd);
  }
  EVP_PKEY *pubkey = load_pub(args->keyfile.c_str());
  ContextManager pkr([&]() { EVP_PKEY_free(pubkey); });

  int sd = connect_to_server(args->server, args->port);
  ContextManager sdc([&]() { close(sd); });

  // Dispatch to the requested command.
  vector<string> cmd = {REQ_REG, REQ_BYE, REQ_SET, REQ_GET, REQ_ALL, REQ_SAV};
  decltype(req_reg) *func[] = {req_reg, req_bye, req_set,
                               req_get, req_all, req_sav};
  for (size_t i = 0; i < cmd.size(); ++i)
    if (args->command == cmd[i])
      func[i](sd, pubkey, args->username, args->userpass, args->arg1);
  delete args;
  return 0;
}
