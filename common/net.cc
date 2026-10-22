#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include "contextmanager.h"
#include "err.h"
#include "net.h"

using namespace std;

/// Internal method to send a buffer of data over a socket.
///
/// @param sd    The socket on which to send
/// @param bytes A pointer to the first byte of the data to send
/// @param len   The number of bytes to send
///
/// @return True if the whole buffer was sent, false otherwise
bool reliable_send(int sd, const unsigned char *bytes, int len) {
  // Sending is not guaranteed to transmit everything at once.
  const unsigned char *next_byte = bytes;
  int remain = len;
  while (remain) {
    int sent = send(sd, next_byte, remain, 0);
    // Sending 0 bytes means the peer closed the socket, so only EINTR is
    // recoverable.
    if (sent <= 0) {
      if (errno != EINTR)
        return err(false, "Error in send(): ", msg_from_errno(errno).c_str());
    } else {
      next_byte += sent;
      remain -= sent;
    }
  }
  return true;
}

/// Send a vector of data over a socket.
///
/// @param sd  The socket on which to send
/// @param msg The message to send
///
/// @return True if the whole vector was sent, false otherwise
bool send_reliably(int sd, const vector<uint8_t> &msg) {
  return reliable_send(sd, msg.data(), msg.size());
}

/// Send a string over a socket.
///
/// @param sd  The socket on which to send
/// @param msg The message to send
///
/// @return True if the whole string was sent, false otherwise
bool send_reliably(int sd, const string &msg) {
  return reliable_send(sd, (const unsigned char *)msg.c_str(), msg.length());
}

/// Perform a reliable read when we have a guess about how many bytes we might
/// get, but it's OK if the socket EOFs before we get that many bytes.
///
/// @param sd   The socket from which to read
/// @param pos  The start of the vector where data should go.  It is assumed to
///             be pre-allocated to amnt or more.
/// @param amnt The maximum number of bytes to get
///
/// @return The actual number of bytes read, or -1 on a non-eof error
int reliable_get_to_eof_or_n(int sd, vector<uint8_t>::iterator pos, int amnt) {
  int remain = amnt;
  unsigned char *next_byte = &*pos;
  int total = 0;
  while (remain) {
    int rcd = recv(sd, next_byte, remain, 0);
    // 0 bytes means the peer closed the socket; -1 means an error.  EINTR
    // means try again, otherwise we fail.
    if (rcd <= 0) {
      if (errno != EINTR)
        return (rcd == 0)
                   ? total
                   : err(-1,
                         "Error in recv(): ", msg_from_errno(errno).c_str());
    } else {
      next_byte += rcd;
      remain -= rcd;
      total += rcd;
    }
  }
  return total;
}

/// Perform a reliable read when we are not sure how many bytes we are going to
/// receive.
///
/// @param sd The socket from which to read
///
/// @return A vector with the data that was read, or an empty vector on error
vector<uint8_t> reliable_get_to_eof(int sd) {
  // Start reading, doubling the buffer any time it fills up.
  vector<uint8_t> res(16);
  int recd = 0;
  while (true) {
    int remain = res.size() - recd;
    int justgot = recv(sd, (res.data() + recd), remain, 0);
    if (justgot == 0) {
      res.resize(recd);
      return res;
    } else if (justgot < 0) {
      if (errno != EINTR)
        return err<vector<uint8_t>>(
            {}, "Error in recv(): ", msg_from_errno(errno).c_str());
    } else {
      recd += justgot;
      if (recd == (int)res.size())
        res.resize(2 * res.size());
    }
  }
}

/// Connect to a server so that we can have bidirectional communication on the
/// socket (represented by a file descriptor) that this function returns
///
/// @param hostname The name of the server (ip or DNS) to connect to
/// @param port     The server's port that we should use
///
/// @return The socket descriptor for further communication, or -1 on error
int connect_to_server(const string &hostname, int port) {
  struct hostent *host = gethostbyname(hostname.c_str());
  if (host == nullptr)
    return err(-1, "connect_to_server():DNS error:", hstrerror(h_errno));
  sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr =
      inet_addr(inet_ntoa(*(struct in_addr *)*host->h_addr_list));
  addr.sin_port = htons(port);
  int sd = socket(AF_INET, SOCK_STREAM, 0);
  if (sd < 0)
    return err(-1,
               "Error making client socket: ", msg_from_errno(errno).c_str());
  if (connect(sd, (sockaddr *)&addr, sizeof(addr)) < 0) {
    close(sd);
    return err(-1, "Error connecting socket to address: ",
               msg_from_errno(errno).c_str());
  }
  return sd;
}

/// Create a server socket that we can use to listen for new incoming requests
///
/// @param port The port on which the program should listen for new connections
///
/// @return The new listening socket, or -1 on error
int create_server_socket(size_t port) {
  // A socket is just a kind of file descriptor.  We want IPv4 over TCP.
  int sd = socket(AF_INET, SOCK_STREAM, 0);
  if (sd < 0)
    return err(-1,
               "Error making server socket: ", msg_from_errno(errno).c_str());
  ContextManager cs([&]() { close(sd); });

  // By default, a crashed server can't reuse its socket for a few minutes.
  // This lets us reuse it immediately.
  int tmp = 1;
  if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(int)) < 0)
    return err(
        -1, "setsockopt(SO_REUSEADDR) failed: ", msg_from_errno(errno).c_str());

  sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(port);
  // Qualified as ::bind to avoid colliding with std::bind (pulled in by
  // <functional> and our `using namespace std;`).
  if (::bind(sd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    return err(-1, "Error binding socket to local address: ",
               msg_from_errno(errno).c_str());

  if (listen(sd, 1024) < 0)
    return err(-1,
               "Error listening on socket: ", msg_from_errno(errno).c_str());
  cs.disable();
  return sd;
}

/// Given a listening socket, call accept() on it to get new connections.
/// Each time a connection comes in, use the provided handler to process the
/// request.  Note that this is not multithreaded: only one client is served
/// at a time.
///
/// @param sd      The socket file descriptor on which to call accept
/// @param handler A function to call when a new connection comes in
///
/// @return true on a graceful shutdown, false on an error
bool accept_client(int sd, function<bool(int)> handler) {
  while (true) {
    cout << "Waiting for a client to connect...\n";
    sockaddr_in clientAddr = {};
    socklen_t clientAddrSize = sizeof(clientAddr);
    int connSd = accept(sd, (sockaddr *)&clientAddr, &clientAddrSize);
    if (connSd < 0) {
      close(sd);
      return err(false, "Error accepting request from client: ",
                 msg_from_errno(errno).c_str());
    }
    ContextManager cs([&]() { close(connSd); });
    char cliName[1024];
    cout << "Connected to "
         << inet_ntop(AF_INET, &clientAddr.sin_addr, cliName, sizeof(cliName))
         << endl;
    bool done = handler(connSd);
    if (done)
      return true;
  }
}
