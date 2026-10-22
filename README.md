# Secure Directory Service

A small client/server system in modern C++ for managing a directory of
users, each with an authenticated, encrypted profile. It's built from
scratch on top of raw POSIX sockets and OpenSSL, with no networking or crypto
frameworks: a TCP wire protocol, a hybrid RSA/AES encryption scheme, salted
password hashing, and a simple pluggable key/value storage layer.

## What it does

- **Registration & authentication** — users register with a username and
  password; passwords are never stored in the clear. Each password is
  combined with a random 16-byte salt and hashed with SHA-256 before it ever
  touches disk.
- **End-to-end encrypted transport** — every request is encrypted before it
  leaves the client, following a PGP-style hybrid scheme:
  - The client generates a fresh AES-256 key for each request.
  - The request header (command, the AES key, and field lengths) is
    encrypted with the server's RSA public key.
  - Any request payload (e.g., profile content) is encrypted with the
    request's AES key.
  - The server's response is encrypted with that same AES key, so only the
    requesting client can read it.
- **Per-user encrypted profile storage** — each user can store an arbitrary
  blob of data (a "profile") on the server, fetch their own or anyone else's,
  and list every registered username.
- **Crash-safe persistence** — the server can serialize its entire user
  table to disk and reload it on restart. Writes go to a temporary file
  first and are atomically renamed into place, so a crash mid-save can't
  corrupt existing data.

## Why it's built this way

`Storage` and `Map` are defined as interfaces (`server/storage.h`,
`server/map.h`) rather than concrete classes. The request handlers in
`server/responses.cc` only ever talk to the `Storage` interface, and
`MyStorage` (`server/my_storage.cc`) only ever talks to the `Map` interface.
That separation is what makes it straightforward to swap the storage
backend — for example, replacing the single-threaded `SequentialMap` with a
lock-striped concurrent hash map — without touching the networking,
protocol, or request-handling code at all.

## Project layout

```
common/      Shared utilities: sockets, file I/O, RSA/AES crypto, RAII helpers
client/      Command-line client: builds/sends requests, decrypts responses
server/      Server: request parsing/dispatch, storage interface + implementation
```

| File | Responsibility |
|---|---|
| `common/net.{h,cc}` | Reliable socket send/receive, connection setup |
| `common/crypto.{h,cc}` | RSA key management, RSA encrypt/decrypt, AES encrypt/decrypt |
| `common/file.{h,cc}` | Reading/writing whole files |
| `common/constants.h` | Wire-protocol command codes, response codes, size limits |
| `server/parsing.cc` | Reads a request off the socket, decrypts it, dispatches to a handler |
| `server/responses.cc` | One handler per request type; talks to `Storage`, encrypts the reply |
| `server/storage.h` / `my_storage.cc` | The `Storage` interface and its implementation (auth, persistence) |
| `server/map.h` / `sequentialmap.h` | A generic key/value map interface and a simple backing implementation |
| `client/requests.{h,cc}` | Builds and sends each request type, decrypts the response |
| `client/client.cc` | Command-line argument parsing and dispatch |

## Wire protocol

Every request other than the initial key fetch is sent as:

```
rsa( command . aes_key . len(user) . len(pass) . len(payload) . user . pass )  .  aes(payload)
```

The RSA-encrypted header is always `LEN_RKBLOCK` (256) bytes. If there's a
payload (e.g., profile content for `SETP`), it's AES-encrypted separately
and appended after the RSA block. The server decrypts the header with its
private key, recovers the per-request AES key, and uses it to decrypt the
payload and encrypt its reply.

Supported commands:

| Command | Purpose |
|---|---|
| `KEY_` | Fetch the server's RSA public key |
| `REG_` | Register a new user |
| `SETP` | Set the calling user's profile content |
| `GETP` | Get a (possibly different) user's profile content |
| `ALL_` | List every registered username |
| `SAVE` | Persist the directory to disk |
| `EXIT` | Authenticate, then shut down the server |

## Building

Requires a C++17 compiler and OpenSSL (headers + library).

```bash
make
```

This produces `bin/server` and `bin/client`. `make clean` removes build
output.

## Running it

Start the server, pointing it at a data file and an RSA keypair basename (the
keypair is generated on first run if it doesn't exist yet):

```bash
./bin/server -p 9000 -f directory.dat -k server_key
```

In another terminal, use the client to register a user and set/fetch a
profile:

```bash
./bin/client -s localhost -p 9000 -k server_key.pub -u alice -w "s3cret" -C REG_
echo "hello, world" > profile.txt
./bin/client -s localhost -p 9000 -k server_key.pub -u alice -w "s3cret" -C SETP -1 profile.txt
./bin/client -s localhost -p 9000 -k server_key.pub -u alice -w "s3cret" -C GETP -1 alice
cat alice.file.dat   # -> hello, world

./bin/client -s localhost -p 9000 -k server_key.pub -u alice -w "s3cret" -C ALL_ -1 users.txt
cat users.txt         # -> alice

./bin/client -s localhost -p 9000 -k server_key.pub -u alice -w "s3cret" -C SAVE
./bin/client -s localhost -p 9000 -k server_key.pub -u alice -w "s3cret" -C EXIT
```

Run `./bin/client -h` or `./bin/server -h` for the full list of flags.

## Possible extensions

The interface-based design leaves a natural path for growth:

- Swap `SequentialMap` for a lock-striped concurrent hash map, and run the
  server's accept loop on a thread pool, to serve many clients at once.
- Add a key/value store alongside the user directory, reusing the same `Map`
  interface and persistence format.
- Move from a per-request TCP connection to a persistent, multiplexed one.
