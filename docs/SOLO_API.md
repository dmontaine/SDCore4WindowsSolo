# SD Core Solo for Windows — the API, as built

How a client reaches a Solo computer, what runs on it, and what each step is
checked by. It is the Windows counterpart of Linux Solo's note of the same name.
Where a line here and the tree disagree, the tree is right.

The client libraries are unchanged from the multiuser product's: **the wire
protocol is too.** A network login is SCRAM-SHA-256 inside TLS 1.3, requests 47
and 48, and nothing else. Request 24 (cleartext) is refused, and request 25
(`SDConnectLocal`) is refused with message 15910 (Linux Solo's 14910).

## What runs

| | |
|---|---|
| The daemon | `sd-solo.exe -start`, started at sign-in by the user's own startup task "SD Core Solo". It owns the shared-memory segment and runs as the user. Windows has neither systemd socket activation nor xinetd, so the listener and the per-connection start that Linux gets from the operating system live in the daemon (`gplsrc/sdwind.c`) |
| The listener | `open_api_listener()` in `sdwind.c`, only when sd.conf has `APIPORT` set (`remote.api local\|open`). With `APILOCAL=1` (local) it binds `127.0.0.1`; without it (open) every interface. The firewall rule `SD-Solo-API-In-TCP` (`api-firewall.ps1`) is set to match. The socket is opened only when SD starts, so a change takes effect at the next `sd-solo -stop` and `-start` |
| One connection | the daemon accepts, then starts `sd -n -q` with the accepted socket as its standard input (`sdwind.c`). `-n` is a network session, `-q` no banner. It runs as the user, and it is the session: there is no handover to another process |
| The TLS relay | `sdtlsrelay.exe`, started by `win32relay.c` with a restricted copy of the user's own token (`relay_token()`): every privilege removed, integrity Low, restricting SIDs Everyone, Users and RESTRICTED (ruling 20). It does the handshake and copies bytes; `sd` gets the plaintext end and the channel binding. With that token it can create no file and open none of the user's files (measured 25 Sep 2026 with `gplbld/probe-relayrestrict.c` against the real relay); it can still read what Windows grants to Users or Everyone |
| The identity | `api.pem` (private key and self-signed certificate) in `sd-tls` beside sd.conf (`linuxio.c` `api_tls_dir()`). `sd_tlssrv.c` refuses it unless only the user, SYSTEM and Administrators can reach it (`win32tls.c` `win32_owner_only()`) |
| Pinning | the client library (`sd_pin.c`, called by `SDConnect` after the handshake and before any login byte) records the SHA-256 of the server's certificate for `host:port` the first time it connects, in `$SD_KNOWN_SERVERS` or `%USERPROFILE%\.sdcore\known_servers`. A later connection that presents another certificate is refused before any login byte. **Trust on first use**, as Linux's. A reinstalled server has a new certificate and needs its line removed |

The port is **4249 and cannot be changed** (owner, 2 Oct 2026: no adjustable
ports). 4243 is OpenQM's and ScarletDME's, 4245 upstream SD's and 4247 the full SD
Core products', so a Solo, a full product and those databases can all run on one
computer. The door is changed with `REMOTE.API off | local | open` (after ADMIN),
which hands the change to the doors helper the installer set up; TOOL.REMOTE shows
the same door.

## The login

1. **TLS 1.3** handshake. Anything older is refused.
2. **Request 47**: the client sends `n,,n=<user>,r=<nonce>`. The server reads the
   account's own credential and, on a managed computer, `$global`, and answers with
   the salt and iteration count. **The two records share one salt** (`!CRED_SET`
   takes the account's salt for `$global`), so one challenge can be answered by
   either password.
3. **Request 48**: the client proof. The server checks it against the account
   record first and `$global` second (`apisrvr` `scram.check.proof`).
   - account proof → `via=account`, an ordinary session, audited `api login user=sduser via=account`;
   - global proof (managed only) → the administrator flag **and** `K$GLOBAL.SESSION`
     are set (`USR_GLOBAL`), audited `api login user=sduser via=global`;
   - neither → refused, audited `api refused user=… reason=…`.
4. The server's signature is sent back and the client verifies it.

**Who may log in:** the user name is always `sduser`. `vb.account` lets the session
enter only its own account; a name with no register record is refused before
anything is entered (10003, audited `account refused branch=1 no.path.in.register`),
and asking for SDSYS or another account gives the same 10003, *User not allowed in
requested account* (audited `account refused branch=4 not.own.account`). **The
administrator password is not an API login**; a session unlocks the administrator
commands with ADMIN, as at the keyboard. **Until a control-file install's first
console login, only `$global` verifies**: the account record does not exist yet.

## Request 72: the managed server's ssh key

In managed mode the server logs in as `sduser` with the global password, over the API
and over ssh, and knows only the client's address. ssh needs a real Windows user, so
after a global login the server installs its public key through request 72 (`apisrvr`
`vb.sshkey`) and learns the user name from the reply. Linux Solo answers the same
request in the same words. Request 49 asks the server for its revision, as in SD Core.

- **Who may send it:** only a session signed in with the global password
  (`K$GLOBAL.SESSION`). An account-password session, or ADMIN, gets message 12894, "Only
  the SD Core server may manage ssh keys". It is not admitted before login, and on a
  computer with no global password no session can be a global one.
- **The request:** a verb, then a field mark and an argument. `ADD` and a one-line public
  key; `REMOVE` and a `SHA256:...` fingerprint; `LIST` alone.
- **The reply:** `ADD` gives six fields: the Windows user, the host name, the key's
  fingerprint, `ADDED` or `PRESENT`, the fingerprint of Solo's own sshd's host key,
  and the port to connect to (4251); a client that reads only the first five fields is
  unaffected by the sixth. `REMOVE` gives `REMOVED` or `ABSENT` and how
  many Solo lines are left. `LIST` gives one fingerprint per field.
- **The refusals,** message 12884, "The ssh key request was refused: %1", with the reason
  "the key or fingerprint is not valid", "four Solo ssh keys are already installed",
  "ssh is not set up on this Solo", "unknown request, use ADD, REMOVE or LIST" or "the
  request could not be carried out". The audit trail keeps the helper's own, more exact
  reason.
- **What it writes:** one line in **Solo's own key file**, `<Solo folder>\ssh\
  authorized_keys` (not the user's `~\.ssh\authorized_keys`), marked
  `sdcoresolo-managed`. The work is `gplbld/solo-sshkey.ps1`, unelevated, which
  checks the argument again.
- **Audit:** every verb writes `api sshkey <verb> ... peer=<address>` with the key's
  fingerprint and never its text.

## Pinning the server's certificate

Covered in the table of "What runs" above: the client library records each server's
certificate on first use and refuses a changed one before any login byte is sent.

## What checks it

| check | what it covers |
|---|---|
| `gplbld/scram-probe.py` | the client the witnesses use: the whole exchange over TLS |
| `gplbld/test-scramprobe-units.py`, `test-tlsrelay-units.py` | the probe and the relay without an installed system (free tier) |
| `gplbld/test-pin-units.ps1`, `probe-pin.py` | the pin store's rules |
| `gplbld/test-sshkey-units.ps1` | request 72's helper, on scratch files |
| `gplbld/test-apilistener-units.ps1` | the listener's off / local / open in sd.conf |

## What is not established

- An API session from another computer with nobody signed in at this one.
- `open` behind a real network firewall.
- The relay's restricted token was measured with a launcher (25 Sep 2026); the
  token `win32relay.c` gives it was read back once on a staged tree, not on an
  installed one.
