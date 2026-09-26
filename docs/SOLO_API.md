# SD Core Solo — the API design (SOLO 3's remainder, SOLO 6)

**Status: a PLAN for the owner's approval, 25 Sep 2026. Nothing below is built.**
Every step names what would falsify it. Rulings cited are in PROJECT_STATUS.md,
"WHAT SD CORE SOLO IS".

***CONSTRAINT, owner, 25 Sep 2026: "the client libraries need to remain
unchanged as they are used to log into all versions of sd".*** Both the Windows
`sdclilib` and the Linux client library stay as they are, so **the wire protocol
does too**: a network login is SCRAM-SHA-256, requests 47/48, and nothing else
(`SDConnect` has had no other network path since request 24 was retired,
`gplsrc/sdclilib/sdclilib.c:1257`). The first draft's request 49, key pinning
and `SDConnectWindows` are withdrawn with it.

## 1. What happens today (multi-user), and which steps Solo cannot do

| step | who does it | Solo? |
|---|---|---|
| `sdwind` accepts on APIPORT and starts a session process ("the front") | the daemon, LocalSystem | yes — as the user now (ruling 16) |
| the front reads the TLS identity `api.pem`, refused unless only SYSTEM/Administrators can reach it (`win32tls.c`) | front | the ACL rule is wrong for Solo — the file is the user's |
| the relay `sdtlsrelay.exe` is started as the `sdrelay` account: S4U logon, all privileges removed, Low (`win32relay.c`, RELEASE_1.1 43) | front, needs **SeTcb** | **no** — the daemon is not SYSTEM |
| TLS handshake in the relay; channel binding back to the front | relay | yes |
| SCRAM 47/48 against `$cred\<user>`, plus the `sdapi` group test (`apisrvr`) | front | SCRAM yes; the group test goes |
| `K$HANDOFF` prepare: the relay stands up a named pipe (control channel, `sd_tls.h`) | front + relay | not needed |
| `K$HANDOFF` commit: a NEW `sd` started **as the user** by S4U logon (`win32session.c`, `win32s4u.c`), on the pipe; the front exits and the relay cuts over (RELEASE_1.1 55, 57) | front, needs **SeTcb** | **no** — and not needed: the front already IS the user |

## 2. Solo's shape (server side only)

**The front is already the user**, at Medium with Administrators deny-only
(ruling 16, witnessed). So, if the plan holds:

1. **No handover.** After login the front simply carries on as the session —
   the pre-55 shape. `K$HANDOFF`, `K$ASSUME.USER`, the relay's control channel
   and pipe cutover, `win32session.c`'s spawn, `win32s4u.c`, the `sdrelay`
   account and `sdsvc.exe` all retire. RELEASE_1.1 57's race (a client byte read
   before the cutover) cannot arise, because nothing cuts over. **The client
   sees no difference** — the handover was always invisible on the wire.
2. **The relay stays a separate process** (a flaw in the TLS code should not
   land in the session), started with a **restricted copy of the user's own
   token**: every privilege removed, integrity Low. Neither step needs SeTcb:
   `CreateRestrictedToken` and lowering integrity are allowed on one's own
   token. *Falsified if* the relay cannot handshake on its inherited socket at
   Low as the user — the multi-user relay did at Low as `sdrelay`, so it is
   expected to work.
   **What it gives up, stated:** Low stops writes to the user's files but not
   reads, so a TLS exploit could read what the user can — including `api.pem`.
   The multi-user relay, a different account, could read nothing of the user's.
   Restricting SIDs would close that but may stop the relay loading DLLs; a
   measured follow-up, not the first build (decision D3).
3. **`api.pem`'s ACL check** becomes: owner is the user; only the user, SYSTEM
   and Administrators have access.
4. **`op_sh.c`'s refusal of `SH` on a socket session** (SOLO 3's note) is lifted
   once an API session is shown to run as the user.

## 3. Logging in (SOLO 6) — SCRAM only

Two parties may log in over the network, and nobody else. Both use SCRAM 47/48
exactly as every SD does, so the unchanged clients work.

**(A) The user.** Ruling 3's option A — the Windows password checked by
`LogonUserW` at every login — **cannot be built with unchanged clients**: SCRAM
never lets the server see the password, and the client has no other login. So
the user's API login needs a SCRAM credential in `$cred\<user>`, and **which
password it holds is the owner's decision D5**:

- **(a) an API password of the user's own**, asked for by the installer (a page
  like the administrator password's) and changed later by a verb. Separate from
  Windows, so it never goes stale. One more password.
- **(b) the Windows password, enrolled** (ruling 3's option B, declined 24 Sep
  for staleness): the installer asks for it, checks it with `LogonUserW`
  (measured in SOLO 1), and stores its SCRAM verifier. **After a Windows
  password change the OLD Windows password keeps opening the API** until the
  user re-enrols — the opposite of what the change was for.

*Recommended: (a).* Either way the login is refused unless the name is the one
Solo user's (ruling 10), and refusals are audited as today.

**(B) The master server, with the global password (ruling 4b).** SCRAM against
`$cred\$GLOBAL` (SOLO 5 stores it there), under a **reserved login name**
(decision D2). It lands in the user's account with `K$ADMINISTRATOR` set, as
`ADMIN` does (ruling 12). Refused in standalone mode, where no `$GLOBAL` exists
(ruling 15).

**The administrator password is not an API login.** A logged-in user unlocks
the admin verbs with `ADMIN` inside the session, as locally (ruling 12).

**The clients do not verify the server's certificate** (`SSL_VERIFY_NONE`,
`gplsrc/sdclilib/sd_tls.c:175`). With SCRAM that is the accepted position
(RELEASE_1.1 41): the password never crosses the wire and channel binding
exposes a relaying man in the middle; an impostor can still collect a proof to
attack offline, so the password's strength is the defence. Unchanged here.

**The local API** (`SDConnectLocal`, request 25) starts `sd` as the calling user
already; its SDSYS/elevation test is multi-user and is retargeted, not removed.

## 4. Build order, each step with its witness

1. **Relay on a restricted own token** (`win32relay.c`): started without S4U;
   probe that it handshakes; free guard for the token (privileges 0, Low).
2. **No handover** (`apisrvr`, `op_kernel.c`, `sd_tlssrv.c`): the session
   continues in the front. `test-tlsrelay-units.py` is adapted; a real SCRAM
   login with the unchanged client against a staged tree is the witness.
3. **The user's credential** (per D5): installer page and `solo_password`-style
   step to store it; the verb to change it; login refused for any other name.
4. **The master's reserved name → `$GLOBAL`**, landing with `K$ADMINISTRATOR`;
   refused in standalone mode.
5. **Retire** `sdsvc.exe`, `win32s4u.c`, `win32session.c`'s spawn, `K$HANDOFF`,
   `K$ASSUME.USER`, the control channel, the `sdrelay` account, the `sdapi`
   test — and lift `op_sh.c`'s socket refusal.

Owed from SOLO 3 regardless: an API and an ssh session reaching the daemon from
**another machine with nobody signed in** (ruling 2).

## 5. Decisions for the owner

- **D5 — the user's API password** (above): (a) its own, or (b) the Windows
  password enrolled. *Recommended: (a).* Either way ruling 3 changes, since
  option A is not buildable with unchanged clients.
- **D2 — the master server's login name.** (a) a reserved name such as
  `$global`; (b) any name, where the password alone decides. *Recommended: (a).*
- **D3 — relay confinement.** (a) Low with no privileges now, restricting SIDs
  measured later; (b) block the build on restricting SIDs. *Recommended: (a).*
- *(D1 key pinning and D4 the 32-bit libraries were withdrawn with the client
  changes.)*

## 6. Objections raised while writing this, and their answers

*"Why not keep the S4U handover and only change the relay?"* Because S4U needs
SeTcb, which only SYSTEM holds, and ruling 16 made the daemon a standard token —
the handover cannot run in Solo at all. And it has nothing to do: its purpose
was to move the session from LocalSystem to the user, and in Solo the session
is the user from the start. *Would be wrong if* a Solo API session needed a
token different from the daemon's — none of rulings 3–16 asks for one.

*"Could the server get the Windows password some other way, without changing
the client?"* Not through SCRAM: the client sends only a proof derived from the
password, and turning that back into the password is exactly what SCRAM is
designed to prevent. The retired cleartext request 24 is gone from the client
(`sdclilib.c:1257`), so there is no path — which is why D5 exists.
