# SD Core Solo — the API design (SOLO 3's remainder, SOLO 6)

**Status: a PLAN for the owner's approval, 25 Sep 2026. Nothing below is built.**
Every step names what would falsify it. Rulings cited are in PROJECT_STATUS.md,
"WHAT SD CORE SOLO IS".

## 1. What happens today (multi-user), and which steps Solo cannot do

| step | who does it | Solo? |
|---|---|---|
| `sdwind` accepts on APIPORT and starts a session process ("the front") | the daemon, LocalSystem | yes — as the user now (ruling 16) |
| the front reads the TLS identity `api.pem`, refused unless only SYSTEM/Administrators can reach it (`win32tls.c`) | front | the ACL rule is wrong for Solo — the file is the user's |
| the relay `sdtlsrelay.exe` is started as the `sdrelay` account: S4U logon, all privileges removed, Low (`win32relay.c`, RELEASE_1.1 43) | front, needs **SeTcb** | **no** — the daemon is not SYSTEM |
| TLS handshake in the relay; channel binding back to the front | relay | yes |
| SCRAM 47/48 against `$cred\<user>`, plus the `sdapi` group test (`apisrvr`) | front | the user has no SD password in Solo (ruling 3) |
| `K$HANDOFF` prepare: the relay stands up a named pipe (control channel, `sd_tls.h`) | front + relay | not needed |
| `K$HANDOFF` commit: a NEW `sd` started **as the user** by S4U logon (`win32session.c`, `win32s4u.c`), on the pipe; the front exits and the relay cuts over (RELEASE_1.1 55, 57) | front, needs **SeTcb** | **no** — and not needed: the front already IS the user |

## 2. Solo's shape

**The front is already the user**, at Medium with Administrators deny-only
(ruling 16, witnessed). So, if the plan holds:

1. **No handover.** After login the front simply carries on as the session —
   the pre-55 shape. `K$HANDOFF`, `K$ASSUME.USER`, the relay's control channel
   and pipe cutover, `win32session.c`'s spawn, `win32s4u.c`, the `sdrelay`
   account and `sdsvc.exe` all retire. RELEASE_1.1 57's race (a client byte read
   before the cutover) cannot arise, because nothing cuts over.
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
   Adding restricting SIDs would close that, but may stop the relay loading
   DLLs; it is a measured follow-up, not part of the first build (decision D3).
3. **`api.pem`'s ACL check** becomes: owner is the user; only the user, SYSTEM
   and Administrators have access.
4. **`op_sh.c`'s refusal of `SH` on a socket session** (SOLO 3's note) is lifted
   once an API session is shown to run as the user — it is only the user's own
   token, like the console.

## 3. Logging in (SOLO 6)

Two parties may log in over the network, and nobody else.

**(A) The user, with the Windows password (ruling 3, option A).** A new request,
**49**: the client sends the user name and the Windows password inside the TLS
tunnel. The front calls `LogonUserW(..., LOGON32_LOGON_NETWORK, ...)` — measured
in SOLO 1: unelevated, 2 ms, refuses a wrong password with 1326 — and then
requires the token's SID to equal **its own** SID. So only the one Solo user can
log in, and always with the current Windows password. `$cred` is not involved.
Refusals are audited the way SCRAM's are. Windows' own lockout policy applies to
wrong passwords; SD adds none.

> ***THIS NEEDS SERVER AUTHENTICATION, WHICH THE CLIENTS DO NOT DO TODAY.***
> Both client libraries use `SSL_VERIFY_NONE` (`gplsrc/sdclilib/sd_tls.c:175`,
> `gplsrc/sd_tls.c:237`). That is safe for SCRAM — the password never crosses
> the wire and channel binding exposes a man in the middle — but option A sends
> the password itself. **A man in the middle who poses as the server would
> receive the Windows password in plain text**, and channel binding cannot stop
> it: the password has been sent before any mismatch could be noticed.
> **So request 49 must only be sent to a server whose key the client has
> verified: pinning the server certificate's public key (decision D1).** The
> server already has a stable self-signed identity (`api.pem`), so pinning
> needs no certificate authority.

**(B) The master server, with the global password (ruling 4b).** SCRAM 47/48,
unchanged on the wire, against `$cred\$GLOBAL` (SOLO 5 stores it there), under a
**reserved login name** (decision D2). It lands in the user's account with
`K$ADMINISTRATOR` set, as `ADMIN` does (ruling 12). Refused in standalone mode,
where no `$GLOBAL` exists (ruling 15). SCRAM needs no pinning to keep the
password secret; pinning would still stop an impostor collecting a proof to
crack offline (RELEASE_1.1 41), so it is recommended here too.

**The administrator password is not an API login.** A user logged in by (A)
unlocks the admin verbs with `ADMIN` inside the session, as locally (ruling 12).

**The local API** (`SDConnectLocal`, request 25) starts `sd` as the calling user
already; its SDSYS/elevation test is multi-user and is retargeted, not removed.

## 4. The client libraries

`SDConnect(host, port, username, password, account)` today always does SCRAM.
**Proposed:** keep it as the SCRAM login (the master server's), and add
`SDConnectWindows(host, port, username, password, account, pin)` for (A), which
refuses to send the password unless the server key matches `pin` (or, per D1, a
stored first-use pin). **No automatic fallback between the two** — a fallback
would send a Windows password to whichever server answered.

**Both libraries change**: `gplsrc/sdclilib` here, and the Linux client library
in `SDCore4Linux`. There is no mailbox for Solo, so the Linux half goes through
the owner. The 32-bit `qmclient` compatibility DLLs: in scope or not is D4.

## 5. Build order, each step with its witness

1. **Relay on a restricted own token** (`win32relay.c`): start it without S4U,
   probe that it handshakes; free guard for the token (privileges 0, Low).
2. **No handover** (`apisrvr`, `op_kernel.c`, `sd_tlssrv.c`): the session
   continues in the front. `test-tlsrelay-units.py` is adapted; a real SCRAM
   login against a staged tree is the witness.
3. **Request 49** (`apisrvr` + a small C kernel call for `LogonUserW` and the
   SID compare): witnessed with a test client — right password in, wrong
   password refused with the audit line, another Windows user refused.
4. **Pinning and `SDConnectWindows`** in `sdclilib`; witnessed against a real
   Solo install, including a refused mismatched pin.
5. **The master's SCRAM name → `$GLOBAL`**, landing with `K$ADMINISTRATOR`;
   refused in standalone mode.
6. **Retire** `sdsvc.exe`, `win32s4u.c`, `win32session.c`'s spawn, `K$HANDOFF`,
   `K$ASSUME.USER`, the control channel, the `sdrelay` account, the `sdapi`
   test — and lift `op_sh.c`'s socket refusal.
7. **Linux client library** — the same `SDConnectWindows` and pinning, through
   the owner.

Owed from SOLO 3 regardless: an API and an ssh session reaching the daemon from
**another machine with nobody signed in** (ruling 2).

## 6. Decisions for the owner

- **D1 — how the client learns the server's key.** (a) the caller must pass the
  fingerprint every time; (b) trust on first use, remembered per user, and any
  change refused; (c) both — a given fingerprint wins, otherwise first use.
  *Recommended: (c).* The installer can show the fingerprint (and write it to
  `install-summary.log`) so a first connection can be checked.
- **D2 — the master server's login name.** (a) a reserved name such as
  `$global`; (b) any name, where the password alone decides. *Recommended: (a)* —
  one name, one record, nothing to guess.
- **D3 — relay confinement.** (a) Low with no privileges now, restricting SIDs
  measured later; (b) block the build on restricting SIDs. *Recommended: (a).*
- **D4 — the 32-bit `qmclient` DLLs.** Give them `SDConnectWindows` too, or
  leave them SCRAM-only (master-server use only).

## 7. An objection raised while writing this, and its answer

*"Why not keep the S4U handover and only change the relay?"* Because S4U needs
SeTcb, which only SYSTEM holds, and ruling 16 made the daemon a standard token —
the handover cannot run in Solo at all. And it has nothing to do: its purpose
was to move the session from LocalSystem to the user, and in Solo the session
is the user from the start. *Would be wrong if* a Solo API session needed a
token different from the daemon's — none of rulings 3–16 asks for one.
