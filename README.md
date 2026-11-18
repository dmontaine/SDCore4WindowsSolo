# SD Core Solo for Windows

A personal, single-user edition of SD Core for Windows: the SD multivalue
database for one Windows user, installed entirely under that user's home
directory (`%USERPROFILE%\SDCoreSolo`).

SD is a multivalue database in the Pr1me Information tradition, descended from
OpenQM and ScarletDME through [sdb64](https://codeberg.org/stringdatabase/sdb64).
SD Core for Linux is the version the other SD Core versions follow; SD Core Solo
has its features except those that exist to serve more than one person: there is
one account, `sduser`, and no commands to create accounts or grant access to them.

SD Core is English only: it has no support for other languages or locales.

**Version WS1.1-2.** WS1.1-1 was the first release. See `sdb_ai/sd64/sdsys/changelog` for
what has changed. Documentation:
[SDCore4WindowsSoloDocs](https://github.com/dmontaine/SDCore4WindowsSoloDocs).

## What it is for

A local, single-user database, used much as you would use SQLite. The
installer asks for a global password, which may be left blank. With one, the
computer is also a client of a master SD Core server on Linux, which holds the
central data and manages its clients and signs in with that password; without
one, nothing manages it. Whether there is a global password is fixed at install
time.

## How it differs from SD Core for Windows

| | SD Core for Windows | SD Core Solo |
|---|---|---|
| Users | many SD accounts | one account, for the installing Windows user |
| Installs to | `C:\Program Files\SD` and `C:\ProgramData\SD` | `%USERPROFILE%\SDCoreSolo` |
| Runs as | a Windows service | the user's own Windows account |
| Account and grant commands | yes | removed |
| Administrator commands | in the SDSYS account | from the user's own account, unlocked by an administrator password set at install (or, on a managed computer, the global password) |

- **Every session asks for the account password** — at the keyboard, over ssh,
  over the API, and for a one-shot `sd <command>`.
- **Remote access works while the user is signed out** — over ssh, which lands
  straight in SD, and over the client API (TLS 1.3, SCRAM login).
- **Remote sessions never run with an administrator token**, even when the
  Windows user is an administrator.
- **The tree is portable.** Copy `SDCoreSolo` to another Windows account, on the
  same computer or another, and it becomes that user's once the account password
  is given.
- **The install works offline.** A release is a folder — the installer, the
  documentation, and optionally Microsoft's OpenSSH server MSI and python.org's
  Python installer, both of which the SD Core Solo installer can install for
  you. It runs equally from a download or a USB stick.

It can be installed beside the multi-user SD Core for Windows (since 2 Oct 2026:
`sd-solo` and `sd` are separate commands, and each product has its own ports,
shared memory and firewall rules).

## Requirements

Windows 11, 64-bit.

## Building from source

This repository contains no binaries; everything is built from source.

- **C server and client library** — MSYS2 (the server against the MSYS2 POSIX
  runtime, the client library against native UCRT64). `make sd` from
  `sdb_ai/sd64`.
- **SD BASIC system programs** — compiled by the Python tooling in
  `sdb_ai/sd64/gplbld`.
- **Installer** — Inno Setup, from `sdb_ai/sd64/gplbld/sd-solo.iss`.

`sdb_ai/sd64/gplbld/cycle.ps1`, run from an ordinary (unelevated) PowerShell,
does all three and then installs the result.

## Related repositories

- [SDCore4Linux](https://github.com/dmontaine/SDCore4Linux) — the multi-user
  SD Core for Linux, whose features this edition follows.
- [SDCore4Windows](https://github.com/dmontaine/SDCore4Windows) — the
  multi-user SD Core for Windows this edition is derived from.
- [SDCore4LinuxSolo](https://github.com/dmontaine/SDCore4LinuxSolo) — the Linux
  edition of Solo.

## Licence

SD, including the API, is licensed under the GPL v3.0. The install and delete
scripts are licensed under the Blue Oak Model License 1.0.0. The header of each
source file says which applies; see `sdb_ai/LICENSE`.
