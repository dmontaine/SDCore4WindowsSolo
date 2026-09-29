# SD Core Solo

A personal, single-user edition of SD Core for Windows: the SD multivalue
database for one Windows user, installed entirely under that user's home
directory (`%USERPROFILE%\SDCoreSolo`).

SD is a multivalue database in the Pr1me Information tradition, descended from
OpenQM and ScarletDME through [sdb64](https://codeberg.org/stringdatabase/sdb64).
SD Core Solo has every feature of the full SD Core for Windows except those that
exist to serve more than one person: there is one account, named after the
Windows user, and no commands to create accounts or grant access to them.

**Version WS1.1-1, in development — not yet released.** See
`sdb_ai/sd64/sdsys/changelog` for what has changed.

## What it is for

The installer offers two modes, fixed at install time:

- **Standalone** — a local, single-user database, used much as you would use
  SQLite.
- **Managed client** — a local store in a distributed setup, where a master
  SD Core server on Linux holds the central data and manages its clients. A
  global password, set by the installer, lets the master server reach the
  client.

## How it differs from SD Core for Windows

| | SD Core for Windows | SD Core Solo |
|---|---|---|
| Users | many SD accounts | one account, for the installing Windows user |
| Installs to | `C:\Program Files\SD` and `C:\ProgramData\SD` | `%USERPROFILE%\SDCoreSolo` |
| Runs as | a Windows service | the user's own Windows account |
| Account and grant commands | yes | removed |
| Administrator commands | in the SDSYS account | from the user's own account, unlocked by an administrator password set at install (or, in managed mode, the global password) |

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

SD Core Solo cannot be installed on a computer that has the multi-user
SD Core for Windows installed; the installer refuses.

## Requirements

Windows 10 or 11, 64-bit.

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

- [SDCore4Windows](https://github.com/dmontaine/SDCore4Windows) — the
  multi-user SD Core for Windows this edition is derived from.
- [SDCore4Linux](https://github.com/dmontaine/SDCore4Linux) — SD Core for Linux.

## Licence

SD, including the API, is licensed under the GPL v3.0. The install and delete
scripts are licensed under the Blue Oak Model License 1.0.0. The header of each
source file says which applies; see `sdb_ai/LICENSE`.
