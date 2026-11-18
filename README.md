# SD Core Solo for Windows

A personal, single-user edition of SD Core for Windows: the SD multivalue
database for one Windows user, installed entirely under that user's home
directory (`%USERPROFILE%\SDCoreSolo`).

SD is a multivalue database in the Pr1me Information tradition, descended from
OpenQM and ScarletDME through [sdb64](https://codeberg.org/stringdatabase/sdb64).
SD Core for Linux is the version the other SD Core versions follow; SD Core Solo
has its features except those that exist to serve more than one person: there is
one account, `sduser`, and no commands to create accounts or grant access to them.
[SD Core Solo for Linux](https://github.com/dmontaine/SDCore4LinuxSolo) is the
Linux counterpart of this edition.

**Version WS1.1-2.** WS1.1-1 was the first release. See `sdb_ai/sd64/sdsys/changelog` for
what has changed.

SD Core is English only: it has no support for other languages or locales.

## Installing

Run the installer, `sd-solo-setup-WS2.0-0.exe`, as your own Windows user. It
installs into `%USERPROFILE%\SDCoreSolo`, sets your passwords, and asks Windows
for one administrator consent at the end, for the parts that belong to the
computer (the startup tasks that keep SD and its ssh server running while you are
signed out, and the firewall rules you chose). A release is a folder - the
installer, the documentation, and optionally Microsoft's OpenSSH server package and
python.org's Python installer, which the installer can install for you - so it
runs equally from a download or a USB stick, offline. Uninstalling (Settings >
Apps) asks whether to keep your data; a new install into that folder then offers
to reload it.

## Requirements

Windows 11, 64-bit.

It can be installed beside the multi-user SD Core for Windows (`sd-solo` and `sd`
are separate commands, and each product has its own ports, shared memory and
firewall rules).

## What it is for

- **On its own** - a local, single-user database, used much as you would use
  SQLite.
- **As a client of an SD Core server** - a local store in a distributed setup,
  where a master SD Core server holds the central data and manages its clients.
  A global password lets the master server reach the client.

There is one install for both. The installer asks for a global password and you
can leave it blank if no SD Core server manages this computer; a computer is
managed if, and only if, it has a global password. The API and ssh are always your
choice (off, this computer only, or reachable from the network), with or without a
global password; a computer that a server manages needs both open to the network.
An install file (`sd-solo-setup.conf.sample`) can answer these questions for an
install nobody sits at.

## Documentation

The installation guide and the SD BASIC and TCL references are in the separate
[SDCore4WindowsSoloDocs](https://github.com/dmontaine/SDCore4WindowsSoloDocs)
repository.

## Building from source

This repository contains no binaries; everything is built from source.

- **C server and client library** - MSYS2 (the server against the MSYS2 POSIX
  runtime, the client library against native UCRT64). `make sd` from
  `sdb_ai/sd64`.
- **SD BASIC system programs** - compiled by the Python tooling in
  `sdb_ai/sd64/gplbld`.
- **Installer** - Inno Setup, from `sdb_ai/sd64/gplbld/sd-solo.iss`.

`sdb_ai/sd64/gplbld/cycle.ps1`, run from an ordinary (unelevated) PowerShell,
does all three and then installs the result.

## Related repositories

- [SDCore4Linux](https://github.com/dmontaine/SDCore4Linux) - the multi-user
  SD Core for Linux, whose features this edition follows.
- [SDCore4Windows](https://github.com/dmontaine/SDCore4Windows) - SD Core for
  Windows, the multi-user Windows version, which this edition is derived from.
- [SDCore4LinuxSolo](https://github.com/dmontaine/SDCore4LinuxSolo) - the Linux
  edition of Solo.

## Licence

Most of SD is licensed under the GPL v3.0; the install and delete scripts are
licensed under the Blue Oak Model License 1.0.0. The header of each source file
says which applies; see `sdb_ai/LICENSE`.
