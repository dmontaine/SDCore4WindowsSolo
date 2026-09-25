/* WIN32TOKEN.C
 * Never serve a remote session on an administrator token.
 * Copyright (c) 2026 Ladybridge Systems, All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * START-HISTORY:
 * 25 Sep 26 SD Core Solo - written, SOLO 3, owner's ruling 16.
 * END-HISTORY
 *
 * START-DESCRIPTION:
 *
 * win32_drop_admin() re-launches this process on a STANDARD token when the
 * one it holds is an administrator's, waits for it, and hands back its exit
 * code; the caller then exits with it.
 *
 * WHY.  MEASURED 25 Sep 2026 (gplbld/probe-solo-token.ps1, owner's run): a
 * scheduled task running as the user with nobody signed in (S4U) holds the
 * FULL administrator token - High integrity, BUILTIN\Administrators enabled,
 * SeDebugPrivilege - whatever -RunLevel says.  Solo's daemon starts that way
 * (SOLO 3), and sshd builds the same full token for an administrator's ssh
 * session (measured 5 Sep 2026).  Owner's ruling 16: SD never serves a remote
 * session on it; it drops to what an ordinary unelevated window has.
 *
 * WHAT "STANDARD" IS, and each part is needed:
 *   - CreateRestrictedToken(DISABLE_MAX_PRIVILEGE) removes every privilege
 *     but SeChangeNotify - SeDebug, SeBackup, SeTakeOwnership and the rest;
 *   - BUILTIN\Administrators becomes DENY-ONLY, as UAC's filtered token has it,
 *     so it can refuse access but never grant it;
 *   - the integrity level drops to Medium (S-1-16-8192), so the process
 *     cannot write to anything labelled High.
 * A restricted version of the caller's OWN primary token can be given to
 * CreateProcessAsUser without SeAssignPrimaryTokenPrivilege, and lowering the
 * integrity of a token you hold needs no privilege, which is why this works
 * from the S4U task and from an ssh session alike.
 *
 * WHEN.  Only when the token is at High integrity or above.  The caller
 * decides WHICH processes ask (sd.c: -START, -RESTART, and a session with
 * SSH_CONNECTION set); a local elevated console is left alone.
 *
 * NO LOOP.  The child gets SD_TOKEN_FILTERED=1 in its environment and at
 * Medium integrity would not ask again anyway; if it were somehow still High
 * with the marker set, this REFUSES (returns -1) rather than re-launching for
 * ever or running on the admin token.
 *
 * THE CHILD SHARES THE CONSOLE AND THE STANDARD HANDLES, so to the terminal,
 * sshd or the task it is the same program.  The parent ignores Ctrl-C AFTER
 * the child starts (the setting is inherited, so not before), so a break
 * reaches SD in the child instead of killing the parent and orphaning it.
 *
 * THIS FILE INCLUDES windows.h AND NO SD HEADER, for the reason win32sem.c
 * records: the two do not compile together.
 *
 * END-DESCRIPTION
 *
 * START-CODE
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "win32token.h"

#define FILTER_MARKER "SD_TOKEN_FILTERED"

static void why_set(char* why, size_t whylen, const char* what) {
  if (why != NULL && whylen > 0)
    snprintf(why, whylen, "%s failed, Windows error %lu", what,
             (unsigned long)GetLastError());
}

/* Integrity RID of a token, or -1 if it cannot be read. */
static long token_integrity(HANDLE tok) {
  BYTE buf[128];
  DWORD len = 0;
  TOKEN_MANDATORY_LABEL* tml = (TOKEN_MANDATORY_LABEL*)buf;
  PUCHAR count;

  if (!GetTokenInformation(tok, TokenIntegrityLevel, buf, sizeof(buf), &len))
    return -1;
  count = GetSidSubAuthorityCount(tml->Label.Sid);
  return (long)*GetSidSubAuthority(tml->Label.Sid, (DWORD)(*count - 1));
}

int win32_drop_admin(int* exit_code, char* why, size_t whylen) {
  HANDLE tok = NULL;
  HANDLE rtok = NULL;
  PSID admins = NULL;
  PSID medium = NULL;
  SID_AND_ATTRIBUTES deny;
  SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
  TOKEN_MANDATORY_LABEL tml;
  STARTUPINFOA si;
  PROCESS_INFORMATION pi;
  DWORD code = 1;
  long level;
  int result = -1;
  char* cmdline = NULL;
  HANDLE std[3];
  int i;

  if (why != NULL && whylen > 0)
    why[0] = '\0';

  if (!OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &tok)) {
    why_set(why, whylen, "OpenProcessToken");
    return -1;
  }

  level = token_integrity(tok);
  if (level < 0) {
    why_set(why, whylen, "GetTokenInformation(TokenIntegrityLevel)");
    goto done;
  }
  if (level < SECURITY_MANDATORY_HIGH_RID) {
    result = 0; /* Already standard - nothing to do */
    goto done;
  }
  if (getenv(FILTER_MARKER) != NULL) {
    if (why != NULL && whylen > 0)
      snprintf(why, whylen, "still at integrity 0x%lx after filtering", level);
    goto done; /* Refuse: never loop, never run on the admin token */
  }

  if (!AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                &admins)) {
    why_set(why, whylen, "AllocateAndInitializeSid(Administrators)");
    goto done;
  }
  deny.Sid = admins;
  deny.Attributes = 0;

  if (!CreateRestrictedToken(tok, DISABLE_MAX_PRIVILEGE, 1, &deny, 0, NULL, 0,
                             NULL, &rtok)) {
    why_set(why, whylen, "CreateRestrictedToken");
    goto done;
  }

  if (!ConvertStringSidToSidA("S-1-16-8192", &medium)) {
    why_set(why, whylen, "ConvertStringSidToSid(Medium)");
    goto done;
  }
  tml.Label.Sid = medium;
  tml.Label.Attributes = SE_GROUP_INTEGRITY;
  if (!SetTokenInformation(rtok, TokenIntegrityLevel, &tml,
                           sizeof(tml) + GetLengthSid(medium))) {
    why_set(why, whylen, "SetTokenInformation(TokenIntegrityLevel)");
    goto done;
  }

  if (!SetEnvironmentVariableA(FILTER_MARKER, "1")) {
    why_set(why, whylen, "SetEnvironmentVariable");
    goto done;
  }

  /* The same command line, on the same console and standard handles. */
  cmdline = strdup(GetCommandLineA());
  if (cmdline == NULL) {
    if (why != NULL && whylen > 0)
      snprintf(why, whylen, "out of memory copying the command line");
    goto done;
  }
  std[0] = GetStdHandle(STD_INPUT_HANDLE);
  std[1] = GetStdHandle(STD_OUTPUT_HANDLE);
  std[2] = GetStdHandle(STD_ERROR_HANDLE);
  for (i = 0; i < 3; i++) {
    if (std[i] != NULL && std[i] != INVALID_HANDLE_VALUE)
      SetHandleInformation(std[i], HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
  }
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = std[0];
  si.hStdOutput = std[1];
  si.hStdError = std[2];

  if (!CreateProcessAsUserA(rtok, NULL, cmdline, NULL, NULL, TRUE, 0, NULL,
                            NULL, &si, &pi)) {
    why_set(why, whylen, "CreateProcessAsUser");
    goto done;
  }

  /* After the child exists, so the child does not inherit it. */
  SetConsoleCtrlHandler(NULL, TRUE);

  WaitForSingleObject(pi.hProcess, INFINITE);
  if (!GetExitCodeProcess(pi.hProcess, &code))
    code = 1;
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  if (exit_code != NULL)
    *exit_code = (int)code;
  result = 1;

done:
  if (cmdline != NULL)
    free(cmdline);
  if (medium != NULL)
    LocalFree(medium);
  if (admins != NULL)
    FreeSid(admins);
  if (rtok != NULL)
    CloseHandle(rtok);
  if (tok != NULL)
    CloseHandle(tok);
  return result;
}

/* END-CODE */
