/* WIN32RELAY.C
 * Native Windows half of the API's TLS relay: start sdtlsrelay.exe on a
 * restricted copy of this process's own token, at Low integrity, with exactly
 * three inherited handles.
 * Copyright (c) String Database
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
 * START-HISTORY:
 * 25 Sep 26 SD Core Solo - SOLO 3, ruling 20: the relay's token is a
 *           RESTRICTED COPY OF OUR OWN, not an S4U logon of sdrelay - Solo's
 *           daemon is the user at a standard token and holds no SeTcb.  No
 *           account argument, no environment block from the token, the
 *           working directory is System32, the desktop is inherited.
 * 17 Sep 26 Windows port - RELEASE_1.1 55: a THIRD inherited descriptor, the
 *           control socketpair the front uses to have the relay stand up the
 *           authenticated session's pipe.  It is passed the same way as the
 *           other two and for the same reason (sd_tls.h's control section).
 * 16 Sep 26 Windows port - written for RELEASE_1.1 43.
 * END-HISTORY
 *
 * START-DESCRIPTION:
 *
 * This file includes windows.h and NO SD header, as win32tls.c, win32s4u.c
 * and win32sem.c do and for the same reason.  Its interface is in sd_tls.h
 * with no Windows type in it; sd_tlssrv.c calls it with Cygwin descriptors.
 *
 * THE DROP, IN ORDER (SD Core Solo, ruling 20).  The relay parses an
 * unauthenticated peer's bytes, so a flaw in the TLS code must land in a
 * process that can reach nothing.  Multi-user SD started it as a separate
 * account (S4U, which needs SeTcb); Solo's sd is the user at a standard token
 * (ruling 16) and cannot.  Instead, every step allowed on one's OWN token:
 *
 *   1. CreateRestrictedToken(own token)   DISABLE_MAX_PRIVILEGE, and
 *                                          RESTRICTING SIDs Everyone, Users,
 *                                          RESTRICTED: every access must also
 *                                          pass that list, and the user's
 *                                          files grant none of the three
 *   2. AdjustTokenPrivileges, REMOVED      every privilege, SeChangeNotify
 *                                          too - removed, not disabled
 *   3. TokenIntegrityLevel = Low           no write to anything at Medium
 *   4. TokenDefaultDacl                    SYSTEM, the user and RESTRICTED,
 *                                          so the child can open its OWN
 *                                          process and thread objects
 *   5. CreateProcessAsUser                 a restricted copy of the caller's
 *                                          own primary token needs no
 *                                          privilege to assign
 *
 * MEASURED 25 Sep 2026, gplbld/probe-relayrestrict.c (mode b-users-strip),
 * unelevated, the real sdtlsrelay.exe: child token privileges 0, Low,
 * restricting SIDs 3; test-tlsrelay-units.py's TLS rows all pass (handshake,
 * binding equal to the client's exporter, 256 KB both ways, refusals); READ
 * DENIED on the user's sd.conf, $cred\$ADMIN and .ssh; System32 readable.
 * RESTRICTED alone as the list kills the relay (0xC0000409).  ONE THING IT
 * CANNOT DO: create the multi-user handover pipe (error 5) - Solo has no
 * handover (docs/SOLO_API.md), so nothing asks it to.
 *
 * NO ENVIRONMENT BLOCK, AND System32 AS THE WORKING DIRECTORY.  The child
 * inherits sd's environment (the same user's), and a working directory in
 * the user's tree is one the child could not open.  The DESKTOP is
 * inherited: the relay loads no user32, and naming winsta0 from a session-0
 * S4U daemon asks for a window station that is not its own.
 *
 * THE HANDLE LIST IS CORRECTNESS, NOT HYGIENE.  Every socket handle Cygwin
 * creates carries HANDLE_FLAG_INHERIT (measured, gplbld/probe-relaysp.c), so
 * bInheritHandles=TRUE on its own would copy EVERY socket sd holds into the
 * relay - and a socket with a live handle in another process does not close.
 * In that probe's first run the relay had inherited the client's own end,
 * and the client's close never reached sd.  PROC_THREAD_ATTRIBUTE_HANDLE_LIST
 * names the three the relay may have, and nothing else crosses.
 *
 * WHERE THE RELAY IS: beside sd.exe, from GetModuleFileName - the native
 * answer exepath.c's header names.  exe_directory() is not used because it
 * answers a POSIX path and this is a native CreateProcess (the trap
 * sdpy_session.c paid for), and because its bool is sd.h's int16_t, which
 * this file may not include.
 *
 * END-DESCRIPTION
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <io.h>                        /* _get_osfhandle: a Cygwin fd's HANDLE */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Declared in sd_tls.h; repeated so this file includes no SD header. */
int win32_relay_spawn(int net_fd, int sp_fd, int ctl_fd, int timeout_ms,
                      void** proc, char* why, size_t whylen);
int win32_relay_exit_code(void* proc, int wait_ms);
int win32_my_sid(char* out, size_t outlen, char* why, size_t whylen);

#define RELAY_EXE_NAME "sdtlsrelay.exe"        /* SD_RELAY_EXE in sd_tls.h */

/* ====================================================================== */

static void win_error(const char* what, char* why, size_t whylen) {
  DWORD e = GetLastError();
  char* text = NULL;
  size_t n;

  FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                     FORMAT_MESSAGE_IGNORE_INSERTS,
                 NULL, e, 0, (LPSTR)&text, 0, NULL);
  snprintf(why, whylen, "%s: error %lu %s", what, (unsigned long)e,
           text ? text : "");
  if (text)
    LocalFree(text);
  for (n = 0; n < whylen && why[n]; n++)
    if (why[n] == '\r' || why[n] == '\n')
      why[n] = ' ';
}

/* Remove EVERY privilege from the token.  SE_PRIVILEGE_REMOVED, not
   disabled: a disabled privilege can be enabled again by the holder. */
static int strip_privileges(HANDLE tok, char* why, size_t whylen) {
  BYTE buf[8192];
  DWORD len = 0;
  TOKEN_PRIVILEGES* tp;
  DWORD i;

  if (!GetTokenInformation(tok, TokenPrivileges, buf, sizeof(buf), &len)) {
    win_error("GetTokenInformation(privileges)", why, whylen);
    return 0;
  }
  tp = (TOKEN_PRIVILEGES*)buf;
  for (i = 0; i < tp->PrivilegeCount; i++)
    tp->Privileges[i].Attributes = SE_PRIVILEGE_REMOVED;
  if (tp->PrivilegeCount > 0 &&
      !AdjustTokenPrivileges(tok, FALSE, tp, 0, NULL, NULL)) {
    win_error("AdjustTokenPrivileges(remove all)", why, whylen);
    return 0;
  }
  /* AdjustTokenPrivileges can return TRUE having done only part of the job;
     ask again rather than believe it. */
  len = 0;
  if (!GetTokenInformation(tok, TokenPrivileges, buf, sizeof(buf), &len) ||
      ((TOKEN_PRIVILEGES*)buf)->PrivilegeCount != 0) {
    snprintf(why, whylen, "the relay token still holds %lu privilege(s)",
             (unsigned long)((TOKEN_PRIVILEGES*)buf)->PrivilegeCount);
    return 0;
  }
  return 1;
}

/* Low integrity, S-1-16-4096. */
static int set_low_integrity(HANDLE tok, char* why, size_t whylen) {
  PSID low = NULL;
  TOKEN_MANDATORY_LABEL tml;
  int ok;

  if (!ConvertStringSidToSidA("S-1-16-4096", &low)) {
    win_error("ConvertStringSidToSid(Low)", why, whylen);
    return 0;
  }
  tml.Label.Attributes = SE_GROUP_INTEGRITY;
  tml.Label.Sid = low;
  ok = SetTokenInformation(tok, TokenIntegrityLevel, &tml,
                           sizeof(tml) + GetLengthSid(low));
  if (!ok)
    win_error("SetTokenInformation(Low)", why, whylen);
  LocalFree(low);
  return ok;
}

/* 25 Sep 26 SD Core Solo - ruling 20.  The relay's primary token: a
   restricted copy of this process's own, steps 1-4 of the description.  The
   restricting list is the MEASURED one; RESTRICTED alone is not enough for
   the relay to start. */
static HANDLE relay_token(char* why, size_t whylen) {
  static const char* restricting[3] = {
      "S-1-1-0",      /* Everyone */
      "S-1-5-32-545", /* BUILTIN\Users */
      "S-1-5-12"      /* RESTRICTED */
  };
  SID_AND_ATTRIBUTES rs[3];
  HANDLE own = NULL;
  HANDLE tok = NULL;
  BYTE ubuf[512];
  DWORD len = 0;
  char* user = NULL;
  char sddl[256];
  PSECURITY_DESCRIPTOR sd = NULL;
  BOOL present = FALSE, defaulted = FALSE;
  PACL dacl = NULL;
  TOKEN_DEFAULT_DACL tdd;
  int i;
  int ok = 0;

  ZeroMemory(rs, sizeof(rs));
  for (i = 0; i < 3; i++) {
    if (!ConvertStringSidToSidA(restricting[i], &rs[i].Sid)) {
      win_error("ConvertStringSidToSid(restricting)", why, whylen);
      goto done;
    }
  }
  if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY |
                            TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_PRIVILEGES,
                        &own)) {
    win_error("OpenProcessToken", why, whylen);
    goto done;
  }
  if (!CreateRestrictedToken(own, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL, 3,
                             rs, &tok)) {
    win_error("CreateRestrictedToken", why, whylen);
    goto done;
  }
  if (!strip_privileges(tok, why, whylen) || !set_low_integrity(tok, why, whylen))
    goto done;

  /* Step 4: the child's own objects must pass the restricted check too. */
  if (!GetTokenInformation(own, TokenUser, ubuf, sizeof(ubuf), &len) ||
      !ConvertSidToStringSidA(((TOKEN_USER*)ubuf)->User.Sid, &user)) {
    win_error("the user's SID", why, whylen);
    goto done;
  }
  snprintf(sddl, sizeof(sddl), "D:(A;;GA;;;SY)(A;;GA;;;%s)(A;;GA;;;RC)", user);
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
          sddl, SDDL_REVISION_1, &sd, NULL) ||
      !GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) || !dacl) {
    win_error("the relay's default DACL", why, whylen);
    goto done;
  }
  tdd.DefaultDacl = dacl;
  if (!SetTokenInformation(tok, TokenDefaultDacl, &tdd, sizeof(tdd))) {
    win_error("SetTokenInformation(default DACL)", why, whylen);
    goto done;
  }
  ok = 1;

done:
  for (i = 0; i < 3; i++)
    if (rs[i].Sid)
      LocalFree(rs[i].Sid);
  if (user)
    LocalFree(user);
  if (sd)
    LocalFree(sd);
  if (own)
    CloseHandle(own);
  if (!ok && tok) {
    CloseHandle(tok);
    tok = NULL;
  }
  return tok;
}

/* The relay's path: beside this executable.  dir gets the directory. */
static int relay_path(char* dir, size_t dirlen, char* out, size_t outlen,
                      char* why, size_t whylen) {
  DWORD n = GetModuleFileNameA(NULL, dir, (DWORD)dirlen);
  char* slash;

  if (n == 0 || n >= dirlen) {
    win_error("GetModuleFileName", why, whylen);
    return 0;
  }
  slash = strrchr(dir, '\\');
  if (slash == NULL) {
    snprintf(why, whylen, "cannot find the directory of %s", dir);
    return 0;
  }
  *slash = '\0';
  if (snprintf(out, outlen, "%s\\%s", dir, RELAY_EXE_NAME) >= (int)outlen) {
    snprintf(why, whylen, "relay path too long");
    return 0;
  }
  if (GetFileAttributesA(out) == INVALID_FILE_ATTRIBUTES) {
    snprintf(why, whylen, "%s is missing: was the install complete?", out);
    return 0;
  }
  return 1;
}

static int dup_inheritable(HANDLE h, HANDLE* out, const char* what, char* why,
                           size_t whylen) {
  if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), out, 0,
                       TRUE, DUPLICATE_SAME_ACCESS)) {
    win_error(what, why, whylen);
    return 0;
  }
  return 1;
}

/* ======================================================================
   win32_relay_spawn()                                                    */

int win32_relay_spawn(int net_fd, int sp_fd, int ctl_fd, int timeout_ms,
                      void** proc, char* why, size_t whylen) {
  char dir[MAX_PATH];
  char sysdir[MAX_PATH];
  char exe[MAX_PATH + 32];
  char cmd[MAX_PATH + 160];
  HANDLE prim = NULL;
  HANDLE net = INVALID_HANDLE_VALUE;
  HANDLE sp = INVALID_HANDLE_VALUE;
  HANDLE ctl = INVALID_HANDLE_VALUE;
  HANDLE netInh = NULL;
  HANDLE spInh = NULL;
  HANDLE ctlInh = NULL;
  HANDLE list[3];
  STARTUPINFOEXA six;
  PROCESS_INFORMATION pi;
  SIZE_T alen = 0;
  int ok = 0;

  *proc = NULL;
  ZeroMemory(&six, sizeof(six));
  ZeroMemory(&pi, sizeof(pi));

  if (!relay_path(dir, sizeof(dir), exe, sizeof(exe), why, whylen))
    return 0;
  if (GetSystemDirectoryA(sysdir, sizeof(sysdir)) == 0) {
    win_error("GetSystemDirectory", why, whylen);
    return 0;
  }

  net = (HANDLE)_get_osfhandle(net_fd);
  sp = (HANDLE)_get_osfhandle(sp_fd);
  ctl = (HANDLE)_get_osfhandle(ctl_fd);
  if (net == INVALID_HANDLE_VALUE || sp == INVALID_HANDLE_VALUE ||
      ctl == INVALID_HANDLE_VALUE) {
    snprintf(why, whylen,
             "no Windows handle behind descriptor %d, %d or %d", net_fd, sp_fd,
             ctl_fd);
    return 0;
  }

  /* 1-4: the token. */
  prim = relay_token(why, whylen);
  if (prim == NULL)
    return 0;

  /* The three handles, and ONLY the three (description block). */
  if (!dup_inheritable(net, &netInh, "DuplicateHandle(connection)", why,
                       whylen) ||
      !dup_inheritable(sp, &spInh, "DuplicateHandle(socketpair)", why, whylen) ||
      !dup_inheritable(ctl, &ctlInh, "DuplicateHandle(control)", why, whylen))
    goto done;
  list[0] = netInh;
  list[1] = spInh;
  list[2] = ctlInh;

  InitializeProcThreadAttributeList(NULL, 1, 0, &alen);
  six.lpAttributeList =
      (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, alen);
  if (six.lpAttributeList == NULL ||
      !InitializeProcThreadAttributeList(six.lpAttributeList, 1, 0, &alen) ||
      !UpdateProcThreadAttribute(six.lpAttributeList, 0,
                                 PROC_THREAD_ATTRIBUTE_HANDLE_LIST, list,
                                 sizeof(list), NULL, NULL)) {
    win_error("PROC_THREAD_ATTRIBUTE_HANDLE_LIST", why, whylen);
    goto done;
  }
  six.StartupInfo.cb = sizeof(six);
  /* lpDesktop left NULL - inherited (description block). */

  snprintf(cmd, sizeof(cmd), "\"%s\" %llu %llu %llu %d", exe,
           (unsigned long long)(uintptr_t)netInh,
           (unsigned long long)(uintptr_t)spInh,
           (unsigned long long)(uintptr_t)ctlInh, timeout_ms);

  /* 5.  Environment inherited (NULL): sd's own, the same user's. */
  if (!CreateProcessAsUserA(prim, exe, cmd, NULL, NULL, TRUE,
                            CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                            NULL, sysdir, &six.StartupInfo, &pi)) {
    win_error("CreateProcessAsUser(sdtlsrelay)", why, whylen);
    goto done;
  }
  CloseHandle(pi.hThread);
  *proc = (void*)pi.hProcess;
  ok = 1;

done:
  /* The child holds its own copies now; sd keeps none of the inheritable
     duplicates, or the connection would stay open after the relay ends. */
  if (netInh)
    CloseHandle(netInh);
  if (spInh)
    CloseHandle(spInh);
  if (ctlInh)
    CloseHandle(ctlInh);
  if (six.lpAttributeList) {
    DeleteProcThreadAttributeList(six.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, six.lpAttributeList);
  }
  if (prim)
    CloseHandle(prim);
  return ok;
}

/* ======================================================================
   win32_my_sid()  -  this process's own user SID, as SDDL text

   RELEASE_1.1 55.  The front tells the relay which SID may open the handover
   pipe's client end, and the answer is the front's own: it is the only party
   that opens it, and it then hands the HANDLE to the session it spawned,
   which is not an access check.  Read rather than assumed - see sd_tls.h. */

int win32_my_sid(char* out, size_t outlen, char* why, size_t whylen) {
  HANDLE tok = NULL;
  BYTE buf[1024];
  DWORD len = 0;
  char* text = NULL;
  int ok = 0;

  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
    win_error("OpenProcessToken", why, whylen);
    return 0;
  }
  if (!GetTokenInformation(tok, TokenUser, buf, sizeof(buf), &len)) {
    win_error("GetTokenInformation(TokenUser)", why, whylen);
  } else if (!ConvertSidToStringSidA(((TOKEN_USER*)buf)->User.Sid, &text)) {
    win_error("ConvertSidToStringSid", why, whylen);
  } else if (strlen(text) >= outlen) {
    snprintf(why, whylen, "no room for the SID %s", text);
  } else {
    strcpy(out, text);
    ok = 1;
  }
  if (text)
    LocalFree(text);
  CloseHandle(tok);
  return ok;
}

/* ======================================================================
   win32_relay_exit_code()                                                */

int win32_relay_exit_code(void* proc, int wait_ms) {
  HANDLE h = (HANDLE)proc;
  DWORD code = 0;
  int result = -1;

  if (h == NULL)
    return -1;
  if (WaitForSingleObject(h, (DWORD)(wait_ms < 0 ? 0 : wait_ms)) ==
          WAIT_OBJECT_0 &&
      GetExitCodeProcess(h, &code))
    result = (int)code;
  CloseHandle(h);
  return result;
}

/* END-CODE */
