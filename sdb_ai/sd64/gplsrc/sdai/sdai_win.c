/* SDAI_WIN.C
 * sd-ai.exe: the Windows facts - the caller, DPAPI, private files, atomic replace, locks.
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
 * 13 Nov 26 Windows port - New (RELEASE_1.1 246): the C helper replaces the Python one (gplbld/sd-ai's peer, in_group, is_sdsys, is_admin,
 *           may_ask, dpapi, acl_sids, private_file, private_create, replace, Locked and event_log, rule for rule).
 * 16 Nov 26 SD Core Solo - RELEASE_1.1 246: carried from SD Core (92aef613, f89f8bc3) in Linux Solo's same-user form (owner 23 Oct 2026; Linux
 *           Solo gplbld/sd-ai): caller_from_pipe replaced by caller_self (this process's own token, standard input a pipe or no caller);
 *           is_admin is any caller; may_ask moved to sdai_main.c (gate=yes in ai.conf); in_group, is_sdsys, gate_group, account_sid,
 *           GATE_GROUP, ADMIN_USER and event_log removed (nothing calls them without the service and the pipe).
 * END-HISTORY
 *
 * START-DESCRIPTION:
 *
 * Linux Solo's form is the template; each of these is forced by the operating system:
 *   THE CALLER (Linux Solo: SO_PEERCRED, the peer's uid must be the helper's own).  The helper is a child of the caller on anonymous pipes, so
 *     the caller is this process's own token; standard input that is not a pipe, a token that cannot be read, and LocalSystem, LocalService
 *     and NetworkService are never a caller.  Nothing the caller wrote names the caller.
 *   THE GATE (Linux Solo: gate=yes in ai.conf).  In sdai_main.c, read with the settings at each request; off as delivered; every doubt is no.
 *   THE ADMINISTRATOR (Linux Solo: any process of the same user).  Any caller may change the settings and the keys.
 *   THE KEY (Linux: a 0600 file).  A DPAPI blob in THIS ACCOUNT'S user scope (no CRYPTPROTECT_LOCAL_MACHINE: owner, Q4), no UI, the entropy
 *     "sd-ai key <provider>", in a file whose list allows only this account and SYSTEM; a key file that grants anyone else is refused, not
 *     repaired.  The blobs the Python helper wrote are the same and read here unchanged.
 *   LOCKS (Linux: flock).  LockFileEx on byte 0, tried for ten seconds as msvcrt.locking did.
 *
 * END-DESCRIPTION
 */

#include "sdai.h"

#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>

#define SID_SYSTEM "S-1-5-18"

wchar_t* u2w(const char* s) {
  int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
  wchar_t* w;
  if (n <= 0)
    n = 1;
  w = (wchar_t*)calloc((size_t)n + 1, sizeof(wchar_t));
  if (w == NULL)
    ExitProcess(9);
  MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
  return w;
}

char* w2u(const wchar_t* s) {
  int n = WideCharToMultiByte(CP_UTF8, 0, s, -1, NULL, 0, NULL, NULL);
  char* u;
  if (n <= 0)
    n = 1;
  u = (char*)calloc((size_t)n + 1, 1);
  if (u == NULL)
    ExitProcess(9);
  WideCharToMultiByte(CP_UTF8, 0, s, -1, u, n, NULL, NULL);
  return u;
}

wchar_t* wjoin(const wchar_t* dir, const char* name) {
  wchar_t* wn = u2w(name);
  size_t a = wcslen(dir), b = wcslen(wn);
  wchar_t* out = (wchar_t*)calloc(a + b + 2, sizeof(wchar_t));
  if (out == NULL)
    ExitProcess(9);
  wcscpy(out, dir);
  if (a > 0 && dir[a - 1] != L'\\' && dir[a - 1] != L'/')
    wcscat(out, L"\\");
  wcscat(out, wn);
  free(wn);
  return out;
}

wchar_t* wdirname(const wchar_t* path) {
  wchar_t* d = _wcsdup(path);
  wchar_t* s1;
  wchar_t* s2;
  if (d == NULL)
    ExitProcess(9);
  s1 = wcsrchr(d, L'\\');
  s2 = wcsrchr(d, L'/');
  if (s2 > s1)
    s1 = s2;
  if (s1 != NULL)
    *s1 = L'\0';
  else
    wcscpy(d, L".");
  return d;
}

static int sid_text(PSID sid, char* out, size_t n) {
  LPSTR s = NULL;
  if (sid == NULL || !IsValidSid(sid) || !ConvertSidToStringSidA(sid, &s))
    return 0;
  snprintf(out, n, "%s", s);
  LocalFree(s);
  return 1;
}

static BYTE* token_info(HANDLE tok, TOKEN_INFORMATION_CLASS cls) {
  DWORD need = 0;
  BYTE* buf;
  GetTokenInformation(tok, cls, NULL, 0, &need);
  if (need == 0)
    return NULL;
  buf = (BYTE*)malloc(need);
  if (buf == NULL)
    return NULL;
  if (!GetTokenInformation(tok, cls, buf, need, &need)) {
    free(buf);
    return NULL;
  }
  return buf;
}

/* A caller from a token handle; 0 when any part cannot be read. */
static int read_token(HANDLE tok, caller_t* c) {
  BYTE* tu = token_info(tok, TokenUser);
  BYTE* te;
  BYTE* tg;
  BYTE admins[SECURITY_MAX_SID_SIZE];
  DWORD alen = sizeof admins;
  PSID user;
  memset(c, 0, sizeof *c);
  if (tu == NULL)
    return 0;
  user = ((TOKEN_USER*)tu)->User.Sid;
  if (!sid_text(user, c->sid, sizeof c->sid) || GetLengthSid(user) > sizeof c->psid) {
    free(tu);
    return 0;
  }
  CopySid(sizeof c->psid, c->psid, user);
  free(tu);
  te = token_info(tok, TokenElevation);
  c->elevated = (te != NULL) && ((TOKEN_ELEVATION*)te)->TokenIsElevated != 0;
  free(te);
  c->admins = 0;
  tg = token_info(tok, TokenGroups);
  if (tg != NULL && CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, admins, &alen)) {
    TOKEN_GROUPS* g = (TOKEN_GROUPS*)tg;
    DWORD i;
    for (i = 0; i < g->GroupCount; i++) {
      DWORD a = g->Groups[i].Attributes;
      if (EqualSid(g->Groups[i].Sid, admins) && (a & SE_GROUP_ENABLED) && !(a & SE_GROUP_USE_FOR_DENY_ONLY))
        c->admins = 1;
    }
  }
  free(tg);
  return 1;
}

int own_sid(char* out, size_t n, PSID* psid) {
  static caller_t me;
  static int have = 0;
  if (!have) {
    HANDLE tok;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
      return 0;
    have = read_token(tok, &me);
    CloseHandle(tok);
    if (!have)
      return 0;
  }
  if (out != NULL)
    snprintf(out, n, "%s", me.sid);
  if (psid != NULL)
    *psid = (PSID)me.psid;
  return 1;
}

/* SOLO: the caller is this process's own user (Linux Solo: the peer's uid from SO_PEERCRED must be the helper's own).  The helper is started per
   request by the SD session (or by its own client, sdai_ctl.c) with anonymous pipes as its standard input and output, so the caller's token IS this
   process's token: it is read from OpenProcessToken(GetCurrentProcess()).  Fail closed, as Linux refuses a connection that is not a socket: standard
   input that is not a pipe (a file, a console, nothing) is no caller, nor is a token that cannot be read, nor LocalSystem, LocalService or
   NetworkService. */
int caller_self(HANDLE in, caller_t* c) {
  HANDLE tok = NULL;
  int ok;
  memset(c, 0, sizeof *c);
  if (in == NULL || in == INVALID_HANDLE_VALUE || GetFileType(in) != FILE_TYPE_PIPE)
    return 0;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
    return 0;
  ok = read_token(tok, c);
  CloseHandle(tok);
  if (!ok)
    return 0;
  if (strcmp(c->sid, "S-1-5-18") == 0 || strcmp(c->sid, "S-1-5-19") == 0 || strcmp(c->sid, "S-1-5-20") == 0)
    return 0; /* LocalSystem, LocalService, NetworkService: never a person */
  return 1;
}

/* SOLO: the administrator is the caller (Linux Solo: any process of the same user may change the settings and the keys - a key is as safe as the
   user's other private files, and no safer).  The SD side stays gated: set.ai and tool.ai want SD's administrator. */
int is_admin(const caller_t* c) { return c != NULL; }

/* ---------------------------------------------------------------- the key at rest */

int dpapi(const BYTE* in, DWORD n, const char* entropy, int protect, BYTE** out, DWORD* outn) {
  DATA_BLOB din, ent, dout;
  BOOL ok;
  din.cbData = n;
  din.pbData = (BYTE*)in;
  ent.cbData = (DWORD)strlen(entropy);
  ent.pbData = (BYTE*)entropy;
  memset(&dout, 0, sizeof dout);
  if (protect)
    ok = CryptProtectData(&din, NULL, &ent, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &dout);
  else
    ok = CryptUnprotectData(&din, NULL, &ent, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &dout);
  if (!ok)
    return 0;
  *out = (BYTE*)malloc(dout.cbData ? dout.cbData : 1);
  if (*out == NULL) {
    LocalFree(dout.pbData);
    return 0;
  }
  memcpy(*out, dout.pbData, dout.cbData);
  *outn = dout.cbData;
  SecureZeroMemory(dout.pbData, dout.cbData);
  LocalFree(dout.pbData);
  return 1;
}

int path_exists(const wchar_t* path) { return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES; }

int path_isfile(const wchar_t* path) {
  DWORD a = GetFileAttributesW(path);
  return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

int path_plain_file(const wchar_t* path) {
  DWORD a = GetFileAttributesW(path);
  return a != INVALID_FILE_ATTRIBUTES && !(a & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE));
}

/* True when the file is plain (not a link or other reparse point) and every ALLOW entry of its list names this account or SYSTEM.  A list that
   cannot be read, no list (everyone), or an entry of a kind not known here is no.  A DENY entry takes nothing away from who may NOT read it. */
int private_file(const wchar_t* path) {
  PACL dacl = NULL;
  PSECURITY_DESCRIPTOR sd = NULL;
  ACL_SIZE_INFORMATION info;
  PSID me;
  BYTE system[SECURITY_MAX_SID_SIZE];
  DWORD slen = sizeof system;
  DWORD i;
  int ok = 1;
  if (!path_plain_file(path) || !own_sid(NULL, 0, &me) || !CreateWellKnownSid(WinLocalSystemSid, NULL, system, &slen))
    return 0;
  if (GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &sd) != ERROR_SUCCESS)
    return 0;
  if (dacl == NULL || !GetAclInformation(dacl, &info, sizeof info, AclSizeInformation))
    ok = 0;
  for (i = 0; ok && i < info.AceCount; i++) {
    ACE_HEADER* hdr = NULL;
    PSID s;
    if (!GetAce(dacl, i, (LPVOID*)&hdr)) {
      ok = 0;
      break;
    }
    if (hdr->AceType == ACCESS_DENIED_ACE_TYPE)
      continue;
    if (hdr->AceType != ACCESS_ALLOWED_ACE_TYPE) { /* anything but a plain ALLOW: not a list this helper can judge */
      ok = 0;
      break;
    }
    s = (PSID) & ((ACCESS_ALLOWED_ACE*)hdr)->SidStart;
    if (!EqualSid(s, me) && !EqualSid(s, (PSID)system))
      ok = 0;
  }
  if (sd != NULL)
    LocalFree(sd);
  return ok;
}

HANDLE private_create(const wchar_t* path) {
  char me[192];
  char sddl[512];
  wchar_t* w;
  PSECURITY_DESCRIPTOR psd = NULL;
  SECURITY_ATTRIBUTES sa;
  HANDLE h;
  if (!own_sid(me, sizeof me, NULL))
    return INVALID_HANDLE_VALUE;
  snprintf(sddl, sizeof sddl, "O:%sD:P(A;;FA;;;SY)(A;;FA;;;%s)", me, me);
  w = u2w(sddl);
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(w, SDDL_REVISION_1, &psd, NULL)) {
    free(w);
    return INVALID_HANDLE_VALUE;
  }
  free(w);
  sa.nLength = sizeof sa;
  sa.lpSecurityDescriptor = psd;
  sa.bInheritHandle = FALSE;
  h = CreateFileW(path, GENERIC_WRITE, 0, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  LocalFree(psd);
  return h;
}

/* os.replace, tried a few times: a file another request is reading cannot be replaced for that moment. */
int replace_file(const wchar_t* tmp, const wchar_t* path) {
  int attempt;
  for (attempt = 0; attempt < 20; attempt++) {
    DWORD e;
    if (MoveFileExW(tmp, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
      return 1;
    e = GetLastError();
    if (e != ERROR_ACCESS_DENIED && e != ERROR_SHARING_VIOLATION && e != ERROR_LOCK_VIOLATION)
      return 0;
    SleepEx(50, FALSE);
  }
  return 0;
}

int read_file(const wchar_t* path, size_t max, char** data, size_t* n) {
  HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  char* buf;
  size_t got = 0;
  if (h == INVALID_HANDLE_VALUE) {
    DWORD e = GetLastError();
    return (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) ? 1 : -1;
  }
  buf = (char*)malloc(max + 1);
  if (buf == NULL) {
    CloseHandle(h);
    return -1;
  }
  while (got < max) {
    DWORD k = 0;
    DWORD want = (DWORD)(((max - got) > 65536) ? 65536 : (max - got));
    if (!ReadFile(h, buf + got, want, &k, NULL)) {
      CloseHandle(h);
      free(buf);
      return -1;
    }
    if (k == 0)
      break;
    got += k;
  }
  CloseHandle(h);
  buf[got] = '\0';
  *data = buf;
  *n = got;
  return 0;
}

HANDLE lock_open(const wchar_t* path) {
  HANDLE h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  int tries;
  if (h == INVALID_HANDLE_VALUE)
    return h;
  for (tries = 0; tries < 10; tries++) {
    OVERLAPPED ov;
    memset(&ov, 0, sizeof ov);
    if (LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ov))
      return h;
    SleepEx(1000, FALSE);
  }
  CloseHandle(h);
  return INVALID_HANDLE_VALUE;
}

void lock_close(HANDLE h) {
  OVERLAPPED ov;
  if (h == INVALID_HANDLE_VALUE)
    return;
  memset(&ov, 0, sizeof ov);
  UnlockFileEx(h, 0, 1, 0, &ov);
  CloseHandle(h);
}

/* END-CODE */
