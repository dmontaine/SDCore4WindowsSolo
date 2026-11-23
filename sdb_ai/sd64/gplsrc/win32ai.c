/* WIN32AI.C
 * The transport of the in-SD AI helper (op_ai.c), SD Core Solo for Windows.
 * Copyright (c) Donald Montaine
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
 * 16 Nov 26 SD Core Solo - RELEASE_1.1 246: written from SD Core for Windows'
 *           win32ai.c (13 Nov 26), whose write, avail and read are kept; its
 *           open (the pipe \\.\pipe\sd-ai and the check that the service owns
 *           it) became a start of the helper on anonymous pipes, as Linux Solo's
 *           per-connection helper (plan .claude/plan-solo-ai-20261116.md 2).
 * END-HISTORY
 *
 * START-DESCRIPTION:
 *
 * SD Core for Windows' helper is the service sd-ai, the virtual account
 * NT SERVICE\sd-ai, on the pipe \\.\pipe\sd-ai: it is ANOTHER account, so it
 * needs a server, a name in the global pipe namespace, a check that the pipe's
 * owner is that account (anyone may squat the name while the service is
 * stopped) and the caller's token read off the pipe.  SD CORE SOLO HAS ONE
 * USER, AND ITS HELPER RUNS AS THAT USER, so none of that is needed and none of
 * it is here: as Linux Solo starts one helper process per connection (systemd
 * Accept=true, the user's own socket), THIS FILE STARTS ONE sd-ai.exe PER
 * REQUEST, as a child of the SD session, on the session's own token.  The
 * helper's caller is then its own token (sdai_win.c caller_self), and it
 * refuses unless its standard input is a pipe.  The protocol is Core's and
 * Linux's byte for byte: one JSON line in, one JSON line out.
 *
 * HOW THE HELPER IS STARTED (win32_ai_open):
 *   - THE PROGRAM IS sd-ai.exe IN THE RUNNING PROGRAM'S OWN FOLDER, from
 *     GetModuleFileNameW: never PATH, never the current directory, never the
 *     environment.  CreateProcessW is given that full path as the application
 *     name AND a quoted copy on the command line, so a space in the folder
 *     cannot make another program run.  Its current directory is that folder
 *     too, not the account's.
 *   - Two anonymous pipes, made NOT inheritable; only the child's two ends
 *     (its standard input's read end, its standard output's write end) and a
 *     handle on NUL for its standard error are then made inheritable, and
 *     PROC_THREAD_ATTRIBUTE_HANDLE_LIST names exactly those three, so nothing
 *     else this MSYS2 process holds (its descriptors, a socket, another
 *     request's pipes) reaches the helper.  The child's ends are closed here
 *     as soon as CreateProcessW returns.
 *   - CREATE_NO_WINDOW and no new console; no token is given, so the helper
 *     runs on the session's own; no environment is given, so it has the
 *     session's.
 *   - The parent's two ends are put in non-blocking mode (PIPE_NOWAIT), as
 *     Core's pipe handle is, and kept OUT of the MSYS2 descriptor table.
 *
 * WHAT WAS MEASURED ON ANONYMOUS PIPES (16 Nov 26, a probe built with the
 * same MSYS2 compiler): SetNamedPipeHandleState(PIPE_NOWAIT) succeeds on both
 * ends; a non-blocking WriteFile that does not fit returns TRUE having written
 * 0 (so Core's write loop, 4096-byte pieces and a 10 ms wait, carries: 16
 * pieces filled a 65536-byte pipe and the next went in once the reader took
 * some); PeekNamedPipe reports the bytes waiting, still reports them after
 * the writer has gone, and fails with ERROR_BROKEN_PIPE once they are read;
 * ReadFile on an empty non-blocking end fails with ERROR_NO_DATA; WriteFile
 * after the reader has gone fails with ERROR_NO_DATA.  Every one of those is
 * a case Core's avail, read and write already answer.
 *
 * HOW A REQUEST ENDS:
 *   - win32_ai_close, the normal end (the reply line has been read): both
 *     pipes are closed, the helper is given AI_END_MS to finish (it writes its
 *     log line after the reply), then ended if it has not, and its process
 *     handle closed.
 *   - win32_ai_cancel (op_ai.c's CANCEL, its time limit, a reply too big, a
 *     helper that hung up without a line): the helper is ended at once with
 *     TerminateProcess and every handle closed.
 *   The helper also ends itself past its own watchdog (sdai_main.c
 *   WATCHDOG_MS), so a session that dies mid-request leaves nothing for long.
 *
 * windows.h and NO SD header, the rule every win32*.c file follows.  SleepEx,
 * not Sleep: linuxlb.c defines SD's own Sleep(), and kernel32's would clash at
 * link (13 Nov 26).
 *
 * END-DESCRIPTION
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string.h>
#include <wchar.h>
#include <stdlib.h>

#include "win32ai.h"

#define AI_SLOTS 4
#define AI_CHUNK 4096
#define AI_PIPE_BYTES 65536 /* each pipe's buffer */
#define AI_END_MS 2000      /* a helper that has answered is given this long to finish before it is ended */
#define AI_PROGRAM L"sd-ai.exe"

typedef struct {
  HANDLE to;   /* the helper's standard input: the request is written here */
  HANDLE from; /* the helper's standard output: the reply is read here */
  HANDLE proc; /* the helper's process */
} AI_SLOT;

static AI_SLOT slots[AI_SLOTS];

static AI_SLOT* slot_of(int slot) {
  if (slot < 0 || slot >= AI_SLOTS || slots[slot].proc == NULL)
    return NULL;
  return &slots[slot];
}

static void close_if(HANDLE* h) {
  if (*h != NULL && *h != INVALID_HANDLE_VALUE)
    CloseHandle(*h);
  *h = NULL;
}

/* <the running program's own folder>\sd-ai.exe into path (MAX_PATH * 2 wide characters), and its folder into dir.  0 when it cannot be known. */
static int helper_path(wchar_t* path, wchar_t* dir, DWORD cap) {
  DWORD n = GetModuleFileNameW(NULL, path, cap);
  wchar_t* sep;

  if (n == 0 || n >= cap)
    return 0; /* not known, or cut short: launching the wrong program is worse than launching none */
  sep = wcsrchr(path, L'\\');
  if (sep == NULL)
    return 0;
  sep[1] = L'\0';
  if (wcslen(path) + wcslen(AI_PROGRAM) + 1 > cap)
    return 0;
  wcscpy(dir, path);
  if (wcslen(dir) > 3)
    dir[wcslen(dir) - 1] = L'\0'; /* the folder without its last separator (a drive's root keeps it) */
  wcscat(path, AI_PROGRAM);
  return 1;
}

int win32_ai_open(void) {
  wchar_t path[MAX_PATH * 2];
  wchar_t dir[MAX_PATH * 2];
  wchar_t* cmd;
  HANDLE in_r = NULL, in_w = NULL, out_r = NULL, out_w = NULL, err = NULL;
  HANDLE inherit[3];
  SECURITY_ATTRIBUTES sa;
  STARTUPINFOEXW si;
  PROCESS_INFORMATION pi;
  SIZE_T asz = 0;
  DWORD mode;
  int ok;
  int slot;

  for (slot = 0; slot < AI_SLOTS; slot++) {
    if (slots[slot].proc == NULL)
      break;
  }
  if (slot >= AI_SLOTS)
    return WIN32_AI_NONE;
  if (!helper_path(path, dir, MAX_PATH * 2))
    return WIN32_AI_NONE;
  if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES)
    return WIN32_AI_NONE; /* no helper installed */

  /* The pipes are made NOT inheritable; only the child's ends are then marked, so no other start in this process can carry ours */
  if (!CreatePipe(&in_r, &in_w, NULL, AI_PIPE_BYTES))
    return WIN32_AI_NONE;
  if (!CreatePipe(&out_r, &out_w, NULL, AI_PIPE_BYTES)) {
    close_if(&in_r);
    close_if(&in_w);
    return WIN32_AI_NONE;
  }
  sa.nLength = sizeof sa;
  sa.lpSecurityDescriptor = NULL;
  sa.bInheritHandle = TRUE;
  err = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
  ok = (err != INVALID_HANDLE_VALUE) && SetHandleInformation(in_r, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) &&
       SetHandleInformation(out_w, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
  if (err == INVALID_HANDLE_VALUE)
    err = NULL;

  cmd = NULL;
  memset(&si, 0, sizeof si);
  memset(&pi, 0, sizeof pi);
  if (ok) {
    cmd = (wchar_t*)calloc(wcslen(path) + 16, sizeof(wchar_t));
    ok = (cmd != NULL);
  }
  if (ok) {
    wcscpy(cmd, L"\"");
    wcscat(cmd, path);
    wcscat(cmd, L"\" --one");
    si.StartupInfo.cb = sizeof si;
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = in_r;
    si.StartupInfo.hStdOutput = out_w;
    si.StartupInfo.hStdError = err;
    inherit[0] = in_r;
    inherit[1] = out_w;
    inherit[2] = err;
    InitializeProcThreadAttributeList(NULL, 1, 0, &asz);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(asz);
    ok = (si.lpAttributeList != NULL) && InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &asz);
    if (!ok && si.lpAttributeList != NULL) {
      free(si.lpAttributeList);
      si.lpAttributeList = NULL;
    }
  }
  if (ok)
    ok = UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit, 3 * sizeof(HANDLE), NULL, NULL);
  if (ok)
    ok = CreateProcessW(path, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, dir, &si.StartupInfo, &pi);
  if (si.lpAttributeList != NULL) {
    DeleteProcThreadAttributeList(si.lpAttributeList);
    free(si.lpAttributeList);
  }
  if (cmd != NULL)
    free(cmd);
  /* the child's ends and NUL: the helper holds its own copies now (or there is no helper) */
  close_if(&in_r);
  close_if(&out_w);
  close_if(&err);
  if (!ok) {
    close_if(&in_w);
    close_if(&out_r);
    return WIN32_AI_NONE;
  }
  close_if(&pi.hThread);

  /* Core's mode on the parent's ends: a write that does not fit returns at once, as does a read with nothing there */
  mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
  if (!SetNamedPipeHandleState(in_w, &mode, NULL, NULL) || !SetNamedPipeHandleState(out_r, &mode, NULL, NULL)) {
    TerminateProcess(pi.hProcess, 1);
    close_if(&in_w);
    close_if(&out_r);
    close_if(&pi.hProcess);
    return WIN32_AI_NONE;
  }
  slots[slot].to = in_w;
  slots[slot].from = out_r;
  slots[slot].proc = pi.hProcess;
  return slot;
}

int win32_ai_write(int slot, const char* buf, int len, int wait_ms) {
  AI_SLOT* s = slot_of(slot);
  int done = 0;
  int idle = 0;
  DWORD want;
  DWORD n;

  if (s == NULL || s->to == NULL || len < 0)
    return 0;
  while (done < len) {
    want = (DWORD)(((len - done) > AI_CHUNK) ? AI_CHUNK : (len - done));
    n = 0;
    if (!WriteFile(s->to, buf + done, want, &n, NULL))
      return 0;
    if (n > 0) {
      done += (int)n;
      idle = 0;
      continue;
    }
    if (idle >= wait_ms)
      return 0;
    SleepEx(10, FALSE); /* not Sleep(): linuxlb.c defines SD's own Sleep(), and kernel32's stub would clash at link (13 Nov 26) */
    idle += 10;
  }
  return 1;
}

int win32_ai_avail(int slot) {
  AI_SLOT* s = slot_of(slot);
  DWORD avail = 0;
  DWORD e;

  if (s == NULL)
    return -2;
  if (!PeekNamedPipe(s->from, NULL, 0, NULL, &avail, NULL)) {
    e = GetLastError();
    if (e == ERROR_BROKEN_PIPE || e == ERROR_PIPE_NOT_CONNECTED || e == ERROR_NO_DATA)
      return -1;
    return -2;
  }
  return (avail > 0x7fffffffUL) ? 0x7fffffff : (int)avail;
}

int win32_ai_read(int slot, char* buf, int len) {
  AI_SLOT* s = slot_of(slot);
  DWORD n = 0;
  DWORD e;

  if (s == NULL || len <= 0)
    return -1;
  if (!ReadFile(s->from, buf, (DWORD)len, &n, NULL)) {
    e = GetLastError();
    if (e == ERROR_BROKEN_PIPE || e == ERROR_PIPE_NOT_CONNECTED || e == ERROR_NO_DATA)
      return 0;
    return -1;
  }
  return (int)n;
}

void win32_ai_close(int slot) {
  AI_SLOT* s = slot_of(slot);

  if (s == NULL)
    return;
  close_if(&s->to);   /* the helper sees the end of its input */
  close_if(&s->from); /* and a reader gone, if it is still writing */
  if (WaitForSingleObject(s->proc, AI_END_MS) != WAIT_OBJECT_0)
    TerminateProcess(s->proc, 1);
  close_if(&s->proc);
}

void win32_ai_cancel(int slot) {
  AI_SLOT* s = slot_of(slot);

  if (s == NULL)
    return;
  TerminateProcess(s->proc, 1); /* fails harmlessly on a helper that has already ended */
  close_if(&s->to);
  close_if(&s->from);
  close_if(&s->proc);
}

/* END-CODE */
