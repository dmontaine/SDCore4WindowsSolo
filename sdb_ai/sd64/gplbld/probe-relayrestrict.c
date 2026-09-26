/* probe-relayrestrict.c - SOLO 3, decision D3: can the TLS relay run on a
 * RESTRICTED copy of the user's own token, and what could code running in it
 * still reach?  A probe, never shipped.  docs/SOLO_API.md section 2 and 5.
 *
 * Solo's daemon is the user at a standard token (ruling 16), so it cannot
 * start the relay as another account the way win32relay.c does (S4U needs
 * SeTcb).  The options: (a) the user's token, no privileges, Low; (b) the
 * same plus RESTRICTING SIDs, so every access must also pass a second SID
 * list.  This builds each token WITHOUT any privilege - CreateRestrictedToken
 * on our own token, integrity lowered, CreateProcessAsUser with a restricted
 * copy of the caller's own primary token, which needs no privilege.
 *
 * TWO USES, both selected by environment so the relay harness runs unchanged:
 *
 *   RELAY   test-tlsrelay-units.py with SD_TLSRELAY = this exe.  It is given
 *           the relay's arguments (three inherited handles and a timeout),
 *           starts SD_PROBE_RELAY under the token with exactly those three
 *           handles inherited, and returns the relay's exit code.  So the
 *           harness's real TLS 1.3 handshake runs under the token.
 *   ACCESS  SD_PROBE_ACCESS = "path|path|..." : starts ITSELF under the same
 *           token, and the child tries to READ each path and to CREATE a file
 *           in SD_PROBE_WRITEDIR, reporting through an inherited handle -
 *           what code in the relay could actually reach.
 *
 *   SD_PROBE_TOKEN   a | b-users | b-restricted
 *       a             no privileges, Low - no restricting SIDs (the control)
 *       b-users       + restricting SIDs Everyone, Users, RESTRICTED
 *       b-restricted  + restricting SID RESTRICTED only
 *   SD_PROBE_LOG     file this process appends its report to (required)
 *
 * THE INSTRUMENT RULES: it logs the mode, the SIDs, the command line it
 * started, and the CHILD's token as read back from the child process
 * (privilege count, integrity RID, restricting-SID count) - not the token it
 * meant to make.  Unknown mode, missing relay or missing log: exit 2.
 *
 * Build (native UCRT64, static so the child needs no DLL beside it):
 *   gcc -O2 -static -o probe-relayrestrict.exe probe-relayrestrict.c -ladvapi32
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static FILE* logf = NULL;

static void say(const char* fmt, ...) {
  va_list ap;
  if (!logf)
    return;
  va_start(ap, fmt);
  vfprintf(logf, fmt, ap);
  va_end(ap);
  fflush(logf);
}

static PSID sid_of(const char* s) {
  PSID p = NULL;
  if (!ConvertStringSidToSidA(s, &p)) {
    say("  cannot convert SID %s: error %lu\n", s, GetLastError());
    return NULL;
  }
  return p;
}

/* The token for MODE, or NULL.  Reports what it built. */
static HANDLE make_token(const char* mode) {
  HANDLE tok = NULL, rtok = NULL;
  SID_AND_ATTRIBUTES rs[3];
  DWORD nrs = 0;
  const char* list[3];
  DWORD i;
  TOKEN_MANDATORY_LABEL tml;
  PSID low;
  char user_sid[256] = "";
  BYTE ubuf[512];
  DWORD len;
  char* ustr = NULL;
  char dacl_sddl[512];
  PSECURITY_DESCRIPTOR sd = NULL;
  BOOL present = FALSE, defaulted = FALSE;
  PACL dacl = NULL;
  TOKEN_DEFAULT_DACL tdd;

  /* "<mode>-strip": also REMOVE every privilege, SeChangeNotify included -
     what win32relay.c's strip_privileges() does (added 25 Sep 2026, before
     building ruling 20, which asks for exactly that). */
  int strip = 0;
  char base[64];
  snprintf(base, sizeof(base), "%s", mode);
  if (strlen(base) > 6 && strcmp(base + strlen(base) - 6, "-strip") == 0) {
    base[strlen(base) - 6] = '\0';
    strip = 1;
  }
  mode = base;
  if (strcmp(mode, "a") == 0) {
    nrs = 0;
  } else if (strcmp(mode, "b-users") == 0) {
    list[0] = "S-1-1-0";       /* Everyone */
    list[1] = "S-1-5-32-545";  /* BUILTIN\Users */
    list[2] = "S-1-5-12";      /* RESTRICTED */
    nrs = 3;
  } else if (strcmp(mode, "b-restricted") == 0) {
    list[0] = "S-1-5-12";
    nrs = 1;
  } else {
    say("REFUSED: unknown SD_PROBE_TOKEN '%s'\n", mode);
    return NULL;
  }
  for (i = 0; i < nrs; i++) {
    rs[i].Sid = sid_of(list[i]);
    rs[i].Attributes = 0;
    if (!rs[i].Sid)
      return NULL;
    say("  restricting SID %s\n", list[i]);
  }
  if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY |
                            TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_PRIVILEGES,
                        &tok)) {
    say("  OpenProcessToken: error %lu\n", GetLastError());
    return NULL;
  }
  if (!CreateRestrictedToken(tok, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL,
                             nrs, nrs ? rs : NULL, &rtok)) {
    say("  CreateRestrictedToken: error %lu\n", GetLastError());
    return NULL;
  }
  if (strip) {
    BYTE pb[4096];
    DWORD pl = 0;
    TOKEN_PRIVILEGES* tp = (TOKEN_PRIVILEGES*)pb;
    if (!GetTokenInformation(rtok, TokenPrivileges, pb, sizeof(pb), &pl)) {
      say("  GetTokenInformation(privileges): error %lu\n", GetLastError());
      return NULL;
    }
    for (i = 0; i < tp->PrivilegeCount; i++)
      tp->Privileges[i].Attributes = SE_PRIVILEGE_REMOVED;
    if (tp->PrivilegeCount &&
        !AdjustTokenPrivileges(rtok, FALSE, tp, 0, NULL, NULL)) {
      say("  AdjustTokenPrivileges(remove): error %lu\n", GetLastError());
      return NULL;
    }
    say("  every privilege REMOVED (%lu)\n", tp->PrivilegeCount);
  }
  /* Low integrity, S-1-16-4096. */
  low = sid_of("S-1-16-4096");
  tml.Label.Sid = low;
  tml.Label.Attributes = SE_GROUP_INTEGRITY;
  if (!SetTokenInformation(rtok, TokenIntegrityLevel, &tml,
                           sizeof(tml) + GetLengthSid(low))) {
    say("  SetTokenInformation(Low): error %lu\n", GetLastError());
    return NULL;
  }
  /* With restricting SIDs the child must still be able to open ITSELF: its
     process and thread objects take the token's default DACL, and the
     restricted check needs a restricting SID in it.  So the default DACL
     grants SYSTEM, the user, and RESTRICTED (SDDL "RC"). */
  if (GetTokenInformation(tok, TokenUser, ubuf, sizeof(ubuf), &len) &&
      ConvertSidToStringSidA(((TOKEN_USER*)ubuf)->User.Sid, &ustr)) {
    snprintf(user_sid, sizeof(user_sid), "%s", ustr);
    LocalFree(ustr);
  }
  say("  user SID %s\n", user_sid);
  if (nrs) {
    snprintf(dacl_sddl, sizeof(dacl_sddl), "D:(A;;GA;;;SY)(A;;GA;;;%s)(A;;GA;;;RC)",
             user_sid);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            dacl_sddl, SDDL_REVISION_1, &sd, NULL) ||
        !GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted)) {
      say("  default DACL %s: error %lu\n", dacl_sddl, GetLastError());
      return NULL;
    }
    tdd.DefaultDacl = dacl;
    if (!SetTokenInformation(rtok, TokenDefaultDacl, &tdd, sizeof(tdd))) {
      say("  SetTokenInformation(default DACL): error %lu\n", GetLastError());
      return NULL;
    }
    say("  default DACL %s\n", dacl_sddl);
  }
  CloseHandle(tok);
  return rtok;
}

/* What the child REALLY holds, read from the child process. */
static void report_child_token(HANDLE proc) {
  HANDLE t = NULL;
  BYTE buf[8192];
  DWORD len = 0;
  DWORD privs = 0, rid = 0, nrestr = 0;
  if (!OpenProcessToken(proc, TOKEN_QUERY, &t)) {
    say("  child token: cannot open, error %lu\n", GetLastError());
    return;
  }
  if (GetTokenInformation(t, TokenPrivileges, buf, sizeof(buf), &len))
    privs = ((TOKEN_PRIVILEGES*)buf)->PrivilegeCount;
  if (GetTokenInformation(t, TokenIntegrityLevel, buf, sizeof(buf), &len)) {
    PSID s = ((TOKEN_MANDATORY_LABEL*)buf)->Label.Sid;
    rid = *GetSidSubAuthority(s, *GetSidSubAuthorityCount(s) - 1);
  }
  if (GetTokenInformation(t, TokenRestrictedSids, buf, sizeof(buf), &len))
    nrestr = ((TOKEN_GROUPS*)buf)->GroupCount;
  say("  CHILD TOKEN (read back): privileges %lu, integrity RID 0x%lx%s, "
      "restricting SIDs %lu\n",
      privs, rid, rid == 0x1000 ? " (Low)" : "", nrestr);
  CloseHandle(t);
}

static int spawn(HANDLE tok, const char* exe, char* cmdline, HANDLE* inherit,
                 int ninherit) {
  STARTUPINFOEXA si;
  PROCESS_INFORMATION pi;
  SIZE_T sz = 0;
  DWORD code = 99;
  int i;

  for (i = 0; i < ninherit; i++)
    SetHandleInformation(inherit[i], HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
  ZeroMemory(&si, sizeof(si));
  si.StartupInfo.cb = sizeof(si);
  InitializeProcThreadAttributeList(NULL, 1, 0, &sz);
  si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(sz);
  if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &sz) ||
      !UpdateProcThreadAttribute(si.lpAttributeList, 0,
                                 PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit,
                                 ninherit * sizeof(HANDLE), NULL, NULL)) {
    say("  attribute list: error %lu\n", GetLastError());
    return 98;
  }
  say("  $ %s\n", cmdline);
  if (!CreateProcessAsUserA(tok, exe, cmdline, NULL, NULL, TRUE,
                            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                            NULL, NULL, &si.StartupInfo, &pi)) {
    say("  CreateProcessAsUser: error %lu - NOT STARTED\n", GetLastError());
    return 97;
  }
  report_child_token(pi.hProcess);
  WaitForSingleObject(pi.hProcess, INFINITE);
  GetExitCodeProcess(pi.hProcess, &code);
  say("  child exit %lu (0x%lx)\n", code, code);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return (int)code;
}

/* ---- the ACCESS child ---------------------------------------------------- */
static void out(HANDLE h, const char* fmt, ...) {
  char b[1024];
  DWORD w;
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(b, sizeof(b), fmt, ap);
  va_end(ap);
  WriteFile(h, b, (DWORD)strlen(b), &w, NULL);
}

static int access_child(HANDLE rep, const char* paths, const char* writedir) {
  char buf[4096];
  char* p;
  char* next;
  snprintf(buf, sizeof(buf), "%s", paths);
  for (p = buf; p && *p; p = next) {
    HANDLE f;
    DWORD attrs, got = 0;
    char b[16];
    next = strchr(p, '|');
    if (next)
      *next++ = '\0';
    attrs = GetFileAttributesA(p);
    f = CreateFileA(p, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (f == INVALID_HANDLE_VALUE) {
      out(rep, "    READ   DENIED   error %lu   %s\n", GetLastError(), p);
      continue;
    }
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY))
      out(rep, "    READ   OPENED   (directory)   %s\n", p);
    else if (ReadFile(f, b, sizeof(b), &got, NULL))
      out(rep, "    READ   ALLOWED  %lu bytes read   %s\n", got, p);
    else
      out(rep, "    READ   OPENED, ReadFile error %lu   %s\n", GetLastError(), p);
    CloseHandle(f);
  }
  if (writedir && *writedir) {
    char w[1024];
    HANDLE f;
    snprintf(w, sizeof(w), "%s\\probe-relayrestrict-write.tmp", writedir);
    f = CreateFileA(w, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (f == INVALID_HANDLE_VALUE)
      out(rep, "    WRITE  DENIED   error %lu   %s\n", GetLastError(), w);
    else {
      out(rep, "    WRITE  ALLOWED  (created, deleted on close)   %s\n", w);
      CloseHandle(f);
    }
  }
  return 0;
}

int main(int argc, char* argv[]) {
  const char* mode = getenv("SD_PROBE_TOKEN");
  const char* logp = getenv("SD_PROBE_LOG");
  const char* relay = getenv("SD_PROBE_RELAY");
  const char* acc = getenv("SD_PROBE_ACCESS");
  const char* wdir = getenv("SD_PROBE_WRITEDIR");
  HANDLE tok;
  char cmd[4096];
  int i;

  /* "--inspect <pid>": the token of a RUNNING process, to stdout - used on the
     relay sd.exe itself started (win32relay.c), the build's witness. */
  if (argc == 3 && strcmp(argv[1], "--inspect") == 0) {
    DWORD pid = (DWORD)strtoul(argv[2], NULL, 10);
    HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!ph) {
      printf("inspect %lu: cannot open the process, error %lu\n", pid, GetLastError());
      return 2;
    }
    logf = stdout;
    say("inspect pid %lu:\n", pid);
    report_child_token(ph);
    CloseHandle(ph);
    return 0;
  }

  /* The ACCESS child: "--access-child <report handle>". */
  if (argc == 3 && strcmp(argv[1], "--access-child") == 0) {
    HANDLE rep = (HANDLE)(uintptr_t)strtoull(argv[2], NULL, 10);
    return access_child(rep, acc ? acc : "", wdir);
  }

  if (!logp || !*logp)
    return 2;
  logf = fopen(logp, "a");
  if (!logf)
    return 2;
  say("=== probe-relayrestrict pid %lu, mode %s, %s\n", GetCurrentProcessId(),
      mode ? mode : "(none)", acc ? "ACCESS" : "RELAY");
  if (!mode) {
    say("REFUSED: SD_PROBE_TOKEN not set\n");
    return 2;
  }
  tok = make_token(mode);
  if (!tok)
    return 2;

  if (acc) {
    /* The report travels through an inherited file handle: the child may be
       unable to open ANY file by name, which is what is being measured. */
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    HANDLE rep;
    char self[MAX_PATH];
    int rc;
    rep = CreateFileA(logp, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                      &sa, OPEN_ALWAYS, 0, NULL);
    if (rep == INVALID_HANDLE_VALUE) {
      say("REFUSED: cannot open the report handle\n");
      return 2;
    }
    GetModuleFileNameA(NULL, self, sizeof(self));
    snprintf(cmd, sizeof(cmd), "\"%s\" --access-child %llu", self,
             (unsigned long long)(uintptr_t)rep);
    say("  access child reads: %s\n  and writes in: %s\n", acc, wdir ? wdir : "(none)");
    rc = spawn(tok, self, cmd, &rep, 1);
    CloseHandle(rep);
    fseek(logf, 0, SEEK_END);
    say("  access child finished, exit %d\n", rc);
    return rc;
  }

  /* RELAY: argv[1..3] are the three handles, argv[4] the timeout. */
  if (!relay || !*relay || GetFileAttributesA(relay) == INVALID_FILE_ATTRIBUTES) {
    say("REFUSED: SD_PROBE_RELAY '%s' is not a file\n", relay ? relay : "");
    return 2;
  }
  if (argc != 5) {
    say("REFUSED: want 3 handles and a timeout, got %d argument(s)\n", argc - 1);
    return 2;
  }
  {
    HANDLE hs[3];
    int n = snprintf(cmd, sizeof(cmd), "\"%s\"", relay);
    for (i = 1; i < argc; i++)
      n += snprintf(cmd + n, sizeof(cmd) - n, " %s", argv[i]);
    for (i = 0; i < 3; i++)
      hs[i] = (HANDLE)(uintptr_t)strtoull(argv[i + 1], NULL, 10);
    return spawn(tok, relay, cmd, hs, 3);
  }
}
