/* WIN32SEM.C
 * Native Windows named semaphores, for sdsem.c.
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
 * 25 Sep 26 SD Core Solo - SOLO 4: the set grants SYSTEM and the creating
 *           user, not Administrators and sdusers (an unelevated start failed).
 * 16 Aug 26 Windows port - written.  POSIX sem_open() cannot be used in
 *           session 0, so SD could not run as a service.
 * END-HISTORY
 *
 * START-DESCRIPTION:
 *
 * WHY THIS FILE EXISTS AT ALL.  POSIX sem_open() on the MSYS2 runtime does not
 * work in session 0: as LocalSystem it BLOCKS FOR TEN SECONDS AND FAILS WITH
 * ETIMEDOUT.  Measured 16 Aug 2026 with the creating process and the opening
 * process BOTH LocalSystem in session 0, so it is not about crossing sessions -
 * the runtime's POSIX semaphores simply do not work there.  SD could therefore
 * never be started by a Windows service, and the requirement is a production
 * system with nobody logged in, serving every user from system startup.
 *
 * The repository owner sanctioned the windows.h exception on 16 Aug 2026.
 * win32sem.h explains why the exception has to live in a file of its own
 * rather than inside sdsem.c.
 *
 * TWO THINGS ARE LOAD-BEARING HERE AND NEITHER IS OBVIOUS:
 *
 * THE "Global\" PREFIX.  A service runs in session 0 and its users in sessions
 * 1 and up.  An unqualified name is session-local, so the service and the users
 * would each get their own private semaphore of the same name and neither would
 * ever see the other - the same failure as before, wearing a different hat.
 * Creating in Global needs SeCreateGlobalPrivilege, which LocalSystem and an
 * elevated administrator both hold; OPENING one does not, which is what lets an
 * ordinary user's session attach.
 *
 * THE SECURITY DESCRIPTOR.  A default one grants the creator's token and
 * nothing else, so SD would start as a service and then refuse every user on
 * the machine - and it would look healthy while doing it.  The objects are
 * therefore created granting SYSTEM, Administrators and the caller's nominated
 * group, which is sdusers: the same three the data tree's ACL grants.
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

#include "win32sem.h"

/* ======================================================================
   The security descriptor.

   Built in SDDL rather than with InitializeAcl/AddAccessAllowedAce because the
   call form is forty lines with three failure paths and this can be read at a
   glance.  GA is GENERIC_ALL, SY is SYSTEM, BA is the Administrators alias -
   the last of these by SID rather than by name, so it is right on a localised
   Windows, which is the same reason sd.iss passes *S-1-5-32-544 to icacls.

   A MISSING GROUP IS NOT AN ERROR.  The bootstrap (gplbld/bootstrap.py) starts
   SD on a build machine that has never had the installer near it, so sdusers
   does not exist there.  Falling back to SYSTEM and Administrators is exactly
   right for that case: the bootstrap is elevated and nobody else is involved.

   25 Sep 26 SD Core Solo (SOLO 4) - SYSTEM AND THE CALLER'S OWN USER SID, NOT
   Administrators and a group; everything above describes the multi-user
   product.  MEASURED: the first unelevated bootstrap died at "sdwind: Error 5
   getting semaphores" - sd -start created the set and sdwind, the SAME user,
   could not open it: an unelevated token carries Administrators deny-only and
   Solo has no sdusers, so no ACE matched.  Solo's server is the one user's
   (rulings 1 and 11), so every process opening these is that user - or
   SYSTEM, kept for SOLO 3's daemon.  The group argument is ignored.         */

static PSECURITY_DESCRIPTOR build_descriptor(const char* group) {
  char sddl[256];
  char* user_sid = NULL;
  PSECURITY_DESCRIPTOR sd = NULL;
  HANDLE tok = NULL;
  BYTE buf[256];
  DWORD len = 0;

  (void)group;

  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
    if (GetTokenInformation(tok, TokenUser, buf, sizeof(buf), &len))
      ConvertSidToStringSidA(((TOKEN_USER*)buf)->User.Sid, &user_sid);
    CloseHandle(tok);
  }

  /* No SID, no descriptor: refusing to create the set beats creating one that
     nobody but SYSTEM can open, which is the failure this replaced.         */
  if (user_sid == NULL)
    return NULL;

  if (strlen(user_sid) + strlen("D:(A;;GA;;;SY)(A;;GA;;;)") >= sizeof(sddl)) {
    LocalFree(user_sid);
    return NULL;
  }
  sprintf(sddl, "D:(A;;GA;;;SY)(A;;GA;;;%s)", user_sid);
  LocalFree(user_sid);

  if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
          sddl, SDDL_REVISION_1, &sd, NULL))
    return NULL;

  return sd;
}

/* ====================================================================== */

void* w32sem_create(const char* name, const char* group, int* already_exists) {
  SECURITY_ATTRIBUTES sa;
  PSECURITY_DESCRIPTOR sd;
  HANDLE h;

  if (already_exists != NULL)
    *already_exists = 0;

  sd = build_descriptor(group);
  if (sd == NULL)
    return NULL;

  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = sd;
  sa.bInheritHandle = FALSE;

  /* Binary: initial one, maximum one, matching the POSIX set this replaced. */
  h = CreateSemaphoreA(&sa, 1, 1, name);

  /* GetLastError() is meaningful even when the call succeeded, and reading it
     has to happen before anything else can overwrite it - LocalFree included. */
  if (h != NULL && already_exists != NULL &&
      GetLastError() == ERROR_ALREADY_EXISTS)
    *already_exists = 1;

  {
    DWORD saved = GetLastError();
    LocalFree(sd);
    SetLastError(saved);
  }

  return (void*)h;
}

void* w32sem_open(const char* name) {
  return (void*)OpenSemaphoreA(SEMAPHORE_ALL_ACCESS, FALSE, name);
}

void w32sem_close(void* handle) {
  if (handle != NULL)
    CloseHandle((HANDLE)handle);
}

int w32sem_trywait(void* handle) {
  return (WaitForSingleObject((HANDLE)handle, 0) == WAIT_OBJECT_0);
}

void w32sem_post(void* handle) {
  ReleaseSemaphore((HANDLE)handle, 1, NULL);
}

unsigned long w32sem_last_error(void) {
  return (unsigned long)GetLastError();
}

int w32sem_absent(unsigned long err) {
  return (err == (unsigned long)ERROR_FILE_NOT_FOUND);
}

/* END-CODE */
