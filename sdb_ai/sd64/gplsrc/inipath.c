/* INIPATH.C
 * Get system paths
 * Copyright (c) 2004 Ladybridge Systems, All Rights Reserved
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
 * 25 Sep 26 SD Core Solo - everything is found from the installation's own
 *                      folder (GetHomePath); no machine path is compiled in
 * 14 Aug 26 Windows port - SD_CONFIG replaces SCARLET_CONFIG, and the
 *                      fallback is the Windows location rather than /etc
 * 31 Dec 23 SD launch - prior history suppressed
 * END-HISTORY
 *
 * START-DESCRIPTION:
 *
 * GetConfigPath() answers where sd.conf is.
 *
 * AN INSTALLED SYSTEM MUST FIND IT WITH NOTHING SET IN THE ENVIRONMENT.  It
 * did not: the fallback was "/etc/sd.conf", and once the binaries ship with
 * msys-2.0.dll beside them the POSIX root moves to C:\Program Files\SD\, so
 * /etc/sd.conf resolves INSIDE Program Files - read-only to ordinary users,
 * and separated from the data it describes.  Installing therefore required
 * setting an environment variable by hand, which is not an install.
 * See PROJECT_STATUS.md 5.8 and 5.16.
 *
 * The variable is SD_CONFIG.  It was SCARLET_CONFIG here while the client
 * library read SD_CONFIG, with a comment in the client wrongly claiming the
 * two matched - so setting the one you would expect fixed exactly one of
 * them.  SCARLET_CONFIG is not read any more; it named a project this is no
 * longer part of.
 *
 * SD CORE SOLO (25 Sep 2026, owner's choice of layout): THE HOME IS WHERE THE
 * PROGRAMS ARE.  Solo installs into one folder, %USERPROFILE%\SDCoreSolo, with
 * the programs and msys-2.0.dll in its usr\bin, so the home is the folder two
 * above the running executable.  sd.conf is <home>\sd.conf, SDSYS defaults to
 * <home>\sdsys and the account folders sit beside it; nothing holds the
 * user's path, so the tree works wherever it is put.
 *
 * FROM THE EXECUTABLE'S OWN PATH, NOT FROM THE POSIX ROOT - measured, and the
 * first version got it wrong.  It asked the runtime for "/", which is the
 * folder two above msys-2.0.dll when sd.exe is started natively.  But sd.exe
 * started BY ANOTHER MSYS2 PROCESS (the bootstrap's python, and so Git Bash)
 * inherits that parent's mount table: 25 Sep 2026, run from MSYS2 python,
 * "sd -start" reported "C:/msys64/sd.conf not found".  /proc/self/exe
 * converted by cygwin_conv_path() is right under any mount table, because the
 * two use the same one.  And the executable must be in a folder named usr\bin,
 * or this refuses: a guess at the home from an exe somewhere else is worse
 * than an error, and a development run from sdb_ai/sd64/bin sets SD_CONFIG.
 *
 * /dev/shm is <root>\dev\shm with no fstab (measured 25 Sep 2026: shm_open()
 * works once that directory exists and fails without it).  That IS the POSIX
 * root, so an sd.exe started from an MSYS2 shell would put its segment under
 * that shell's root instead - open, SOLO 2 in PROJECT_STATUS.md.
 *
 * END-CODE
 */

#include "sd.h"

#include <sys/cygwin.h>
#include <unistd.h>  /* readlink() */

/* ======================================================================
   GetHomePath()  -  The installation's own folder, as a Windows path with
                     no trailing separator.  FALSE if it cannot be had;
                     callers must fail rather than guess.                   */

bool GetHomePath(char* buff, int buff_len) {
  char exe[MAX_PATHNAME_LEN + 1];
  char* p;
  ssize_t n;
  int i;
  static const char* const expect[2] = {"bin", "usr"};

  if ((buff == NULL) || (buff_len < 4))
    return FALSE;

  n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
  if ((n <= 0) || (n >= (ssize_t)sizeof(exe) - 1))
    return FALSE;
  exe[n] = '\0';

  if (cygwin_conv_path(CCP_POSIX_TO_WIN_A | CCP_ABSOLUTE, exe, buff,
                       (size_t)buff_len) != 0)
    return FALSE;

  /* <home>\usr\bin\sd  ->  <home>.  Strip the name, then insist on bin and
     usr, so an executable anywhere else is refused rather than guessed at. */

  if ((p = strrchr(buff, '\\')) == NULL)
    return FALSE;
  *p = '\0';

  for (i = 0; i < 2; i++) {
    if (((p = strrchr(buff, '\\')) == NULL) || (p == buff) ||
        (stricmp(p + 1, expect[i]) != 0))
      return FALSE;
    *p = '\0';
  }

  /* A home at a drive root is "C:", which callers' "\name" completes.     */

  return (buff[0] != '\0');
}

/* ======================================================================
   GetDefaultSysdir()  -  <home>\sdsys, used when sd.conf names no SDSYS    */

bool GetDefaultSysdir(char* buff, int buff_len) {
  char home[MAX_PATHNAME_LEN + 1];

  if (!GetHomePath(home, sizeof(home)))
    return FALSE;

  return (snprintf(buff, (size_t)buff_len, "%s\\sdsys", home) < buff_len);
}

/* ====================================================================== */

bool GetConfigPath(char *inipath) {
  char home[MAX_PATHNAME_LEN + 1];

  char* p;

  /* Callers pass a buffer of MAX_PATHNAME_LEN + 1.  Nothing here may write
     more than that.                                                        */

  p = getenv(SD_CONFIG_ENV);
  if ((p != NULL) && (*p != '\0')) {
    snprintf(inipath, MAX_PATHNAME_LEN + 1, "%s", p);
    return TRUE;
  }

  if (!GetHomePath(home, sizeof(home))) {
    fprintf(stderr, "Cannot determine the SD Core Solo folder.\n");
    return FALSE;
  }

  return (snprintf(inipath, MAX_PATHNAME_LEN + 1, "%s\\sd.conf", home)
          < MAX_PATHNAME_LEN + 1);
}

/* END-CODE */
