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
 * the programs and msys-2.0.dll in its usr\bin.  The MSYS2 runtime already
 * makes the folder two above that DLL the POSIX root "/" (PROJECT_STATUS.md 6),
 * so "/" IS the home, and asking the runtime for it keeps one rule rather than
 * two.  sd.conf is <home>\sd.conf, SDSYS defaults to <home>\sdsys and the
 * account folders sit beside it; nothing holds the user's path, so the tree
 * works wherever it is put.  /dev/shm is <home>\dev\shm with no fstab -
 * measured 25 Sep 2026: shm_open() works once that directory exists and
 * fails without it.
 *
 * SD_CONFIG still overrides, and a development run from sdb_ai/sd64/bin needs
 * it: there the DLL is MSYS2's own and the root is C:\msys64.
 *
 * END-CODE
 */

#include "sd.h"

#include <sys/cygwin.h>

/* ======================================================================
   GetHomePath()  -  The installation's own folder, as a Windows path with
                     no trailing separator.  FALSE if it cannot be had;
                     callers must fail rather than guess.                   */

bool GetHomePath(char* buff, int buff_len) {
  size_t n;

  if ((buff == NULL) || (buff_len < 4))
    return FALSE;

  if (cygwin_conv_path(CCP_POSIX_TO_WIN_A | CCP_ABSOLUTE, "/", buff,
                       (size_t)buff_len) != 0)
    return FALSE;

  /* A drive root comes back as "C:\"; everything else without a separator.
     Strip it so callers can always append "\name".                         */

  n = strlen(buff);
  if ((n > 0) && (buff[n - 1] == '\\'))
    buff[n - 1] = '\0';

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
