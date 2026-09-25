/* WIN32TOKEN.H
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
 * Plain C types only, so sd.c can include it without windows.h (win32token.c
 * says why the two cannot meet).
 *
 * win32_drop_admin() returns
 *    0  the token is already standard (below High integrity): carry on;
 *    1  a filtered child ran this same command line; *exit_code is its exit
 *       code, and the caller must exit with it;
 *   -1  it could not be done, or the child would still be an administrator;
 *       why says which, and the caller must NOT carry on.
 *
 * END-DESCRIPTION
 *
 * START-CODE
 */

#ifndef __WIN32TOKEN
#define __WIN32TOKEN

#include <stddef.h>

int win32_drop_admin(int* exit_code, char* why, size_t whylen);

#endif

/* END-CODE */
