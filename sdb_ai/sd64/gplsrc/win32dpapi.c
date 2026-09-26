/* WIN32DPAPI.C
 * Native Windows half of SD Core Solo's stored account password: encrypt and
 * decrypt with DPAPI for the Windows user this process runs as.
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
 * 25 Sep 26 SD Core Solo - new, SOLO 15 piece 4 (ruling 21).
 * END-HISTORY
 *
 * START-DESCRIPTION:
 *
 * This file includes windows.h and NO SD header, as win32tls.c and
 * win32relay.c do and for the same reason.  Its interface is declared in
 * sd_scram.h with no Windows type in it; op_sdext.c calls it (SD_DPAPI_PROTECT
 * and SD_DPAPI_UNPROTECT) with base64 on the BASIC side.
 *
 * WHAT IT IS FOR.  Ruling 21: every session proves the account password, and
 * a one-shot "sd <command>" - a scheduled job - must never stop to ask.  So
 * the account password is kept encrypted with DPAPI in CurrentUser scope:
 * only this Windows user can decrypt it, on this computer; a tree copied to
 * another user or machine carries a blob nobody there can open, and login
 * falls back to asking.  The installer (solo_password ACCOUNT) and
 * SET.PASSWORD write it; login's one-shot path reads it.
 *
 * THE OPTIONAL ENTROPY is a fixed string, so a blob made by another program
 * for the same user cannot be handed to SD and decrypted as if it were SD's.
 * CRYPTPROTECT_UI_FORBIDDEN: nothing here may ever show a dialog.
 *
 * NOT MEASURED WHEN WRITTEN: whether a task registered with the S4U logon type
 * (no stored password) can decrypt CurrentUser DPAPI data - S4U logons may
 * have no access to the user's DPAPI master key.  A scheduled one-shot job
 * that uses the stored password should be registered to run with the user's
 * password, or tested first.
 *
 * END-DESCRIPTION
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <stdlib.h>
#include <string.h>

/* Declared in sd_scram.h; repeated so this file includes no SD header. */
int win32_dpapi_protect(const char* text, unsigned char** blob, size_t* bloblen);
char* win32_dpapi_unprotect(const unsigned char* blob, size_t bloblen);

static const char entropy_text[] = "SD Core Solo stored account password";

/* Encrypt TEXT for this Windows user.  1 with *blob malloc'd (caller frees),
   0 on any failure, with *blob NULL. */
int win32_dpapi_protect(const char* text, unsigned char** blob, size_t* bloblen) {
  DATA_BLOB in;
  DATA_BLOB out;
  DATA_BLOB ent;

  *blob = NULL;
  *bloblen = 0;
  if (text == NULL || text[0] == '\0')
    return 0;
  in.pbData = (BYTE*)text;
  in.cbData = (DWORD)strlen(text);
  ent.pbData = (BYTE*)entropy_text;
  ent.cbData = (DWORD)(sizeof(entropy_text) - 1);
  out.pbData = NULL;
  out.cbData = 0;
  if (!CryptProtectData(&in, L"SD Core Solo", &ent, NULL, NULL,
                        CRYPTPROTECT_UI_FORBIDDEN, &out))
    return 0;
  *blob = (unsigned char*)malloc(out.cbData);
  if (*blob == NULL) {
    LocalFree(out.pbData);
    return 0;
  }
  memcpy(*blob, out.pbData, out.cbData);
  *bloblen = out.cbData;
  LocalFree(out.pbData);
  return 1;
}

/* Decrypt a blob made above.  The text, malloc'd and NUL-terminated (caller
   frees and should wipe it), or NULL when this Windows user cannot open it -
   another user's blob, another computer's, damaged, or not SD's. */
char* win32_dpapi_unprotect(const unsigned char* blob, size_t bloblen) {
  DATA_BLOB in;
  DATA_BLOB out;
  DATA_BLOB ent;
  char* text;

  if (blob == NULL || bloblen == 0)
    return NULL;
  in.pbData = (BYTE*)blob;
  in.cbData = (DWORD)bloblen;
  ent.pbData = (BYTE*)entropy_text;
  ent.cbData = (DWORD)(sizeof(entropy_text) - 1);
  out.pbData = NULL;
  out.cbData = 0;
  if (!CryptUnprotectData(&in, NULL, &ent, NULL, NULL,
                          CRYPTPROTECT_UI_FORBIDDEN, &out))
    return NULL;
  text = (char*)malloc(out.cbData + 1);
  if (text != NULL) {
    memcpy(text, out.pbData, out.cbData);
    text[out.cbData] = '\0';
  }
  SecureZeroMemory(out.pbData, out.cbData);
  LocalFree(out.pbData);
  return text;
}

/* END-CODE */
