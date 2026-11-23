/* WIN32AI.H
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
 * 16 Nov 26 SD Core Solo - RELEASE_1.1 246: from SD Core for Windows' win32ai.h
 *           (13 Nov 26, the pipe \\.\pipe\sd-ai), in Linux Solo's same-user
 *           form: there is no service and no pipe server here, so win32_ai_open()
 *           STARTS the helper (sd-ai.exe --one, beside the running program) on
 *           anonymous pipes and takes no name; WIN32_AI_NOTOURS is gone with the
 *           pipe-owner check; win32_ai_cancel() is new (ends the helper at once),
 *           and win32_ai_close() now lets a helper that has answered finish.
 * END-HISTORY
 *
 * START-DESCRIPTION:
 *
 * NOTHING IN THIS INTERFACE IS A WINDOWS TYPE, the rule every win32*.h keeps
 * (win32peer.h says why): a request is a small SLOT NUMBER, never a HANDLE.
 *
 * ***AND THE HANDLES NEVER ENTER THE MSYS2 DESCRIPTOR TABLE.***  A pipe pushed
 * there with cygwin_attach_handle_to_fd() is reported permanently ready by
 * select() (measured 17 Aug 2026, win32peer.h), which would make a poll spin.
 * So readiness is asked of the pipe itself, with PeekNamedPipe, which answers
 * for an anonymous pipe as for a named one (win32ai.c says what was measured).
 *
 * A slot is one helper process and its two pipes: the request goes in on the
 * helper's standard input, the reply comes back on its standard output.
 *
 * END-DESCRIPTION
 */

#ifndef WIN32AI_H
#define WIN32AI_H

#define WIN32_AI_NONE   (-1) /* the helper could not be started (not there, no free slot, no pipes, CreateProcess refused) */

/* Start the helper (<the running program's own folder>\sd-ai.exe --one) for one request.  Returns a slot (0 or more) or WIN32_AI_NONE. */
int win32_ai_open(void);

/* Write all len bytes.  1 when all were taken; 0 when the helper took none for wait_ms at a stretch, or the pipe broke. */
int win32_ai_write(int slot, const char* buf, int len, int wait_ms);

/* Bytes waiting to be read (0 or more), or -1 when the helper has closed its end and nothing is left, or -2 on another error.  Never blocks. */
int win32_ai_avail(int slot);

/* Read at most len bytes that win32_ai_avail() said were there.  Returns the count, 0 at the end, -1 on an error.  Never blocks. */
int win32_ai_read(int slot, char* buf, int len);

/* The normal end, after the reply line was read: close both pipes, give the helper a moment to finish (its log line), end it if it has not,
   and close its process handle.  A slot already closed, or -1, is ignored. */
void win32_ai_close(int slot);

/* Give the request up: end the helper at once (TerminateProcess) and close every handle.  A slot already closed, or -1, is ignored. */
void win32_ai_cancel(int slot);

#endif

/* END-CODE */
