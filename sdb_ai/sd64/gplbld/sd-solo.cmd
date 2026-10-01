@echo off
rem sd-solo.cmd - start SD Core Solo for Windows by name.
rem
rem 01 Oct 26 - THE OWNER'S COMMAND NAMES.  "sd" and "sd-full" start the full
rem product when it and SD Core Solo are both installed; "sd-solo" starts Solo;
rem with only one of them installed, "sd" starts that one.
rem
rem This is a second name for the sd.exe BESIDE THIS FILE, so it cannot reach
rem another product's install.  Solo keeps its own sd.exe too: when Solo is the
rem only product installed, plain "sd" finds it.  When the full product is
rem installed as well, plain "sd" finds the full product's first, because it is
rem on the system PATH and Solo is on the user's, which Windows searches after
rem the system one (measured on this machine, 1 Oct 2026) - so this name is how
rem to ask for Solo.  It is a text file and not a copy of the program on purpose:
rem this repository ships no binary, and a second sd.exe would be a second file
rem for the installer to keep current.
"%~dp0sd.exe" %*
exit /b %ERRORLEVEL%
