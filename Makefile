
win-sftp-server.exe: win-sftp-server.c
	/usr/bin/i686-w64-mingw32-gcc-win32 -municode -g -O0 -Wall -o win-sftp-server.exe win-sftp-server.c -l ws2_32

test:
	perl -Mlib::glob=~/g/perl/*/lib test.pl -i -s
