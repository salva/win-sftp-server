
sftp-server.exe: sftp-server.c
	/usr/bin/i686-w64-mingw32-gcc-6.2-win32 -municode -g -O0 -Wall -o sftp-server.exe sftp-server.c

test:
	perl -Mlib::glob=~/g/perl/*/lib test.pl -i -s
