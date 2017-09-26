
win-sftp-server.exe: win-sftp-server.c
	gcc -municode -g -O0 -Wall -o win-sftp-server.exe win-sftp-server.c -l ws2_32

test:
	perl -Mlib::glob=~/g/perl/*/lib test.pl -i -s
