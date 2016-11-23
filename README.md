# SFTP server for MS-Windows

This project is a fork of [OpenSSH](http://www.openssh.com/)
`sftp-server` which calls directly into the Win32 API, instead of
using any other POSIX/Unix/Linux/C emulation layer (i.e. Cygwin).

Note that it does not implement or provide the SSH layer.

## Compilation

The `sftp-server.exe` program is compiled using MinGW-w64.

The included `Makefile` works in recents Ubuntus. But it should be
pretty easy to compile it in any other environment with minor tweaks.

## Caveats

* File ownership and permissions

The filesystem ownership and permissions model supported by the SFTP
protocol version 3, does not fit the one provided by Windows (for
instance, it doesn't use integers as user -uid- an group -gid-
identificators, neither has it the concept of user, group and other
permissions.

As such, file system permissions appear always as 0700 or 0600 and no
ownership information is transmitted to the SFTP client.

Conversely, on write operations, permission and ownership information
is not influenced by the information comming from the client.

* File name encoding

Automatic translation of the UTF-16
([WTF-16](https://simonsapin.github.io/wtf-8/#wtf-16)?) encoding used
natively in Windows file systems and UTF-8 is performed on the fly.

That means that there are some file names, valid on Windows that will
fail to be converted to UTF-8 (moving to
[WTF-8](https://simonsapin.github.io/wtf-8) encoding is in the TODO
list.

* Path length

Path length is limited to the 260 characters supported by the Win32
API.

On recent versions of Windows 10, this limitation can be overcome
[editing some registry entries](http://www.howtogeek.com/266621/how-to-make-windows-10-accept-file-paths-over-260-characters/).

* Symbolic links

Symbolic links work as long as the underlaying file system supports
then and the logged user has the required permissions... which is
pretty unlikely!

## Copyright and Licence

This program is based on the OpenSSH `sftp-server` code and uses the
same license (see [OpenSSH-LICENCE](./OpenSSH-LICENCE)).

   * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland.
   * Copyright (c) 1999-2008 Markus Friedl. All rigths reserved.
   * Copyright (c) 2001-2012 Damien Miller. All rigths reserved.
   * Copyright (c) 2016 Qindel Formacion y Servicios SL. All rigths reserved.
