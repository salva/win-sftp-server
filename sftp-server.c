/* $OpenBSD: sftp-server.c,v 1.110 2016/09/12 01:22:38 deraadt Exp $ */
/*
 * Copyright (c) 2000-2004 Markus Friedl.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <windows.h>
#include <strsafe.h>
#include <aclapi.h>

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdint.h>
#include <wchar.h>

#define	SSH2_FILEXFER_VERSION		3

#define SFTP_MAX_MSG_LENGTH	(256 * 1024)

#define SSH2_FXP_INIT			1
#define SSH2_FXP_OPEN			3
#define SSH2_FXP_CLOSE			4
#define SSH2_FXP_READ			5
#define SSH2_FXP_WRITE			6
#define SSH2_FXP_LSTAT			7
#define SSH2_FXP_STAT_VERSION_0		7
#define SSH2_FXP_FSTAT			8
#define SSH2_FXP_SETSTAT		9
#define SSH2_FXP_FSETSTAT		10
#define SSH2_FXP_OPENDIR		11
#define SSH2_FXP_READDIR		12
#define SSH2_FXP_REMOVE			13
#define SSH2_FXP_MKDIR			14
#define SSH2_FXP_RMDIR			15
#define SSH2_FXP_REALPATH		16
#define SSH2_FXP_STAT			17
#define SSH2_FXP_RENAME			18
#define SSH2_FXP_READLINK		19
#define SSH2_FXP_SYMLINK		20

/* server to client */
#define SSH2_FXP_VERSION		2
#define SSH2_FXP_STATUS			101
#define SSH2_FXP_HANDLE			102
#define SSH2_FXP_DATA			103
#define SSH2_FXP_NAME			104
#define SSH2_FXP_ATTRS			105

#define SSH2_FXP_EXTENDED		200
#define SSH2_FXP_EXTENDED_REPLY		201

/* attributes */
#define SSH2_FILEXFER_ATTR_SIZE		0x00000001
#define SSH2_FILEXFER_ATTR_UIDGID	0x00000002
#define SSH2_FILEXFER_ATTR_PERMISSIONS	0x00000004
#define SSH2_FILEXFER_ATTR_ACMODTIME	0x00000008
#define SSH2_FILEXFER_ATTR_EXTENDED	0x80000000

/* portable open modes */
#define SSH2_FXF_READ			0x00000001
#define SSH2_FXF_WRITE			0x00000002
#define SSH2_FXF_APPEND			0x00000004
#define SSH2_FXF_CREAT			0x00000008
#define SSH2_FXF_TRUNC			0x00000010
#define SSH2_FXF_EXCL			0x00000020

/* status messages */
#define SSH2_FX_OK			0
#define SSH2_FX_EOF			1
#define SSH2_FX_NO_SUCH_FILE		2
#define SSH2_FX_PERMISSION_DENIED	3
#define SSH2_FX_FAILURE			4
#define SSH2_FX_BAD_MESSAGE		5
#define SSH2_FX_NO_CONNECTION		6
#define SSH2_FX_CONNECTION_LOST		7
#define SSH2_FX_OP_UNSUPPORTED		8
#define SSH2_FX_MAX			8

#define SSH_ERR_ALLOC_FAIL			-2
#define SSH_ERR_MESSAGE_INCOMPLETE		-3
#define SSH_ERR_INVALID_FORMAT			-4
#define SSH_ERR_STRING_TOO_LARGE		-6
#define SSH_ERR_NO_BUFFER_SPACE			-9
#define SSH_ERR_BUFFER_READ_ONLY		-49

typedef enum {
	LOG_LEVEL_QUIET,
	LOG_LEVEL_FATAL,
	LOG_LEVEL_ERROR,
	LOG_LEVEL_INFO,
	LOG_LEVEL_VERBOSE,
	LOG_LEVEL_DEBUG1,
	LOG_LEVEL_DEBUG2,
	LOG_LEVEL_DEBUG3,
	LOG_LEVEL_NOT_SET = -1
}       LogLevel;

typedef unsigned int uint;

typedef struct {
	uint32_t	flags;
	uint64_t	size;
	uint32_t	uid;
	uint32_t	gid;
	uint32_t	perm;
	uint32_t	atime;
	uint32_t	mtime;
} Attrib;

#define SSHBUF_SIZE_MAX		0x8000000	/* Hard maximum size */

struct sshbuf {
	uint8_t *d;		/* Data */
	size_t off;		/* First available byte is buf->d + buf->off */
	size_t size;		/* Last byte is buf->d + buf->size - 1 */
	size_t max_size;	/* Maximum size of buffer */
	size_t alloc;		/* Total bytes allocated to buf->d */
};

/* Our verbosity */
static LogLevel log_level = 0; //LOG_LEVEL_ERROR;

static char *client_addr = NULL;

/* input and output queue */
struct sshbuf *iqueue;
struct sshbuf *oqueue;

/* Version of client */
static uint version;

/* SSH2_FXP_INIT received */
static int init_done;

/* Disable writes */
static int readonly;

/* Requests that are allowed/denied */
static char *request_whitelist, *request_blacklist;

/* portable attributes, etc. */
typedef struct Stat Stat;

struct Stat {
	wchar_t *name;
	wchar_t *long_name;
	Attrib attrib;
};

/* Packet handlers */
static void process_open(uint32_t id);
static void process_close(uint32_t id);
static void process_read(uint32_t id);
static void process_write(uint32_t id);
static void process_stat(uint32_t id);
static void process_lstat(uint32_t id);
static void process_fstat(uint32_t id);
static void process_setstat(uint32_t id);
static void process_fsetstat(uint32_t id);
static void process_opendir(uint32_t id);
static void process_readdir(uint32_t id);
static void process_remove(uint32_t id);
static void process_mkdir(uint32_t id);
static void process_rmdir(uint32_t id);
static void process_realpath(uint32_t id);
static void process_rename(uint32_t id);
static void process_readlink(uint32_t id);
static void process_symlink(uint32_t id);
static void process_extended_posix_rename(uint32_t id);
static void process_extended_hardlink(uint32_t id);
static void process_extended_fsync(uint32_t id);
static void process_extended(uint32_t id);

struct sftp_handler {
	const char *name;	/* user-visible name for fine-grained perms */
	const char *ext_name;	/* extended request name */
	uint type;		/* packet type, for non extended packets */
	void (*handler)(uint32_t);
	int does_write;		/* if nonzero, banned for readonly mode */
};

struct sftp_handler handlers[] = {
	/* NB. SSH2_FXP_OPEN does the readonly check in the handler itself */
	{ "open", NULL, SSH2_FXP_OPEN, process_open, 0 },
	{ "close", NULL, SSH2_FXP_CLOSE, process_close, 0 },
	{ "read", NULL, SSH2_FXP_READ, process_read, 0 },
	{ "write", NULL, SSH2_FXP_WRITE, process_write, 1 },
	{ "lstat", NULL, SSH2_FXP_LSTAT, process_lstat, 0 },
	{ "fstat", NULL, SSH2_FXP_FSTAT, process_fstat, 0 },
	{ "setstat", NULL, SSH2_FXP_SETSTAT, process_setstat, 1 },
	{ "fsetstat", NULL, SSH2_FXP_FSETSTAT, process_fsetstat, 1 },
	{ "opendir", NULL, SSH2_FXP_OPENDIR, process_opendir, 0 },
	{ "readdir", NULL, SSH2_FXP_READDIR, process_readdir, 0 },
	{ "remove", NULL, SSH2_FXP_REMOVE, process_remove, 1 },
	{ "mkdir", NULL, SSH2_FXP_MKDIR, process_mkdir, 1 },
	{ "rmdir", NULL, SSH2_FXP_RMDIR, process_rmdir, 1 },
	{ "realpath", NULL, SSH2_FXP_REALPATH, process_realpath, 0 },
	{ "stat", NULL, SSH2_FXP_STAT, process_stat, 0 },
	{ "rename", NULL, SSH2_FXP_RENAME, process_rename, 1 },
	{ "readlink", NULL, SSH2_FXP_READLINK, process_readlink, 0 },
	{ "symlink", NULL, SSH2_FXP_SYMLINK, process_symlink, 1 },
	{ NULL, NULL, 0, NULL, 0 }
};

/* SSH2_FXP_EXTENDED submessages */
struct sftp_handler extended_handlers[] = {
	{ "posix-rename", "posix-rename@openssh.com", 0,
	   process_extended_posix_rename, 1 },
	{ "hardlink", "hardlink@openssh.com", 0, process_extended_hardlink, 1 },
	{ "fsync", "fsync@openssh.com", 0, process_extended_fsync, 1 },
	{ NULL, NULL, 0, NULL, 0 }
};

static void fatal(const char *, ...) __attribute__((noreturn)) __attribute__((format(printf, 1, 2)));
static void verbose(const char *fmt, ...);
static void debug3(const char *fmt,...);
static void do_log(LogLevel level, const char *fmt, va_list args);

static void cleanup_exit(int) __attribute__((noreturn));

#define MINIMUM(a, b) (((a) < (b)) ? (a) : (b))
#define MAXIMUM(a, b) (((a) > (b)) ? (a) : (b))
#define HOWMANY(x, y) (((x)+((y)-1))/(y))
#define ROUNDUP(x, y) (HOWMANY(x, y) * (y))

//#define SIZE_MAX ((unsigned long)-1)

static size_t
strlcat(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;
	size_t dlen;

	/* Find the end of dst and adjust bytes left but don't go past end */
	while (n-- != 0 && *d != '\0')
		d++;
	dlen = d - dst;
	n = siz - dlen;

	if (n == 0)
		return(dlen + strlen(s));
	while (*s != '\0') {
		if (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';

	return(dlen + (s - src));	/* count does not include NUL */
}

#define S_ISUID 2048
#define S_ISGID 1024
#define S_ISVTX 512
//#define S_IRGRP 32
//#define S_IWGRP 16
//#define S_IXGRP 8
//#define S_IROTH 4
//#define S_IWOTH 2
//#define S_IXOTH 1

void
file_info_to_str(BY_HANDLE_FILE_INFORMATION *info, wchar_t *p)
{

        DWORD attrib = info->dwFileAttributes;
	int is_dir = 0;

	if (attrib & FILE_ATTRIBUTE_DIRECTORY) {
		*p++ = 'd';
		is_dir = 1;
	}
	else if (attrib & FILE_ATTRIBUTE_NORMAL)
		*p++ = '-';
	else
		*p++ = '?';

	if (is_dir)
		*p++ = 'x';
	else
		*p++ = '-';

	*p++ = 'r';
	*p++ = 'w';
        wmemcpy(p, L"------ ", 8);
}

/* static int */
/* vasprintf(char **str, const char *fmt, va_list ap) */
/* { */
/* 	const int INIT_SZ = 128; */
/* 	int ret = -1; */
/* 	va_list ap2; */
/* 	char *string, *newstr; */
/* 	size_t len; */

/* 	va_copy(ap2, ap); */
/* 	if ((string = malloc(INIT_SZ)) == NULL) */
/* 		goto fail; */

/* 	ret = vsnprintf(string, INIT_SZ, fmt, ap2); */
/* 	if (ret >= 0 && ret < INIT_SZ) { /\* succeeded with initial alloc *\/ */
/* 		*str = string; */
/* 	} else if (ret == INT_MAX || ret < 0) { /\* Bad length *\/ */
/* 		xfree(string); */
/* 		goto fail; */
/* 	} else {	/\* bigger than initial, realloc allowing for nul *\/ */
/* 		len = (size_t)ret + 1; */
/* 		if ((newstr = realloc(string, len)) == NULL) { */
/* 			xfree(string); */
/* 			goto fail; */
/* 		} else { */
/* 			va_end(ap2); */
/* 			va_copy(ap2, ap); */
/* 			ret = vsnprintf(newstr, len, fmt, ap2); */
/* 			if (ret >= 0 && (size_t)ret < len) { */
/* 				*str = newstr; */
/* 			} else { /\* failed with realloc'ed string, give up *\/ */
/* 				xfree(newstr); */
/* 				goto fail; */
/* 			} */
/* 		} */
/* 	} */
/* 	va_end(ap2); */
/* 	return (ret); */

/* fail: */
/* 	*str = NULL; */
/* 	va_end(ap2); */
/* 	fatal("vasprintf: out of memory"); */
/* } */

#define tell_error(msg) verbose("%s: %lu at %s", (msg), GetLastError(), __func__)
#define fatal_error(msg) fatal("%s: %lu at %s", (msg), GetLastError(), __func__)

static void *
xmalloc(size_t size)
{
	void *ptr;

	if (size == 0)
		fatal("xmalloc: zero size");
	ptr = HeapAlloc(GetProcessHeap(), 0, size);
	if (ptr == NULL)
		fatal_error("HeapAlloc failed");
	return ptr;
}

static void
xfree(void *ptr) {
	if (!HeapFree(GetProcessHeap(), 0, ptr))
		fatal_error("HeapFree failed");
}

static void *
xcalloc(size_t nmemb, size_t size)
{
	void *ptr;

	if (size == 0 || nmemb == 0)
		fatal("xcalloc: zero size");
	if (SIZE_MAX / nmemb < size)
		fatal("xcalloc: nmemb * size > SIZE_MAX");
	ptr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nmemb * size);
	if (ptr == NULL)
		fatal_error("HeapAlloc failed");
	return ptr;
}

#define MUL_NO_OVERFLOW	((size_t)1 << (sizeof(size_t) * 4))

static void *
xmallocarray(size_t nmemb, size_t size)
{
	if ((nmemb < MUL_NO_OVERFLOW && size < MUL_NO_OVERFLOW) ||
	    nmemb == 0 || SIZE_MAX / nmemb > size)
		return xmalloc(size * nmemb);

	fatal("xmallocarray: arguments out of limits, %u elements of %u bytes",
	      nmemb, size);
}

static wchar_t *
xwcsalloc(size_t nmemb) {
        return xmallocarray(nmemb, sizeof(wchar_t));
}

static char *
xstrdup(const char *str)
{
	size_t len;
	char *cp;
	if (str == NULL)
		fatal("xstrdup: NULL pointer");
	len = strlen(str) + 1;
	cp = xmalloc(len);
	memcpy(cp, str, len);
	return cp;
}

static wchar_t *
xwcsdup(const wchar_t *wstr)
{
	if (wstr == NULL) fatal("xwcsdup: NULL pointer");

        size_t len = wcslen(wstr) + 1;
        wchar_t *cp = xwcsalloc(len);
	wmemcpy(cp, wstr, len);
	return cp;
}

static void *
xcopyarray(const void *data, size_t nmenb, size_t size) {
        void *cp = xmallocarray(nmenb, size);
        memcpy(cp, data, nmenb * size);
        return cp;
}

static wchar_t *
xwcopy(const wchar_t *data, size_t size) {
        return (wchar_t *)xcopyarray(data, size, sizeof(wchar_t));
}

/* static int */
/* xasprintf(char **ret, const char *fmt, ...) */
/* { */
/* 	va_list ap; */
/* 	int i; */

/* 	va_start(ap, fmt); */
/* 	i = vasprintf(ret, fmt, ap); */
/* 	va_end(ap); */

/* 	if (i < 0 || *ret == NULL) */
/* 		fatal("xasprintf: could not allocate memory"); */

/* 	return (i); */
/* } */


static void *
xrealloc(void *ptr, size_t size) {
	void *new_ptr = (ptr
			 ? HeapReAlloc(GetProcessHeap(), 0, ptr, size)
			 : HeapAlloc(GetProcessHeap(), 0, size));
	if (new_ptr == NULL)
		fatal_error("HeapReAlloc/HeapAlloc failed");
	return new_ptr;
}

static void *
xreallocarray(void *ptr, size_t nmemb, size_t size)
{
	if ((nmemb < MUL_NO_OVERFLOW && size < MUL_NO_OVERFLOW) ||
	    nmemb == 0 || SIZE_MAX / nmemb > size)
		return xrealloc(ptr, size * nmemb);

	fatal("xreallocarray: arguments out of limits, %u elements of %u bytes",
	      nmemb, size);
}

static wchar_t *
xwcscat(wchar_t *str, wchar_t *cat) {
        size_t str_len = wcslen(str);
        size_t cat_len = wcslen(cat);
        
        wchar_t *cp = xwcsalloc(str_len + cat_len + 1);
        wmemcpy(cp, str, str_len);
        wmemcpy(cp + str_len, cat, cat_len + 1);
        return cp;
}

static wchar_t *
xpathjoin(wchar_t *base, wchar_t *name) {
        // network and other rare paths are forbidden: \\foo\bar, \\?\, \\.\, etc.
        if (name[0] == '\\' && name[1] == '\\') {
                debug3("xpathjoin(%ls, %ls) failed, \\... paths are forbidden", base, name);
                SetLastError(ERROR_BAD_PATHNAME);
                return NULL;
        }

        // volume: C:...
        if (isalpha(name[0]) && name[1] == ':') {
                // volume + absolute path
                if (name[2] == '\0')
                        return xwcscat(name, L"/");
                // just volume: c:
                if (name[2] == '/' || name[2] == '\\')
                        return xwcsdup(name);

                // volume + relative is forbidden: c:foo.txt
                debug3("xpathjoin(%ls, %ls) failed, volume + relative path is forbidden", base, name);
                SetLastError(ERROR_BAD_PATHNAME);
                return NULL;
        }

        // append name to base:
        int base_len  = (base ? wcslen(base) : 0);
        int name_len = wcslen(name);
        if (!base_len)
                return (name_len ? xwcopy(name, name_len + 1) : xwcopy(L".", 2));

        wchar_t *long_name = xwcsalloc(base_len + name_len + 2);
        wmemcpy(long_name, base, base_len);
        if (base[base_len - 1] != '/' && base[base_len - 1] != '\\')
                long_name[base_len++] = '/';
        wmemcpy(long_name + base_len, name, name_len + 1);
        return long_name;
}

static void
fatal(const char *fmt,...)
{
	va_list args;

	va_start(args, fmt);
	do_log(LOG_LEVEL_FATAL, fmt, args);
	va_end(args);
	cleanup_exit(255);
}

static void
do_log(LogLevel level, const char *fmt, va_list args)
{
	char *txt = NULL;
	int saved_error = GetLastError();

	if (level > log_level)
		; //return;

	switch (level) {
	case LOG_LEVEL_FATAL:
		txt = "fatal";
		break;
	case LOG_LEVEL_ERROR:
		txt = "error";
		break;
	case LOG_LEVEL_INFO:
		txt = "info";
		break;
	case LOG_LEVEL_VERBOSE:
		break;
	case LOG_LEVEL_DEBUG1:
		txt = "debug1";
		break;
	case LOG_LEVEL_DEBUG2:
		txt = "debug2";
		break;
	case LOG_LEVEL_DEBUG3:
		txt = "debug3";
		break;
	default:
		txt = "internal error";
		break;
	}
        if (txt)
		fprintf(stderr, "%s: ", txt);
        vfprintf(stderr, fmt, args);
	fprintf(stderr, "\r\n");
        fflush(stderr);
	SetLastError(saved_error);
}

static void
verbose(const char *fmt,...)
{
	va_list args;

	va_start(args, fmt);
	do_log(LOG_LEVEL_VERBOSE, fmt, args);
	va_end(args);
}

static void
logit(const char *fmt,...)
{
	va_list args;

	va_start(args, fmt);
	do_log(LOG_LEVEL_INFO, fmt, args);
	va_end(args);
}

void
error(const char *fmt,...)
{
	va_list args;

	va_start(args, fmt);
	do_log(LOG_LEVEL_ERROR, fmt, args);
	va_end(args);
}

void
debug(const char *fmt,...)
{
	va_list args;

	va_start(args, fmt);
	do_log(LOG_LEVEL_DEBUG1, fmt, args);
	va_end(args);
}

static void
debug3(const char *fmt,...)
{
	va_list args;

	va_start(args, fmt);
	do_log(LOG_LEVEL_DEBUG3, fmt, args);
	va_end(args);
}




/* #define	MAX_PROP	40 */
/* #define	SEP	"," */
/* static char * */
/* match_list(const char *client, const char *server, uint *next) */
/* { */
/* 	char *sproposals[MAX_PROP]; */
/* 	char *c, *s, *p, *ret, *cp, *sp; */
/* 	int i, j, nproposals; */

/* 	c = cp = xstrdup(client); */
/* 	s = sp = xstrdup(server); */

/* 	for ((p = strsep(&sp, SEP)), i=0; p && *p != '\0'; */
/* 	    (p = strsep(&sp, SEP)), i++) { */
/* 		if (i < MAX_PROP) */
/* 			sproposals[i] = p; */
/* 		else */
/* 			break; */
/* 	} */
/* 	nproposals = i; */

/* 	for ((p = strsep(&cp, SEP)), i=0; p && *p != '\0'; */
/* 	    (p = strsep(&cp, SEP)), i++) { */
/* 		for (j = 0; j < nproposals; j++) { */
/* 			if (strcmp(p, sproposals[j]) == 0) { */
/* 				ret = xstrdup(p); */
/* 				if (next != NULL) */
/* 					*next = (cp == NULL) ? */
/* 					    strlen(c) : (uint)(cp - c); */
/* 				xfree(c); */
/* 				xfree(s); */
/* 				return ret; */
/* 			} */
/* 		} */
/* 	} */
/* 	if (next != NULL) */
/* 		*next = strlen(c); */
/* 	xfree(c); */
/* 	xfree(s); */
/* 	return NULL; */
/* } */

static void
debug2(const char *fmt,...)
{
	va_list args;

	va_start(args, fmt);
	do_log(LOG_LEVEL_DEBUG2, fmt, args);
	va_end(args);
}

#define PEEK_U64(p) \
	(((uint64_t)(((const uint8_t *)(p))[0]) << 56) | \
	 ((uint64_t)(((const uint8_t *)(p))[1]) << 48) | \
	 ((uint64_t)(((const uint8_t *)(p))[2]) << 40) | \
	 ((uint64_t)(((const uint8_t *)(p))[3]) << 32) | \
	 ((uint64_t)(((const uint8_t *)(p))[4]) << 24) | \
	 ((uint64_t)(((const uint8_t *)(p))[5]) << 16) | \
	 ((uint64_t)(((const uint8_t *)(p))[6]) << 8) | \
	  (uint64_t)(((const uint8_t *)(p))[7]))
#define PEEK_U32(p) \
	(((uint32_t)(((const uint8_t *)(p))[0]) << 24) | \
	 ((uint32_t)(((const uint8_t *)(p))[1]) << 16) | \
	 ((uint32_t)(((const uint8_t *)(p))[2]) << 8) | \
	  (uint32_t)(((const uint8_t *)(p))[3]))
#define PEEK_U16(p) \
	(((uint16_t)(((const uint8_t *)(p))[0]) << 8) | \
	  (uint16_t)(((const uint8_t *)(p))[1]))

#define POKE_U64(p, v) \
	do { \
		const uint64_t __v = (v); \
		((uint8_t *)(p))[0] = (__v >> 56) & 0xff; \
		((uint8_t *)(p))[1] = (__v >> 48) & 0xff; \
		((uint8_t *)(p))[2] = (__v >> 40) & 0xff; \
		((uint8_t *)(p))[3] = (__v >> 32) & 0xff; \
		((uint8_t *)(p))[4] = (__v >> 24) & 0xff; \
		((uint8_t *)(p))[5] = (__v >> 16) & 0xff; \
		((uint8_t *)(p))[6] = (__v >> 8) & 0xff; \
		((uint8_t *)(p))[7] = __v & 0xff; \
	} while (0)
#define POKE_U32(p, v) \
	do { \
		const uint32_t __v = (v); \
		((uint8_t *)(p))[0] = (__v >> 24) & 0xff; \
		((uint8_t *)(p))[1] = (__v >> 16) & 0xff; \
		((uint8_t *)(p))[2] = (__v >> 8) & 0xff; \
		((uint8_t *)(p))[3] = __v & 0xff; \
	} while (0)
#define POKE_U16(p, v) \
	do { \
		const uint16_t __v = (v); \
		((uint8_t *)(p))[0] = (__v >> 8) & 0xff; \
		((uint8_t *)(p))[1] = __v & 0xff; \
	} while (0)

static uint32_t
get_u32(const void *vp)
{
	const uint8_t *p = (const uint8_t *)vp;
	uint32_t v;

	v  = (uint32_t)p[0] << 24;
	v |= (uint32_t)p[1] << 16;
	v |= (uint32_t)p[2] << 8;
	v |= (uint32_t)p[3];

	return (v);
}

static void
put_u32(void *vp, uint32_t v)
{
	uint8_t *p = (uint8_t *)vp;

	p[0] = (uint8_t)(v >> 24) & 0xff;
	p[1] = (uint8_t)(v >> 16) & 0xff;
	p[2] = (uint8_t)(v >> 8) & 0xff;
	p[3] = (uint8_t)v & 0xff;
}

static int
sshbuf_check_sanity(const struct sshbuf *buf)
{
	if (buf == NULL ||
	    buf->d == NULL ||
	    buf->max_size > SSHBUF_SIZE_MAX ||
	    buf->alloc > buf->max_size ||
	    buf->size > buf->alloc ||
	    buf->off > buf->size) {
		/* Do not try to recover from corrupted buffer internals */
		fatal("Internal error: corrupted buffer at %p", buf);
	}
	return 0;
}

#define SSHBUF_SIZE_INIT 256		/* Initial allocation */
#define SSHBUF_SIZE_INC	256		/* Preferred increment length */
#define SSHBUF_PACK_MIN	8192		/* Minimim packable offset */

static struct sshbuf *
sshbuf_new(void)
{
	struct sshbuf *ret;
	if ((ret = xcalloc(sizeof(*ret), 1)) == NULL)
		return NULL;
	ret->alloc = SSHBUF_SIZE_INIT;
	ret->max_size = SSHBUF_SIZE_MAX;
	if ((ret->d = xcalloc(1, ret->alloc)) == NULL) {
		xfree(ret);
		return NULL;
	}
	return ret;
}

static void
sshbuf_free(struct sshbuf *buf)
{
	if (buf == NULL)
		return;
	/*
	 * The following will leak on insane buffers, but this is the safest
	 * course of action - an invalid pointer or already-freed pointer may
	 * have been passed to us and continuing to scribble over memory would
	 * be bad.
	 */
	if (sshbuf_check_sanity(buf) != 0)
		return;
	/*
	 * If we are a parent with still-extant children, then don't free just
	 * yet. The last child's call to sshbuf_free should decrement our
	 * refcount to 0 and trigger the actual free.
	 */
	memset(buf, 0, sizeof(*buf));
	xfree(buf);
}

static size_t
sshbuf_len(const struct sshbuf *buf)
{
	if (sshbuf_check_sanity(buf) != 0)
		return 0;
	return buf->size - buf->off;
}

static const uint8_t *
sshbuf_ptr(const struct sshbuf *buf)
{
	if (sshbuf_check_sanity(buf) != 0)
		return NULL;
	return buf->d + buf->off;
}

static int
sshbuf_check_reserve(const struct sshbuf *buf, size_t len)
{
	int r;

	if ((r = sshbuf_check_sanity(buf)) != 0)
		return r;
	/* Check that len is reasonable and that max_size + available < len */
	if (len > buf->max_size || buf->max_size - len < buf->size - buf->off)
		return SSH_ERR_NO_BUFFER_SPACE;
	return 0;
}

static void
sshbuf_maybe_pack(struct sshbuf *buf, int force)
{
	if (buf->off == 0)
		return;
	if (force ||
	    (buf->off >= SSHBUF_PACK_MIN && buf->off >= buf->size / 2)) {
		memmove(buf->d, buf->d + buf->off, buf->size - buf->off);
		buf->size -= buf->off;
		buf->off = 0;
	}
}

static int
sshbuf_reserve(struct sshbuf *buf, size_t len, uint8_t **dpp)
{
	size_t rlen, need;
	uint8_t *dp;
	int r;

	if (dpp != NULL)
		*dpp = NULL;

	if ((r = sshbuf_check_reserve(buf, len)) != 0)
		return r;
	/*
	 * If the requested allocation appended would push us past max_size
	 * then pack the buffer, zeroing buf->off.
	 */
	sshbuf_maybe_pack(buf, buf->size + len > buf->max_size);
	if (len + buf->size > buf->alloc) {
		/*
		 * Prefer to alloc in SSHBUF_SIZE_INC units, but
		 * allocate less if doing so would overflow max_size.
		 */
		need = len + buf->size - buf->alloc;
		rlen = ROUNDUP(buf->alloc + need, SSHBUF_SIZE_INC);
		if (rlen > buf->max_size)
			rlen = buf->alloc + need;
		if ((dp = xrealloc(buf->d, rlen)) == NULL) {
			if (dpp != NULL)
				*dpp = NULL;
			return SSH_ERR_ALLOC_FAIL;
		}
		buf->alloc = rlen;
		buf->d = dp;
		if ((r = sshbuf_check_reserve(buf, len)) < 0) {
			/* shouldn't fail */
			if (dpp != NULL)
				*dpp = NULL;
			return r;
		}
	}
	dp = buf->d + buf->size;
	buf->size += len;
	if (dpp != NULL)
		*dpp = dp;
	return 0;
}

int
sshbuf_consume(struct sshbuf *buf, size_t len)
{
	int r;
	if ((r = sshbuf_check_sanity(buf)) != 0)
		return r;
	if (len == 0)
		return 0;
	if (len > sshbuf_len(buf))
		return SSH_ERR_MESSAGE_INCOMPLETE;
	buf->off += len;
	return 0;
}



static int
sshbuf_peek_string_direct(const struct sshbuf *buf, const uint8_t **valp,
			  size_t *lenp)
{
	uint32_t len;
	const uint8_t *p = sshbuf_ptr(buf);

	if (valp != NULL)
		*valp = NULL;
	if (lenp != NULL)
		*lenp = 0;
	if (sshbuf_len(buf) < 4) {
		debug3("sshbuf: message incomplete, len: %d", sshbuf_len(buf));
		return SSH_ERR_MESSAGE_INCOMPLETE;
	}
	len = PEEK_U32(p);
	if (len > SSHBUF_SIZE_MAX - 4) {
		debug3("sshbuf: string too large, len: %d", len);
		return SSH_ERR_STRING_TOO_LARGE;
	}
	if (sshbuf_len(buf) - 4 < len) {
		debug3("sshbuf: message incomplete, len: %d, buffer len: %d", len, sshbuf_len(buf));
		return SSH_ERR_MESSAGE_INCOMPLETE;
	}
	if (valp != NULL)
		*valp = p + 4;
	if (lenp != NULL)
		*lenp = len;
	return 0;
}

#define sshbuf_skip_string(buf) sshbuf_get_string_direct(buf, NULL, NULL)

static int
sshbuf_get_string_direct(struct sshbuf *buf, const uint8_t **valp, size_t *lenp)
{
	uint32_t len;
	const uint8_t *p;
	int r;

	if (valp != NULL)
		*valp = NULL;
	if (lenp != NULL)
		*lenp = 0;
	if ((r = sshbuf_peek_string_direct(buf, &p, &len)) < 0)
		return r;
	if (valp != NULL)
		*valp = p;
	if (lenp != NULL)
		*lenp = len;
	if (sshbuf_consume(buf, len + 4) != 0) {
		fatal("sshbuf: internal error, sshbuf_consume failed");
	}
	return 0;
}

static int
sshbuf_get_string(struct sshbuf *buf, uint8_t **valp, size_t *lenp)
{
	const uint8_t *val;
	size_t len;
	int r;

	if (valp != NULL)
		*valp = NULL;
	if (lenp != NULL)
		*lenp = 0;
	if ((r = sshbuf_get_string_direct(buf, &val, &len)) < 0)
		return r;
	if (valp != NULL) {
		*valp = xmalloc(len + 1);
		if (len != 0)
			memcpy(*valp, val, len);
		(*valp)[len] = '\0';
	}
	if (lenp != NULL)
		*lenp = len;
	return 0;
}

static int
sshbuf_peek_cstring(struct sshbuf *buf, const uint8_t **valp, size_t *lenp)
{
	size_t len;
	const uint8_t *p, *z;
	int r;

	if (valp != NULL)
		*valp = NULL;
	if (lenp != NULL)
		*lenp = 0;
	if ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		return r;
	/* Allow a \0 only at the end of the string */
	if (len > 0 &&
	    (z = memchr(p , '\0', len)) != NULL && z < p + len - 1) {
		return SSH_ERR_INVALID_FORMAT;
	}
	if (valp) *valp = p;
	if (lenp) *lenp = len;
	return 0;
}

static int
sshbuf_get_cstring(struct sshbuf *buf, char **valp, size_t *lenp)
{
	size_t len;
	const uint8_t *p;
	int r;

	if (valp != NULL)
		*valp = NULL;
	if (lenp != NULL)
		*lenp = 0;
	if ((r = sshbuf_peek_cstring(buf, &p, &len)) != 0)
		return r;

	if ((r = sshbuf_skip_string(buf)) != 0)
		return -1;

	if (valp != NULL) {
		*valp = xmalloc(len + 1);
		if (len != 0)
			memcpy(*valp, p, len);
		(*valp)[len] = '\0';
	}
	if (lenp != NULL)
		*lenp = len;
	return 0;
}

static int
sshbuf_get_path(struct sshbuf *buf, wchar_t **valp, size_t *lenp)
{
	size_t len;
	const uint8_t *p;
	int r;

	if (valp != NULL)
		*valp = NULL;
	if (lenp != NULL)
		*lenp = 0;
	if ((r = sshbuf_peek_cstring(buf, &p, &len)) != 0)
		return r;

	if ((r = sshbuf_skip_string(buf)) != 0)
		return -1;

	size_t wlen;
	if (len) {
		if ((wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
						(const char *)p, len, NULL, 0)) != 0) {
			if (valp) {
				*valp = xwcsalloc(wlen + 1);
				if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
							(const char *)p, len, *valp, wlen) == wlen) {
					(*valp)[wlen] = 0;
				}
				else {
					tell_error("MultibyteToWideChar failed");
					xfree(*valp);
					*valp = NULL;
					return SSH_ERR_INVALID_FORMAT;
				}
			}
			if (lenp)
				*lenp = wlen;
		}
		else {
			tell_error("MultiByteToWideChar failed");
			return SSH_ERR_INVALID_FORMAT;
		}
	}
	else {
		debug("zero length path given");
		if (valp)
			*valp = xwcsdup(L"");
	}

	if (valp && *valp)
		debug3("get_path: %ls", *valp);

	return  0;
}

static int
sshbuf_get(struct sshbuf *buf, void *v, size_t len)
{
	const uint8_t *p = sshbuf_ptr(buf);
	int r;

	if ((r = sshbuf_consume(buf, len)) < 0)
		return r;
	if (v != NULL && len != 0)
		memcpy(v, p, len);
	return 0;
}

static int
sshbuf_get_u64(struct sshbuf *buf, uint64_t *valp)
{
	const uint8_t *p = sshbuf_ptr(buf);
	int r;

	if ((r = sshbuf_consume(buf, 8)) < 0)
		return r;
	if (valp != NULL)
		*valp = PEEK_U64(p);
	return 0;
}

static int
sshbuf_get_u32(struct sshbuf *buf, uint32_t *valp)
{
	const uint8_t *p = sshbuf_ptr(buf);
	int r;

	if ((r = sshbuf_consume(buf, 4)) < 0)
		return r;
	if (valp != NULL)
		*valp = PEEK_U32(p);
	return 0;
}

static int
sshbuf_get_u8(struct sshbuf *buf, uint8_t *valp)
{
	const uint8_t *p = sshbuf_ptr(buf);
	int r;

	if ((r = sshbuf_consume(buf, 1)) < 0)
		return r;
	if (valp != NULL)
		*valp = (uint8_t)*p;
	return 0;
}

 int
sshbuf_get_stringb(struct sshbuf *buf, struct sshbuf *v)
{
	uint32_t len;
	uint8_t *p;
	int r;

	/*
	 * Use sshbuf_peek_string_direct() to figure out if there is
	 * a complete string in 'buf' and copy the string directly
	 * into 'v'.
	 */
	if ((r = sshbuf_peek_string_direct(buf, NULL, NULL)) != 0 ||
	    (r = sshbuf_get_u32(buf, &len)) != 0 ||
	    (r = sshbuf_reserve(v, len, &p)) != 0 ||
	    (r = sshbuf_get(buf, p, len)) != 0)
		return r;
	return 0;
}

static int
sshbuf_put_u64(struct sshbuf *buf, uint64_t val)
{
	uint8_t *p;
	int r;

	if ((r = sshbuf_reserve(buf, 8, &p)) < 0)
		return r;
	POKE_U64(p, val);
	return 0;
}

static int
sshbuf_put_u32(struct sshbuf *buf, uint32_t val)
{
	uint8_t *p;
	int r;

	if ((r = sshbuf_reserve(buf, 4, &p)) < 0)
		return r;
	POKE_U32(p, val);
	return 0;
}

static int
sshbuf_put_u8(struct sshbuf *buf, uint8_t val)
{
	uint8_t *p;
	int r;

	if ((r = sshbuf_reserve(buf, 1, &p)) < 0)
		return r;
	p[0] = val;
	return 0;
}

static int
sshbuf_put_string(struct sshbuf *buf, const void *v, size_t len)
{
	uint8_t *d;
	int r;

	if (len > SSHBUF_SIZE_MAX - 4) {
		return SSH_ERR_NO_BUFFER_SPACE;
	}
	if ((r = sshbuf_reserve(buf, len + 4, &d)) < 0)
		return r;
	POKE_U32(d, len);
	if (len != 0)
		memcpy(d + 4, v, len);
	return 0;
}

#ifndef WC_ERR_INVALID_CHARS
#define WC_ERR_INVALID_CHARS 0x80
#endif

static int
sshbuf_put_wcs(struct sshbuf *buf, const wchar_t *v, size_t wlen)
{
	uint8_t *d;
	int r;

	if (wlen) {
            size_t alen = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, v, wlen,
						  NULL, 0, NULL, NULL);
		if (alen) {
			if (alen > SSHBUF_SIZE_MAX - 4) {
				return SSH_ERR_NO_BUFFER_SPACE;
			}
			if ((r = sshbuf_reserve(buf, alen + 4, &d)) < 0)
				return r;
			POKE_U32(d, alen);
			if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, v, wlen,
						(char *)d + 4, alen, NULL, NULL) == alen)
				return 0;
			else {
				tell_error("WideCharToMultiByte failed (2)");
				return SSH_ERR_NO_BUFFER_SPACE;
			}
		}
		else {
			tell_error("WideCharToMultiByte failed (1)");
			return SSH_ERR_NO_BUFFER_SPACE;
		}
	}
	else
		return sshbuf_put_string(buf, "", 0);
}

static int
sshbuf_put_cstring(struct sshbuf *buf, const char *v)
{
	return sshbuf_put_string(buf, (uint8_t *)v, v == NULL ? 0 : strlen(v));
}

static int
sshbuf_put_path(struct sshbuf *buf, const wchar_t *v)
{
	return sshbuf_put_wcs(buf, v, v == NULL ? 0 : wcslen(v));
}

static int
sshbuf_put_stringb(struct sshbuf *buf, const struct sshbuf *v)
{
	return sshbuf_put_string(buf, sshbuf_ptr(v), sshbuf_len(v));
}

static int
sshbuf_put(struct sshbuf *buf, const void *v, size_t len)
{
	uint8_t *p;
	int r;

	if ((r = sshbuf_reserve(buf, len, &p)) < 0)
		return r;
	if (len != 0)
		memcpy(p, v, len);
	return 0;
}

static void
sshbuf_reset(struct sshbuf *buf)
{
	uint8_t *d;
	if (sshbuf_check_sanity(buf) == 0)
		memset(buf->d, 0, buf->alloc);
	buf->off = buf->size = 0;
	if (buf->alloc != SSHBUF_SIZE_INIT) {
		if ((d = xrealloc(buf->d, SSHBUF_SIZE_INIT)) != NULL) {
			buf->d = d;
			buf->alloc = SSHBUF_SIZE_INIT;
		}
	}
}

/* static int */
/* request_permitted(struct sftp_handler *h) */
/* { */
/* 	char *result; */

/* 	if (readonly && h->does_write) { */
/* 		verbose("Refusing %s request in read-only mode", h->name); */
/* 		return 0; */
/* 	} */
/* 	if (request_blacklist != NULL && */
/* 	    ((result = match_list(h->name, request_blacklist, NULL))) != NULL) { */
/* 		free(result); */
/* 		verbose("Refusing blacklisted %s request", h->name); */
/* 		return 0; */
/* 	} */
/* 	if (request_whitelist != NULL && */
/* 	    ((result = match_list(h->name, request_whitelist, NULL))) != NULL) { */
/* 		xfree(result); */
/* 		debug2("Permitting whitelisted %s request", h->name); */
/* 		return 1; */
/* 	} */
/* 	if (request_whitelist != NULL) { */
/* 		verbose("Refusing non-whitelisted %s request", h->name); */
/* 		return 0; */
/* 	} */
/* 	return 1; */
/* } */

static int
last_error_to_portable(void)
{
	switch (GetLastError()) {
	case ERROR_SUCCESS:
		return SSH2_FX_OK;

	case ERROR_FILE_NOT_FOUND:
	case ERROR_PATH_NOT_FOUND:
	case ERROR_INVALID_DRIVE:
	case ERROR_BAD_UNIT:
	case ERROR_BAD_NETPATH:
	case ERROR_INVALID_HANDLE:
		return SSH2_FX_NO_SUCH_FILE;

	case ERROR_ACCESS_DENIED:
		return SSH2_FX_PERMISSION_DENIED;

	case ERROR_NOT_SUPPORTED:
		return SSH2_FX_OP_UNSUPPORTED;

	default:
		return SSH2_FX_FAILURE;
	}
}

/* static int */
/* errno_to_portable(int unixerrno) */
/* { */
/* 	int ret = 0; */

/* 	switch (unixerrno) { */
/* 	case 0: */
/* 		ret = SSH2_FX_OK; */
/* 		break; */
/* 	case ENOENT: */
/* 	case ENOTDIR: */
/* 	case EBADF: */
/* 	case ELOOP: */
/* 		ret = SSH2_FX_NO_SUCH_FILE; */
/* 		break; */
/* 	case EPERM: */
/* 	case EACCES: */
/* 	case EFAULT: */
/* 		ret = SSH2_FX_PERMISSION_DENIED; */
/* 		break; */
/* 	case ENAMETOOLONG: */
/* 	case EINVAL: */
/* 		ret = SSH2_FX_BAD_MESSAGE; */
/* 		break; */
/* 	case ENOSYS: */
/* 		ret = SSH2_FX_OP_UNSUPPORTED; */
/* 		break; */
/* 	default: */
/* 		ret = SSH2_FX_FAILURE; */
/* 		break; */
/* 	} */
/* 	return ret; */
/* } */

/* static int */
/* flags_from_portable(int pflags) */
/* { */
/* 	int flags = 0; */

/* 	if ((pflags & SSH2_FXF_READ) && */
/* 	    (pflags & SSH2_FXF_WRITE)) { */
/* 		flags = O_RDWR; */
/* 	} else if (pflags & SSH2_FXF_READ) { */
/* 		flags = O_RDONLY; */
/* 	} else if (pflags & SSH2_FXF_WRITE) { */
/* 		flags = O_WRONLY; */
/* 	} */
/* 	if (pflags & SSH2_FXF_APPEND) */
/* 		flags |= O_APPEND; */
/* 	if (pflags & SSH2_FXF_CREAT) */
/* 		flags |= O_CREAT; */
/* 	if (pflags & SSH2_FXF_TRUNC) */
/* 		flags |= O_TRUNC; */
/* 	if (pflags & SSH2_FXF_EXCL) */
/* 		flags |= O_EXCL; */
/* 	return flags; */
/* } */

/* handle handles */

typedef struct Handle Handle;
struct Handle {
	int use;
	HANDLE fd;
	int flags;
	wchar_t *name;
	uint64_t bytes_read, bytes_write;
	int next_unused;
        wchar_t *dir_start;
};

enum {
	HANDLE_USED = 1,
	HANDLE_DIR  = 2,
	HANDLE_FILE = 4,
};

#define SEC_TO_POSIX_EPOCH 11644473600LL
#define WINDOWS_TICKS_PER_SECOND 10000000
static FILETIME
posix_time_to_win(uint64_t posix_time)
{
	FILETIME ft;
	uint64_t win_time = ((posix_time + SEC_TO_POSIX_EPOCH) * WINDOWS_TICKS_PER_SECOND);
	ft.dwLowDateTime = win_time & 0xffffffff;
	ft.dwHighDateTime = win_time >> 32;
	return ft;
}

static uint64_t
win_time_to_posix(FILETIME ft) {
        uint64_t win_time = (((uint64_t)ft.dwHighDateTime) << 32) + ft.dwLowDateTime;
        return win_time / WINDOWS_TICKS_PER_SECOND - SEC_TO_POSIX_EPOCH;
}

static int
w_utimes(wchar_t *name, uint32_t mtime, uint32_t atime)
{

	FILETIME wmtime = posix_time_to_win(mtime);
	FILETIME watime = posix_time_to_win(atime);

	int rc = 0;
	HANDLE h = CreateFileW(name, FILE_WRITE_ATTRIBUTES, 0,
			       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (h == INVALID_HANDLE_VALUE)
		rc = -1;
	else {
		if (!SetFileTime(h, &wmtime, &watime, &wmtime))
			rc = -1;
		if (!CloseHandle(h))
			rc = -1;
	}
	return rc;
}

static void
attrib_clear(Attrib *a)
{
	a->flags = 0;
	a->size = 0;
	a->uid = 0;
	a->gid = 0;
	a->perm = 0;
	a->atime = 0;
	a->mtime = 0;
}

static int
win_attrib_to_posix_mode(DWORD attrib, const wchar_t *path) {
        int mode;
        if (attrib & FILE_ATTRIBUTE_DIRECTORY)
                mode =  040700;
        else if (attrib & FILE_ATTRIBUTE_DEVICE)
		mode = 060000;
	else {
                mode = 0100600;

		size_t len1 = GetShortPathNameW(path, NULL, 0);
		if (len1) {
			wchar_t *shortname = xwcsalloc(len1);
			size_t len = len1 - 1;
			if (GetShortPathNameW(path, shortname, len1) == len) {
				debug3("short name: %s, len: %ld", shortname, len);
				if (len >= 4) {
					wchar_t *ext = shortname + (len - 4);
					debug3("extension: %s", ext);
					if ((_wcsicmp(ext, L".EXE") == 0) ||
					    (_wcsicmp(ext, L".COM") == 0) ||
					    (_wcsicmp(ext, L".BAT") == 0))
						mode |= 0100;
				}
			}
			else
				tell_error("GetShortPathName failed (2)");
			xfree(shortname);
		}
		else
			tell_error("GetShortPathName failed");
	}
        debug3("win_attrib_to_posix_mode(%lx) -> %lx", (unsigned long)attrib, (unsigned long)mode);
        return mode;
}

static int64_t
file_info_to_size(BY_HANDLE_FILE_INFORMATION *info) {
	return ((((uint64_t)info->nFileSizeHigh) << 32) + info->nFileSizeLow);
}

static void
file_info_to_attrib(BY_HANDLE_FILE_INFORMATION *info, Attrib *a, const wchar_t *path) {
	attrib_clear(a);
        a->flags |= SSH2_FILEXFER_ATTR_SIZE;
        a->size = file_info_to_size(info);
        a->flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
        a->perm = win_attrib_to_posix_mode(info->dwFileAttributes, path);
        a->flags |= SSH2_FILEXFER_ATTR_ACMODTIME;
	a->atime = win_time_to_posix(info->ftLastAccessTime);
        a->mtime = win_time_to_posix(info->ftLastWriteTime);
}

static int
GetFileInformationW(wchar_t *name, BY_HANDLE_FILE_INFORMATION *file_info) {
	int rc = 0;
	HANDLE h = CreateFileW(name,
			       FILE_READ_ATTRIBUTES,
			       FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
			       NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (h == INVALID_HANDLE_VALUE)
                tell_error("CreateFile failed");
        else {
                rc = GetFileInformationByHandle(h, file_info);
                CloseHandle(h);
	}
	return rc;
}

static int
w_link(char *oldpath, char *newpath) {
	// TODO: implement me!
	error("w_link(%s, %s) <- unimplemented", oldpath, newpath);
	SetLastError(ERROR_NOT_SUPPORTED);
	return -1;
}

static int
w_fsync(HANDLE fd) {
	// TODO: implement me!
	error("w_fsync(%d, ...) <- unimplemented", fd);
	SetLastError(ERROR_NOT_SUPPORTED);
	return -1;
}

static int
w_close(HANDLE h) {
	if (!CloseHandle(h))
		return -1;
	return 0;
}

static int
w_ftruncate(HANDLE h, off_t length) {
        return -1;
}

Handle *handles = NULL;
int num_handles = 0;
int first_unused_handle = -1;

static void
handle_unused(int i)
{
        debug("handle_unused(%d)", i);
	handles[i].use = 0;
	handles[i].next_unused = first_unused_handle;
	first_unused_handle = i;
}

static int
handle_new(int use, const wchar_t *name, HANDLE fd, int flags, wchar_t *dir_start) {
	int i;

	if (first_unused_handle == -1) {
                int next_num = num_handles * 3 / 2 + 5;
		if (next_num <= num_handles)
			return -1;
		handles = xreallocarray(handles, next_num, sizeof(Handle));
                for (i = next_num - 1; i >= num_handles; i--)
                        handle_unused(i);
                num_handles = next_num;
	}

	i = first_unused_handle;
	first_unused_handle = handles[i].next_unused;

	debug3("handle_new(use: %d, name: %ls, HANDLE: 0x%x, flags: 0x%x, %s) -> %d",
	       use, name, fd, flags, dir_start, i);

	handles[i].use = (use | HANDLE_USED);
	handles[i].fd = fd;
	handles[i].flags = flags;
	handles[i].name = xwcsdup(name);
	handles[i].bytes_read = handles[i].bytes_write = 0;
        handles[i].dir_start = (dir_start ? xwcsdup(dir_start) : NULL);
	return i;
}

static int
handle_is_ok(int i, int type)
{
	return i >= 0 && (uint)i < num_handles &&
		(handles[i].use & HANDLE_USED) && (handles[i].use & type);
}

static wchar_t *
handle_dir_start_and_reset(int i) {
        wchar_t *start;
        if (!handle_is_ok(i, HANDLE_DIR))
                fatal("internal error: handle_delete_dir_start called on a non dir handle");
        start = handles[i].dir_start;
	handles[i].dir_start = NULL;
	return start;
}

static int
handle_to_string(int handle, uint8_t **stringp, int *hlenp)
{
	if (stringp == NULL || hlenp == NULL)
		return -1;
	*stringp = xmalloc(sizeof(int32_t));
	put_u32(*stringp, handle);
	*hlenp = sizeof(int32_t);
	return 0;
}

static int
handle_from_string(const uint8_t *handle, uint hlen)
{
	int val;

	if (hlen != sizeof(int32_t))
		return -1;
	val = get_u32(handle);
	if (handle_is_ok(val, HANDLE_FILE|HANDLE_DIR))
		return val;
	return -1;
}

static wchar_t *
handle_to_name(int handle)
{
	if (handle_is_ok(handle, HANDLE_FILE|HANDLE_DIR))
		return handles[handle].name;
	return NULL;
}

static HANDLE
handle_to_win_dir_handle(int handle)
{
	if (handle_is_ok(handle, HANDLE_DIR))
		return handles[handle].fd;
	return INVALID_HANDLE_VALUE;
}

static HANDLE
handle_to_win_file_handle(int handle)
{
	if (handle_is_ok(handle, HANDLE_FILE))
		return handles[handle].fd;
	return INVALID_HANDLE_VALUE;
}

static int
handle_to_flags(int handle)
{
	if (handle_is_ok(handle, HANDLE_FILE))
		return handles[handle].flags;
	return 0;
}

static void
handle_update_read(int handle, ssize_t bytes)
{
	if (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_read += bytes;
}

static void
handle_update_write(int handle, ssize_t bytes)
{
	if (handle_is_ok(handle, HANDLE_FILE) && bytes > 0)
		handles[handle].bytes_write += bytes;
}

static uint64_t
handle_bytes_read(int handle)
{
	if (handle_is_ok(handle, HANDLE_FILE))
		return (handles[handle].bytes_read);
	return 0;
}

static uint64_t
handle_bytes_write(int handle)
{
	if (handle_is_ok(handle, HANDLE_FILE))
		return (handles[handle].bytes_write);
	return 0;
}

static int
handle_close(int handle)
{
	if (handle_is_ok(handle, HANDLE_FILE)) {
		CloseHandle(handles[handle].fd);
	}
	else if (handle_is_ok(handle, HANDLE_DIR)) {
		FindClose(handles[handle].fd);
	}
	else {
		SetLastError(ERROR_INVALID_HANDLE);
		return -1;
	}

	if (handles[handle].name)
		xfree(handles[handle].name);
	if (handles[handle].dir_start)
		xfree(handles[handle].dir_start);

	return 0;
}

static void
handle_log_close(int handle, char *emsg)
{
	if (handle_is_ok(handle, HANDLE_FILE)) {
		logit("%s%sclose \"%s\" bytes read %llu written %llu",
		    emsg == NULL ? "" : emsg, emsg == NULL ? "" : " ",
		    handle_to_name(handle),
		    (unsigned long long)handle_bytes_read(handle),
		    (unsigned long long)handle_bytes_write(handle));
	} else {
		logit("%s%sclosedir \"%s\"",
		    emsg == NULL ? "" : emsg, emsg == NULL ? "" : " ",
		    handle_to_name(handle));
	}
}

static int
get_handle(struct sshbuf *queue, int *hp)
{
	uint8_t *handle;
	int r;
	size_t hlen;

	*hp = -1;
	if ((r = sshbuf_get_string(queue, &handle, &hlen)) != 0)
		return r;
	if (hlen < 256)
		*hp = handle_from_string(handle, hlen);
	xfree(handle);
	return 0;
}

/* send replies */

static void
send_msg(struct sshbuf *m)
{
	int r;

	if ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal("%s: buffer error: %d", __func__, r);
	sshbuf_reset(m);
}

static const char *
status_to_message(uint32_t status)
{
	const char *status_messages[] = {
		"Success",			/* SSH_FX_OK */
		"End of file",			/* SSH_FX_EOF */
		"No such file",			/* SSH_FX_NO_SUCH_FILE */
		"Permission denied",		/* SSH_FX_PERMISSION_DENIED */
		"Failure",			/* SSH_FX_FAILURE */
		"Bad message",			/* SSH_FX_BAD_MESSAGE */
		"No connection",		/* SSH_FX_NO_CONNECTION */
		"Connection lost",		/* SSH_FX_CONNECTION_LOST */
		"Operation unsupported",	/* SSH_FX_OP_UNSUPPORTED */
		"Unknown error"			/* Others */
	};
	return (status_messages[MINIMUM(status,SSH2_FX_MAX)]);
}

static void
send_status(uint32_t id, uint32_t status)
{
	struct sshbuf *msg;
	int r;

	debug3("request %u: sent status %u", id, status);
	if (log_level > LOG_LEVEL_VERBOSE ||
	    (status != SSH2_FX_OK && status != SSH2_FX_EOF))
		logit("sent status %s", status_to_message(status));
	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_STATUS)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u32(msg, status)) != 0)
		fatal("%s: buffer error: %d", __func__, r);
	if (version >= 3) {
		if ((r = sshbuf_put_cstring(msg,
		    status_to_message(status))) != 0 ||
		    (r = sshbuf_put_cstring(msg, "")) != 0)
			fatal("%s: buffer error: %d", __func__, r);
	}
	send_msg(msg);
	sshbuf_free(msg);
}
static void
send_data_or_handle(char type, uint32_t id, const uint8_t *data, int dlen)
{
	struct sshbuf *msg;
	int r;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_u8(msg, type)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_string(msg, data, dlen)) != 0)
		fatal("%s: buffer error: %d", __func__, r);
	send_msg(msg);
	sshbuf_free(msg);
}

static void
send_data(uint32_t id, const uint8_t *data, int dlen)
{
	debug("request %u: sent data len %d", id, dlen);
	send_data_or_handle(SSH2_FXP_DATA, id, data, dlen);
}

static void
send_handle(uint32_t id, int handle)
{
	uint8_t *string;
	int hlen;

	handle_to_string(handle, &string, &hlen);
	debug("request %u: sent handle handle %d", id, handle);
	send_data_or_handle(SSH2_FXP_HANDLE, id, string, hlen);
	xfree(string);
}

static int
encode_attrib(struct sshbuf *b, const Attrib *a)
{
	int r;

	if ((r = sshbuf_put_u32(b, a->flags)) != 0)
		return r;
	if (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		if ((r = sshbuf_put_u64(b, a->size)) != 0)
			return r;
	}
	if (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		if ((r = sshbuf_put_u32(b, a->uid)) != 0 ||
		    (r = sshbuf_put_u32(b, a->gid)) != 0)
			return r;
	}
	if (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		if ((r = sshbuf_put_u32(b, a->perm)) != 0)
			return r;
	}
	if (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		if ((r = sshbuf_put_u32(b, a->atime)) != 0 ||
		    (r = sshbuf_put_u32(b, a->mtime)) != 0)
			return r;
	}
	return 0;
}

static int
decode_attrib(struct sshbuf *b, Attrib *a)
{
	int r;

	attrib_clear(a);
	if ((r = sshbuf_get_u32(b, &a->flags)) != 0)
		return r;
	if (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		if ((r = sshbuf_get_u64(b, &a->size)) != 0)
			return r;
	}
	if (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		if ((r = sshbuf_get_u32(b, &a->uid)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->gid)) != 0)
			return r;
	}
	if (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		if ((r = sshbuf_get_u32(b, &a->perm)) != 0)
			return r;
	}
	if (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		if ((r = sshbuf_get_u32(b, &a->atime)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->mtime)) != 0)
			return r;
	}
	/* vendor-specific extensions */
	if (a->flags & SSH2_FILEXFER_ATTR_EXTENDED) {
		char *type;
		uint8_t *data;
		size_t dlen;
		uint i, count;

		if ((r = sshbuf_get_u32(b, &count)) != 0)
			fatal("%s: buffer error: %d", __func__, r);
		for (i = 0; i < count; i++) {
			if ((r = sshbuf_get_cstring(b, &type, NULL)) != 0 ||
			    (r = sshbuf_get_string(b, &data, &dlen)) != 0)
				return r;
			debug3("Got file attribute \"%.100s\" len %zu",
			    type, dlen);
			xfree(type);
			xfree(data);
		}
	}
	return 0;
}

static void
send_names(uint32_t id, int count, const Stat *stats)
{
	struct sshbuf *msg;
	int i, r;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_NAME)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u32(msg, count)) != 0)
		fatal("%s: buffer error: %d", __func__, r);
	debug("request %u: sent names count %d", id, count);
	for (i = 0; i < count; i++) {
		if ((r = sshbuf_put_path(msg, stats[i].name)) != 0 ||
		    (r = sshbuf_put_path(msg, stats[i].long_name)) != 0 ||
		    (r = encode_attrib(msg, &stats[i].attrib)) != 0)
			fatal("%s: buffer error: %d", __func__, r);
	}
	send_msg(msg);
	sshbuf_free(msg);
}

static void
send_attrib(uint32_t id, const Attrib *a)
{
	struct sshbuf *msg;
	int r;

	debug("request %u: sent attrib have 0x%x", id, a->flags);
	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_ATTRS)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = encode_attrib(msg, a)) != 0)
		fatal("%s: buffer error: %d", __func__, r);
	send_msg(msg);
	sshbuf_free(msg);
}

/* parse incoming */

static void
process_init(void)
{
	struct sshbuf *msg;
	int r;

	if ((r = sshbuf_get_u32(iqueue, &version)) != 0)
		fatal("%s: buffer error: %d", __func__, r);
	verbose("received client version %u", version);
	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_VERSION)) != 0 ||
	    (r = sshbuf_put_u32(msg, SSH2_FILEXFER_VERSION)) != 0 ||
	    /* POSIX rename extension */
	    (r = sshbuf_put_cstring(msg, "posix-rename@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(msg, "1")) != 0 || /* version */
	    /* hardlink extension */
	    (r = sshbuf_put_cstring(msg, "hardlink@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(msg, "1")) != 0 || /* version */
	    /* fsync extension */
	    (r = sshbuf_put_cstring(msg, "fsync@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(msg, "1")) != 0) /* version */
		fatal("%s: buffer error: %d", __func__, r);
	send_msg(msg);
	sshbuf_free(msg);
}

static void
process_open(uint32_t id)
{
	uint32_t pflags;
	Attrib a;
	wchar_t *name;
	int r, handle, status = SSH2_FX_FAILURE;
	HANDLE fd;
	DWORD access = 0;
	DWORD creation = OPEN_EXISTING;

	if ((r = sshbuf_get_path(iqueue, &name, NULL)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &pflags)) != 0 || /* portable flags */
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug3("request %u: open flags %d", id, pflags);

	if (pflags & SSH2_FXF_READ)
		access |= GENERIC_READ;
	if (pflags & SSH2_FXF_WRITE) {
                access |= GENERIC_WRITE;

                if (pflags & SSH2_FXF_CREAT) {
                        if (pflags & SSH2_FXF_EXCL)
                                creation = CREATE_NEW;
                        else if (pflags & SSH2_FXF_TRUNC)
                                creation = CREATE_ALWAYS;
			else
				creation = OPEN_ALWAYS;
		}
                else if (pflags & SSH2_FXF_TRUNC)
                        creation = TRUNCATE_EXISTING;
        }

        if (readonly && (pflags & SSH2_FXF_WRITE)) {
                verbose("Refusing open request in read-only mode");
                status = SSH2_FX_PERMISSION_DENIED;
        }
        else {
		fd = CreateFileW(name, access, 0, NULL, creation, FILE_ATTRIBUTE_NORMAL, NULL);
		if (fd == INVALID_HANDLE_VALUE) {
			status = last_error_to_portable();
		} else {
			handle = handle_new(HANDLE_FILE, name, fd, pflags, NULL);
			if (handle < 0) {
				w_close(fd);
			} else {
				send_handle(id, handle);
				status = SSH2_FX_OK;
			}
		}
	}
	if (status != SSH2_FX_OK)
		send_status(id, status);
	xfree(name);
}

static void
process_close(uint32_t id)
{
	int r, handle, ret, status = SSH2_FX_FAILURE;

	if ((r = get_handle(iqueue, &handle)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug3("request %u: close handle %d", id, handle);
	handle_log_close(handle, NULL);
	ret = handle_close(handle);
	status = (ret == -1) ? last_error_to_portable() : SSH2_FX_OK;
	send_status(id, status);
}

static void
process_read(uint32_t id)
{
	uint8_t buf[64*1024];
	uint32_t len;
	int r, handle, status = SSH2_FX_FAILURE;
	HANDLE fd;
	LARGE_INTEGER off;

	if ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, (uint64_t*)&(off.QuadPart))) != 0 ||
            (r = sshbuf_get_u32(iqueue, &len)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug("request %u: read \"%s\" (handle %d) off %llu len %d",
              id, handle_to_name(handle), handle, (unsigned long long)(off.QuadPart), len);
	if (len > sizeof buf) {
		len = sizeof buf;
		debug2("read change len %d", len);
	}
	fd = handle_to_win_file_handle(handle);
	if (fd != INVALID_HANDLE_VALUE) {
                if (!SetFilePointerEx(fd, off, NULL, FILE_BEGIN)) {
			error("process_read: seek failed");
                        status = last_error_to_portable();
		} else {
                        uint32_t off = 0;
                        while (len > off) {
                                DWORD read;
                                if (ReadFile(fd, buf + off, len - off, &read, NULL)) {
                                        if (read) {
                                                off += read;
                                                handle_update_read(handle, read);
                                        }
                                        else { // EOF!
                                                if (!off) status = SSH2_FX_EOF;
                                                break;
                                        }
                                }
                                else {
                                        if (!off) status = last_error_to_portable();
                                        break;
                                }
                        }
                        if (off || !len) {
                                send_data(id, buf, off);
                                status = SSH2_FX_OK;
                        }
                }
        }
	if (status != SSH2_FX_OK)
		send_status(id, status);
}

static void
process_write(uint32_t id)
{
	LARGE_INTEGER off;
	size_t len;
	int r, handle, status = SSH2_FX_FAILURE;
        HANDLE fd;
	uint8_t *data;

	if ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, (uint64_t*)&(off.QuadPart))) != 0 ||
	    (r = sshbuf_get_string(iqueue, &data, &len)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug("request %u: write \"%s\" (handle %d) off %llu len %zu",
	    id, handle_to_name(handle), handle, (unsigned long long)off.QuadPart, len);
	fd = handle_to_win_file_handle(handle);

	if (fd == INVALID_HANDLE_VALUE)
		status = SSH2_FX_FAILURE;
	else {
		if (!(handle_to_flags(handle) & SSH2_FXF_APPEND) &&
                    !SetFilePointerEx(fd, off, NULL, FILE_BEGIN)) {
			status = last_error_to_portable();
			error("process_write: seek failed");
		} else {
/* XXX ATOMICIO ? */
                        while (len) {
                                DWORD written;
                                if (WriteFile(fd, data, len, &written, NULL)) {
                                        if (written <= len) {
                                                data += written;
                                                len -= written;
                                                handle_update_write(handle, written);
                                        } else {
                                                error("Internal error: too much data written (%d)", written);
                                                status = SSH2_FX_FAILURE;
                                                break;
                                        }
                                }
                                else {
                                        error("process_write: write failed");
                                        status = last_error_to_portable();
                                        break;
                                }
                                
			}
                        if (len == 0)
                                status = SSH2_FX_OK;

		}
	}
	send_status(id, status);
	xfree(data);
}

static void
process_do_stat(uint32_t id, int do_lstat)
{
	Attrib a;
	wchar_t *name;
	int r, status = SSH2_FX_FAILURE;

	if ((r = sshbuf_get_path(iqueue, &name, NULL)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug3("request %u: %sstat", id, do_lstat ? "l" : "");
	verbose("%sstat name \"%ls\"", do_lstat ? "l" : "", name);

	// TODO: add lstat back
	// r = do_lstat ? lstat(name, &st) : stat(name, &st);

	BY_HANDLE_FILE_INFORMATION file_info;
	if (GetFileInformationW(name, &file_info)) {
		file_info_to_attrib(&file_info, &a, name);
		send_attrib(id, &a);
		status = SSH2_FX_OK;
	}
	else
		status = last_error_to_portable();

	if (status != SSH2_FX_OK)
		send_status(id, status);
	
	xfree(name);
}

static void
process_stat(uint32_t id)
{
	process_do_stat(id, 0);
}

static void
process_lstat(uint32_t id)
{
	process_do_stat(id, 1);
}

static void
process_fstat(uint32_t id)
{
	Attrib a;
	int r, handle, status = SSH2_FX_FAILURE;
        HANDLE fd;

	if ((r = get_handle(iqueue, &handle)) != 0)
		fatal("%s: buffer error: %d", __func__, r);
	debug("request %u: fstat \"%s\" (handle %u)",
	    id, handle_to_name(handle), handle);
	fd = handle_to_win_file_handle(handle);
	if (fd != INVALID_HANDLE_VALUE) {
		BY_HANDLE_FILE_INFORMATION file_info;
                if (GetFileInformationByHandle(fd, &file_info)) {
			file_info_to_attrib(&file_info, &a, handle_to_name(handle));
                        send_attrib(id, &a);
			status = SSH2_FX_OK;
                }
                else {
			status = last_error_to_portable();
                }
	}
	if (status != SSH2_FX_OK)
		send_status(id, status);
}

static void
process_setstat(uint32_t id)
{
	Attrib a;
	wchar_t *name;
	int r, status = SSH2_FX_OK;

	if ((r = sshbuf_get_path(iqueue, &name, NULL)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug("request %u: setstat name \"%ls\"", id, name);
	if (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
		logit("set \"%ls\" size %llu",
		    name, (unsigned long long)a.size);
		HANDLE fd = CreateFileW(name, GENERIC_WRITE, 0,
					NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (fd != INVALID_HANDLE_VALUE) {
			LARGE_INTEGER off;
			off.QuadPart = a.size;
			if (!SetFilePointerEx(fd, off, NULL, FILE_BEGIN) || 
			    !SetEndOfFile(fd))
				status = last_error_to_portable();
		}
		else
			status = last_error_to_portable();
	}
	if (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%ls\" mode %04o", name, a.perm);
		// FIXME: reimplement chmod
		// r = chmod(name, a.perm & 07777);
		// if (r == -1)
		// status = last_error_to_portable();
	}
	if (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		char buf[64];
		time_t t = a.mtime;

		strftime(buf, sizeof(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%ls\" modtime %s", name, buf);
		r = w_utimes(name, a.mtime, a.atime);
		if (r == -1)
			status = last_error_to_portable();
	}
	if (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
                      (u_long)a.uid, (u_long)a.gid);
                // FIXME: reimplement chown
		//r = w_chown(name, a.uid, a.gid);
		//if (r == -1)
                //status = last_error_to_portable();
	}
	send_status(id, status);
	xfree(name);
}

static void
process_fsetstat(uint32_t id)
{
	Attrib a;
	int handle, r;
        HANDLE fd;
	int status = SSH2_FX_OK;

	if ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug("request %u: fsetstat handle %d", id, handle);
	fd = handle_to_win_file_handle(handle);
	if (fd == INVALID_HANDLE_VALUE)
		status = SSH2_FX_FAILURE;
	else {
		wchar_t *name = handle_to_name(handle);

		if (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
			logit("set \"%s\" size %llu",
			    name, (unsigned long long)a.size);
			r = w_ftruncate(fd, a.size);
			if (r == -1)
				status = last_error_to_portable();
		}
		if (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
			logit("set \"%s\" mode %04o", name, a.perm);
#ifdef HAVE_FCHMOD
			r = fchmod(fd, a.perm & 07777);
#else
			// TODO: reimplement chmod!
			/* r = chmod(name, a.perm & 07777); */
#endif
			if (r == -1)
				status = last_error_to_portable();
		}
		if (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			char buf[64];
			time_t t = a.mtime;

			strftime(buf, sizeof(buf), "%Y%m%d-%H:%M:%S",
			    localtime(&t));
			logit("set \"%s\" modtime %s", name, buf);

			// TODO: implement and use futimes
			// r = futimes(fd, attrib_to_tv(&a));
			r = w_utimes(name, a.mtime, a.atime);
			if (r == -1)
				status = last_error_to_portable();
		}
		if (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
			logit("set \"%s\" owner %lu group %lu", name,
			    (u_long)a.uid, (u_long)a.gid);

			// TODO: reimplement fchown
			// r = fchown(fd, a.uid, a.gid);
			// r = w_chown(name, a.uid, a.gid);
			//if (r == -1)
			//	status = last_error_to_portable();
		}
	}
	send_status(id, status);
}

static void
process_opendir(uint32_t id)
{
        HANDLE dd;
	wchar_t *path, *pattern;
	int r, handle, status = SSH2_FX_FAILURE;
        size_t path_len;
        WIN32_FIND_DATAW find_data;

	if ((r = sshbuf_get_path(iqueue, &path, &path_len)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug3("request %u: opendir", id);

        wchar_t *fullpath = xpathjoin(NULL, path);

	logit("opendir \"%ls\", len: %ld, fullpath: %ls", path, path_len, fullpath);

        
        if (fullpath) {
                size_t len = wcslen(fullpath);
                if (len == 0 || fullpath[len - 1] == '/' || fullpath[len - 1] == '\\') {
                        path = xreallocarray(path, len + 1, sizeof(wchar_t));
                        wmemcpy(path + len, L"/", 2);
                        len++;
                }

                pattern = xwcscat(fullpath, L"*");

                debug3("FindFistFileW(pattern=%ls)", pattern);

                dd = FindFirstFileW(pattern, &find_data);

                if (dd == INVALID_HANDLE_VALUE) {
                        tell_error("FindFirstFile failed");
                        status = last_error_to_portable();
                }
                else {
                        handle = handle_new(HANDLE_DIR, path, dd, 0, find_data.cFileName);
                        if (handle < 0) {
                                w_close(dd);
                        } else {
                                send_handle(id, handle);
                                status = SSH2_FX_OK;
                        }
                }
                xfree(fullpath);
        }
        if (status != SSH2_FX_OK)
                send_status(id, status);

	xfree(path);
        xfree(pattern);
}

static wchar_t *
xprintf(const wchar_t *fmt, ...) {
	size_t max = 100;
	wchar_t *line = NULL;
	while (1) {
		line = xreallocarray(line, max, sizeof(wchar_t));
		va_list args;
		va_start(args, fmt);
		HRESULT rc = StringCchVPrintfW(line, max, fmt, args);
		va_end(args);
		switch (rc) {
		case S_OK:
			return line;
		case STRSAFE_E_INVALID_PARAMETER:
			fatal_error("StringCchVprintf failed");
		}
		max *= 2;
	}
}

static void
process_readdir(uint32_t id)
{
        // TODO: Fix memory leaks!

        HANDLE dd;
	wchar_t *path;
	int r, handle;

	if ((r = get_handle(iqueue, &handle)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug("request %u: readdir \"%s\" (handle %d)", id,
	    handle_to_name(handle), handle);
        path = handle_to_name(handle);
	dd = handle_to_win_dir_handle(handle);
	if (dd == INVALID_HANDLE_VALUE || path == NULL) {
		send_status(id, SSH2_FX_FAILURE);
	} else {
                wchar_t *fn = handle_dir_start_and_reset(handle);
                if (!fn) {
                        WIN32_FIND_DATAW find_data;
                        if (FindNextFileW(dd, &find_data))
                                fn = xwcsdup(find_data.cFileName);
                        else
                                tell_error("FindNextFile failed");
                }
                if (fn) {
                        // TODO: send more than one entry per packet
                        wchar_t *fullname = xpathjoin(path, fn);
                        Stat stats;
                        wchar_t *user = NULL, *group = NULL, *user_domain = NULL, *group_domain = NULL;
                        wchar_t mode[11 + 1];
                        StringCbCopyW(mode, sizeof(mode), L"---------- "); // default value

                        stats.name = fn;
                        attrib_clear(&stats.attrib);
                        HANDLE fd = CreateFileW(fullname,
						FILE_READ_ATTRIBUTES|READ_CONTROL,
						FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
						NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
                        if (fd == INVALID_HANDLE_VALUE)
                            tell_error("CreateFile failed");
                        else {
                            BY_HANDLE_FILE_INFORMATION file_info;
                            if (GetFileInformationByHandle(fd, &file_info)) {
				    file_info_to_attrib(&file_info, &stats.attrib, fullname);
				    file_info_to_str(&file_info, mode);
                            }
                            else
                                tell_error("GetFileInformationByHandle failed");

                            SECURITY_DESCRIPTOR *sd = NULL;
                            SID *sid_owner = NULL, *sid_group = NULL;
                            if (GetSecurityInfo(fd, SE_FILE_OBJECT,
                                                OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION,
                                                (void **)&sid_owner, (void **)&sid_group,
                                                NULL, NULL,
                                                (void**)&sd) == ERROR_SUCCESS) {

                                SID_NAME_USE use = SidTypeUnknown;
                                DWORD user_size = 0, group_size = 0, user_domain_size = 0, group_domain_size = 0;
                                LookupAccountSid(NULL, sid_owner, NULL, &user_size, NULL, &user_domain_size, &use);
                                if (user_size) {
                                        user_domain = xwcsalloc(user_domain_size);
                                        user = xwcsalloc(user_size);
                                        if (!LookupAccountSidW(NULL, sid_owner, user, &user_size, user_domain, &user_domain_size, &use)) {
                                                tell_error("LookupAccountSid failed (2)");
                                                xfree(user);
                                                xfree(user_domain);
                                                user = NULL;
                                                group_domain = NULL;
                                        }
                                        else {
                                                debug("user: %ls, domain: %ls", user, user_domain);
                                        }
                                }
                                else
                                        tell_error("LookupAccountSid failed (1)");

                                LookupAccountSid(NULL, sid_group, NULL, &group_size, NULL, &group_domain_size, &use);
                                if (group_size) {
                                        group_domain = xwcsalloc(group_domain_size);
                                        group = xwcsalloc(group_size);
                                        if (!LookupAccountSidW(NULL, sid_group, group, &group_size, group_domain, &group_domain_size, &use)) {
                                                tell_error("LookupAccountSid failed (4)");
                                                xfree(group);
                                                xfree(group_domain);
                                                group = NULL;
                                                group_domain = NULL;
                                        }
                                        else {
                                                debug("group: %ls, domain: %ls", group, group_domain);
                                        }
                                }
                                else
                                        tell_error("LookupAccountSid failed (1)");

                                LocalFree(sd);
                            }
                            else
                                    tell_error("GetSecurityInfo failed");

                            CloseHandle(fd);
                        }
                        stats.long_name = xprintf(L"%s %u %s\\%s %s\\%s %8llu %s %s",
                                                  mode, 1,
                                                  (user ? user : L"?"),
                                                  (user_domain ? user_domain : L"?"),
                                                  (group ? group : L"?"),
                                                  (group_domain ? group_domain : L"?"),
                                                  stats.attrib.size,
                                                  L"yesterday",
                                                  fn);

                        send_names(id, 1, &stats);
			xfree(fn);
			xfree(fullname);
			xfree(stats.long_name);
                        if (user) xfree(user);
                        if (group) xfree(group);
                        if (user_domain) xfree(user_domain);
                        if (group_domain) xfree(group_domain);
                }
                else
                        send_status(id, SSH2_FX_EOF);
        }
}

static void
process_remove(uint32_t id)
{
	char *name;
	int r, status = SSH2_FX_FAILURE;

	if ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug3("request %u: remove", id);
	logit("remove name \"%s\"", name);
	r = unlink(name);
	status = (r == -1) ? last_error_to_portable() : SSH2_FX_OK;
	send_status(id, status);
	xfree(name);
}

static void
process_mkdir(uint32_t id)
{
	Attrib a;
	char *name;
	int r, mode, status = SSH2_FX_FAILURE;

	if ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ?
	    a.perm & 07777 : 0777;
	debug3("request %u: mkdir", id);
	logit("mkdir name \"%s\" mode 0%o", name, mode);
	//r = mkdir(name, mode);
	r = mkdir(name); // TODO: set mode!
	status = (r == -1) ? last_error_to_portable() : SSH2_FX_OK;
	send_status(id, status);
	xfree(name);
}

static void
process_rmdir(uint32_t id)
{
	char *name;
	int r, status;

	if ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug3("request %u: rmdir", id);
	logit("rmdir name \"%s\"", name);
	r = rmdir(name);
	status = (r == -1) ? last_error_to_portable() : SSH2_FX_OK;
	send_status(id, status);
	xfree(name);
}

static void
process_realpath(uint32_t id)
{
	wchar_t *path = NULL;
        int status = SSH2_FX_FAILURE;
	int r;

	if ((r = sshbuf_get_path(iqueue, &path, NULL)) != 0)
		fatal("%s: buffer error: %d", __func__, r);
	debug3("request %u: realpath", id);
	verbose("realpath \"%ls\"", path);
        
        wchar_t *sanepath = xpathjoin(NULL, path);
        debug3("sanepath: %ls", sanepath);
        if (sanepath) {
                DWORD len = GetFullPathNameW(sanepath, 0, NULL, NULL);
                if (len) {
                        wchar_t *fullpath = xwcsalloc(len);
                        DWORD len1 = GetFullPathNameW(sanepath, len, fullpath, NULL);
                        if (len1 > 0 && len1 < len) {
                                size_t len = GetLongPathNameW(fullpath, NULL, 0);
                                if (len) {
                                        wchar_t *longpath = xwcsalloc(len);
                                        size_t len1 = GetLongPathNameW(fullpath, longpath, len);
                                        if (len1 && len1 < len) {
                                                Stat s;
                                                attrib_clear(&s.attrib);
                                                s.name = longpath;
                                                s.long_name = xwcsdup(L"");
                                                send_names(id, 1, &s);
                                                status = SSH2_FX_OK;
                                        }
                                        else
                                                tell_error("GetLongPathNameW failed (2)");
                                        xfree(longpath);
                                }
                                else
                                        tell_error("GetLongPathNameW failed (1)");
                        }
                        else
                                tell_error("GetFullPathNameW failed (2)");
                        xfree(fullpath);
                }
                else
                        tell_error("GetFullPathNameW failed (1)");

                xfree(sanepath);
        }
        
        if (status != SSH2_FX_OK)
		send_status(id, last_error_to_portable());
	xfree(path);
}

static void
process_rename(uint32_t id)
{
	char *oldpath, *newpath;
	int r, status;

	if ((r = sshbuf_get_cstring(iqueue, &oldpath, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, NULL)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug3("request %u: rename", id);
	logit("rename old \"%s\" new \"%s\"", oldpath, newpath);
	status = SSH2_FX_FAILURE;

	if (MoveFile(oldpath, newpath))
		status = SSH2_FX_OK;
	else {
		status = last_error_to_portable();
	}

	send_status(id, status);
	xfree(oldpath);
	xfree(newpath);
}

static void
process_readlink(uint32_t id)
{
	int r;
	char *path;

	if ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug3("request %u: readlink", id);
	verbose("readlink \"%s\" (unsupported)", path);

        send_status(id, SSH2_FX_OP_UNSUPPORTED);

	xfree(path);
}

static void
process_symlink(uint32_t id)
{
	char *oldpath, *newpath;
	int r;

	if ((r = sshbuf_get_cstring(iqueue, &oldpath, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, NULL)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug3("request %u: symlink", id);
	logit("symlink old \"%s\" new \"%s\" (unsupported)", oldpath, newpath);

	send_status(id, SSH2_FX_OP_UNSUPPORTED);

	xfree(oldpath);
	xfree(newpath);
}

static void
process_extended_posix_rename(uint32_t id)
{
	char *oldpath, *newpath;
	int r, status;

	if ((r = sshbuf_get_cstring(iqueue, &oldpath, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, NULL)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug3("request %u: posix-rename", id);
	logit("posix-rename old \"%s\" new \"%s\"", oldpath, newpath);
	r = rename(oldpath, newpath);
	status = (r == -1) ? last_error_to_portable() : SSH2_FX_OK;
	send_status(id, status);
	xfree(oldpath);
	xfree(newpath);
}

static void
process_extended_hardlink(uint32_t id)
{
	char *oldpath, *newpath;
	int r, status;

	if ((r = sshbuf_get_cstring(iqueue, &oldpath, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, NULL)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug3("request %u: hardlink", id);
	logit("hardlink old \"%s\" new \"%s\"", oldpath, newpath);
	r = w_link(oldpath, newpath);
	status = (r == -1) ? last_error_to_portable() : SSH2_FX_OK;
	send_status(id, status);
	xfree(oldpath);
	xfree(newpath);
}

static void
process_extended_fsync(uint32_t id)
{
	int handle, r, status = SSH2_FX_OP_UNSUPPORTED;
        HANDLE fd;

	if ((r = get_handle(iqueue, &handle)) != 0)
		fatal("%s: buffer error: %d", __func__, r);
	debug3("request %u: fsync (handle %u)", id, handle);
	verbose("fsync \"%s\"", handle_to_name(handle));
	fd = handle_to_win_file_handle(handle);
        if (fd == INVALID_HANDLE_VALUE)
		status = SSH2_FX_NO_SUCH_FILE;
	else if (handle_is_ok(handle, HANDLE_FILE)) {
		r = w_fsync(fd);
		status = (r == -1) ? last_error_to_portable() : SSH2_FX_OK;
	}
	send_status(id, status);
}

static void
process_extended(uint32_t id)
{
	char *request;
	int i, r;

	if ((r = sshbuf_get_cstring(iqueue, &request, NULL)) != 0)
		fatal("%s: buffer error: %d", __func__, r);
	for (i = 0; extended_handlers[i].handler != NULL; i++) {
		if (strcmp(request, extended_handlers[i].ext_name) == 0) {
			/* if (!request_permitted(&extended_handlers[i])) */
			/* 	send_status(id, SSH2_FX_PERMISSION_DENIED); */
			/* else */
			/* 	extended_handlers[i].handler(id); */
			/* break; */

			extended_handlers[i].handler(id);
			break;
		}
	}
	if (extended_handlers[i].handler == NULL) {
		error("Unknown extended request \"%.100s\"", request);
		send_status(id, SSH2_FX_OP_UNSUPPORTED);	/* MUST */
	}
	xfree(request);
}

/* stolen from ssh-agent */

static void
process(void)
{
	uint msg_len;
	uint buf_len;
	uint consumed;
	uint8_t type;
	const uint8_t *cp;
	int i, r;
	uint32_t id;

	buf_len = sshbuf_len(iqueue);
	if (buf_len < 5)
		return;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	msg_len = get_u32(cp);
	if (msg_len > SFTP_MAX_MSG_LENGTH) {
		error("bad message from %s local user %s",
		    client_addr, NULL);
		cleanup_exit(11);
	}
	if (buf_len < msg_len + 4)
		return;
	if ((r = sshbuf_consume(iqueue, 4)) != 0)
		fatal("%s: buffer error: %d", __func__, r);
	buf_len -= 4;
	if ((r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	switch (type) {
	case SSH2_FXP_INIT:
		process_init();
		init_done = 1;
		break;
	case SSH2_FXP_EXTENDED:
		if (!init_done)
			fatal("Received extended request before init");
		if ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal("%s: buffer error: %d", __func__, r);
		process_extended(id);
		break;
	default:
		if (!init_done)
			fatal("Received %u request before init", type);
		if ((r = sshbuf_get_u32(iqueue, &id)) != 0)
			fatal("%s: buffer error: %d", __func__, r);
		for (i = 0; handlers[i].handler != NULL; i++) {
			if (type == handlers[i].type) {
				// TODO: reintroduce request_permitted
				/* if (!request_permitted(&handlers[i])) { */
				/* 	send_status(id, */
				/* 	    SSH2_FX_PERMISSION_DENIED); */
				/* } else { */
				/* 	handlers[i].handler(id); */
				/* } */
				/* break; */

				handlers[i].handler(id);
				break;
			}
		}
		if (handlers[i].handler == NULL)
			error("Unknown message %u", type);
	}
	/* discard the remaining bytes from the current packet */
	if (buf_len < sshbuf_len(iqueue)) {
		error("iqueue grew unexpectedly");
		cleanup_exit(255);
	}
	consumed = buf_len - sshbuf_len(iqueue);
	if (msg_len < consumed) {
		error("msg_len %u < consumed %u", msg_len, consumed);
		cleanup_exit(255);
	}
	if (msg_len > consumed &&
	    (r = sshbuf_consume(iqueue, msg_len - consumed)) != 0)
		fatal("%s: buffer error: %d", __func__, r);
}

/* Cleanup handler that logs active handles upon normal exit */
static void
cleanup_exit(int i)
{
	if (client_addr != NULL) {
		logit("session closed for local user %s from [%s]",
		    NULL, client_addr);
	}
	_exit(i);
}

static void
sftp_server_usage(void)
{
	char progname[200];
	GetModuleFileName(0, progname, sizeof(progname));

	fprintf(stderr,
		"usage: %s [-ehR] [-d start_directory] [-f log_facility] "
		"[-l log_level]\n\t[-P blacklisted_requests] "
		"[-p whitelisted_requests] [-u umask]\n"
		"       %s -Q protocol_feature\n",
		progname, progname);
	exit(1);
}

static struct {
	const char *name;
	LogLevel val;
} log_levels[] =
{
	{ "QUIET",	LOG_LEVEL_QUIET },
	{ "FATAL",	LOG_LEVEL_FATAL },
	{ "ERROR",	LOG_LEVEL_ERROR },
	{ "INFO",	LOG_LEVEL_INFO },
	{ "VERBOSE",	LOG_LEVEL_VERBOSE },
	{ "DEBUG",	LOG_LEVEL_DEBUG1 },
	{ "DEBUG1",	LOG_LEVEL_DEBUG1 },
	{ "DEBUG2",	LOG_LEVEL_DEBUG2 },
	{ "DEBUG3",	LOG_LEVEL_DEBUG3 },
	{ NULL,		LOG_LEVEL_NOT_SET }
};

static LogLevel
log_level_number(char *name)
{
	int i;

	if (name != NULL)
		for (i = 0; log_levels[i].name; i++)
			if (strcasecmp(log_levels[i].name, name) == 0)
				return log_levels[i].val;
	return LOG_LEVEL_NOT_SET;
}

/* char * */
/* tilde_expand_filename(const char *filename, uid_t uid) */
/* { */
/* 	const char *path, *sep; */
/* 	char user[128], *ret; */
/* 	struct passwd *pw; */
/* 	uint len, slash; */

/* 	if (*filename != '~') */
/* 		return (xstrdup(filename)); */
/* 	filename++; */

/* 	path = strchr(filename, '/'); */
/* 	if (path != NULL && path > filename) {		/\* ~user/path *\/ */
/* 		slash = path - filename; */
/* 		if (slash > sizeof(user) - 1) */
/* 			fatal("tilde_expand_filename: ~username too long"); */
/* 		memcpy(user, filename, slash); */
/* 		user[slash] = '\0'; */
/* 		if ((pw = getpwnam(user)) == NULL) */
/* 			fatal("tilde_expand_filename: No such user %s", user); */
/* 	} else if ((pw = getpwuid(uid)) == NULL)	/\* ~/path *\/ */
/* 		fatal("tilde_expand_filename: No such uid %ld", (long)uid); */

/* 	/\* Make sure directory has a trailing '/' *\/ */
/* 	len = strlen(pw->pw_dir); */
/* 	if (len == 0 || pw->pw_dir[len - 1] != '/') */
/* 		sep = "/"; */
/* 	else */
/* 		sep = ""; */

/* 	/\* Skip leading '/' from specified path *\/ */
/* 	if (path != NULL) */
/* 		filename = path + 1; */

/* 	if (xasprintf(&ret, "%s%s%s", pw->pw_dir, sep, filename) >= PATH_MAX) */
/* 		fatal("tilde_expand_filename: Path too long"); */

/* 	return (ret); */
/* } */

static char *
tilde_expand_filename(const char *filename)
{
	// TODO: Fixme!
	return xstrdup(filename);
}

 char *
percent_expand(const char *string, ...)
{
#define EXPAND_MAX_KEYS	16
	uint num_keys, i, j;
	struct {
		const char *key;
		const char *repl;
	} keys[EXPAND_MAX_KEYS];
	char buf[4096];
	va_list ap;

	/* Gather keys */
	va_start(ap, string);
	for (num_keys = 0; num_keys < EXPAND_MAX_KEYS; num_keys++) {
		keys[num_keys].key = va_arg(ap, char *);
		if (keys[num_keys].key == NULL)
			break;
		keys[num_keys].repl = va_arg(ap, char *);
		if (keys[num_keys].repl == NULL)
			fatal("%s: NULL replacement", __func__);
	}
	if (num_keys == EXPAND_MAX_KEYS && va_arg(ap, char *) != NULL)
		fatal("%s: too many keys", __func__);
	va_end(ap);

	/* Expand string */
	*buf = '\0';
	for (i = 0; *string != '\0'; string++) {
		if (*string != '%') {
 append:
			buf[i++] = *string;
			if (i >= sizeof(buf))
				fatal("%s: string too long", __func__);
			buf[i] = '\0';
			continue;
		}
		string++;
		/* %% case */
		if (*string == '%')
			goto append;
		if (*string == '\0')
			fatal("%s: invalid format", __func__);
		for (j = 0; j < num_keys; j++) {
			if (strchr(keys[j].key, *string) != NULL) {
				i = strlcat(buf, keys[j].repl, sizeof(buf));
				if (i >= sizeof(buf))
					fatal("%s: string too long", __func__);
				break;
			}
		}
		if (j >= num_keys)
			fatal("%s: unknown key %%%c", __func__, *string);
	}
	return (xstrdup(buf));
#undef EXPAND_MAX_KEYS
}

int
sftp_server_main(int argc, char **argv)
{
	int i, r, ch, skipargs = 0;
	char *cp, *homedir = NULL, buf[4*4096];

	HANDLE in, out;

	extern char *optarg;

	while (!skipargs && (ch = getopt(argc, argv,
	    "d:f:l:P:p:Q:u:cehR")) != -1) {
		switch (ch) {
		case 'Q':
			if (strcasecmp(optarg, "requests") != 0) {
				fprintf(stderr, "Invalid query type\n");
				exit(1);
			}
			for (i = 0; handlers[i].handler != NULL; i++)
				printf("%s\n", handlers[i].name);
			for (i = 0; extended_handlers[i].handler != NULL; i++)
				printf("%s\n", extended_handlers[i].name);
			exit(0);
			break;
		case 'R':
			readonly = 1;
			break;
		case 'c':
			/*
			 * Ignore all arguments if we are invoked as a
			 * shell using "sftp-server -c command"
			 */
			skipargs = 1;
			break;
		case 'e':
			// log_stderr = 1;
			break;
		case 'l':
			log_level = log_level_number(optarg);
			if (log_level == LOG_LEVEL_NOT_SET)
				error("Invalid log level \"%s\"", optarg);
			break;
		case 'f':
			break;
		case 'd':
			/* cp = tilde_expand_filename(optarg), user_pw->pw_uid); */
			/* homedir = percent_expand(cp, "d", user_pw->pw_dir, */
			/*     "u", user_pw->pw_name, (char *)NULL); */
			/* xfree(cp); */

			// TODO: Fixme!
			homedir = tilde_expand_filename(optarg);
			// homedir = percent_expand ...
			break;
		case 'p':
			if (request_whitelist != NULL)
				fatal("Permitted requests already set");
			request_whitelist = xstrdup(optarg);
			break;
		case 'P':
			if (request_blacklist != NULL)
				fatal("Refused requests already set");
			request_blacklist = xstrdup(optarg);
			break;
		case 'h':
		default:
			sftp_server_usage();
		}
	}

        debug("arguments parsed");
        
	/*
	 * On platforms where we can, avoid making /proc/self/{mem,maps}
	 * available to the user so that sftp access doesn't automatically
	 * imply arbitrary code execution access that will break
	 * restricted configurations.
	 */

	if ((cp = getenv("SSH_CONNECTION")) != NULL) {
		client_addr = xstrdup(cp);
		if ((cp = strchr(client_addr, ' ')) == NULL) {
			error("Malformed SSH_CONNECTION variable: \"%s\"",
			    getenv("SSH_CONNECTION"));
			cleanup_exit(255);
		}
		*cp = '\0';
	} else
		client_addr = xstrdup("UNKNOWN");

        debug("client addr is %s", client_addr);
        
	logit("session opened for local user %s from [%s]",
              NULL, client_addr);

	in = GetStdHandle(STD_INPUT_HANDLE);
	out = GetStdHandle(STD_OUTPUT_HANDLE);

	if ((iqueue = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((oqueue = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);

	if (homedir != NULL) {
		if (chdir(homedir) != 0) {
			fatal("chdir to \"%s\" failed: %lu", homedir, GetLastError());
		}
	}
	for (;;) {
		DWORD olen, bytes;
		if (sshbuf_check_reserve(oqueue, SFTP_MAX_MSG_LENGTH) == 0)
			process();

		olen = sshbuf_len(oqueue);
		if (olen > 0) {
			if (WriteFile(out, sshbuf_ptr(oqueue), olen, &bytes, NULL)) {
				if ((r = sshbuf_consume(oqueue, bytes)) != 0)
					fatal("%s: buffer error: %d", __func__, r);
				continue;
			}
			else
				fatal("%s: WriteFile failed: %lu", __func__, GetLastError());
		}

		if ((r = sshbuf_check_reserve(iqueue, sizeof(buf))) != 0)
			fatal("%s: sshbuf_check_reserve failed: %d", __func__, r);

		if (ReadFile(in, buf, sizeof(buf), &bytes, NULL)) {
			if (bytes > 0) {
				if ((r = sshbuf_put(iqueue, buf, bytes)) != 0)
					fatal("%s: buffer error: %d", __func__, r);
			}
			else {
				debug("read eof");
				cleanup_exit(0);
			}
		}
		else
			fatal("%s: ReadFile failed: %lu", __func__, GetLastError());
	}
}

static void
sanitise_stdfd(void)
{
        debug("std fds sanitized");
	// TODO: Fixme!
	return;

	/* int nullfd, dupfd; */

	/* if ((nullfd = dupfd = open("/dev/null", O_RDWR)) == -1) { */
	/* 	fprintf(stderr, "Couldn't open /dev/null: %s\n", */
	/* 	    strerror(errno)); */
	/* 	exit(1); */
	/* } */
	/* while (++dupfd <= STDERR_FILENO) { */
	/* 	/\* Only populate closed fds. *\/ */
	/* 	if (fcntl(dupfd, F_GETFL) == -1 && errno == EBADF) { */
	/* 		if (dup2(nullfd, dupfd) == -1) { */
	/* 			fprintf(stderr, "dup2: %s\n", strerror(errno)); */
	/* 			exit(1); */
	/* 		} */
	/* 	} */
	/* } */
	/* if (nullfd > STDERR_FILENO) */
	/* 	close(nullfd); */
}

int
main(int argc, char **argv)
{
	sanitise_stdfd();
	return (sftp_server_main(argc, argv));
}

