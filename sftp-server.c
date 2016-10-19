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

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>
#include <grp.h>

#include <bsd/string.h>

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
	SYSLOG_LEVEL_QUIET,
	SYSLOG_LEVEL_FATAL,
	SYSLOG_LEVEL_ERROR,
	SYSLOG_LEVEL_INFO,
	SYSLOG_LEVEL_VERBOSE,
	SYSLOG_LEVEL_DEBUG1,
	SYSLOG_LEVEL_DEBUG2,
	SYSLOG_LEVEL_DEBUG3,
	SYSLOG_LEVEL_NOT_SET = -1
}       LogLevel;

typedef struct {
	u_int32_t	flags;
	u_int64_t	size;
	u_int32_t	uid;
	u_int32_t	gid;
	u_int32_t	perm;
	u_int32_t	atime;
	u_int32_t	mtime;
} Attrib;

#define SSHBUF_SIZE_MAX		0x8000000	/* Hard maximum size */
#define SSHBUF_REFS_MAX		0x100000	/* Max child buffers */
#define SSHBUF_MAX_BIGNUM	(16384 / 8)	/* Max bignum *bytes* */
#define SSHBUF_MAX_ECPOINT	((528 * 2 / 8) + 1) /* Max EC point *bytes* */

struct sshbuf {
	u_char *d;		/* Data */
	size_t off;		/* First available byte is buf->d + buf->off */
	size_t size;		/* Last byte is buf->d + buf->size - 1 */
	size_t max_size;	/* Maximum size of buffer */
	size_t alloc;		/* Total bytes allocated to buf->d */
};

/* Our verbosity */
static LogLevel log_level = SYSLOG_LEVEL_ERROR;

/* Our client */
static struct passwd *pw = NULL;
static char *client_addr = NULL;

/* input and output queue */
struct sshbuf *iqueue;
struct sshbuf *oqueue;

/* Version of client */
static u_int version;

/* SSH2_FXP_INIT received */
static int init_done;

/* Disable writes */
static int readonly;

/* Requests that are allowed/denied */
static char *request_whitelist, *request_blacklist;

/* portable attributes, etc. */
typedef struct Stat Stat;

struct Stat {
	char *name;
	char *long_name;
	Attrib attrib;
};

/* Packet handlers */
static void process_open(u_int32_t id);
static void process_close(u_int32_t id);
static void process_read(u_int32_t id);
static void process_write(u_int32_t id);
static void process_stat(u_int32_t id);
static void process_lstat(u_int32_t id);
static void process_fstat(u_int32_t id);
static void process_setstat(u_int32_t id);
static void process_fsetstat(u_int32_t id);
static void process_opendir(u_int32_t id);
static void process_readdir(u_int32_t id);
static void process_remove(u_int32_t id);
static void process_mkdir(u_int32_t id);
static void process_rmdir(u_int32_t id);
static void process_realpath(u_int32_t id);
static void process_rename(u_int32_t id);
static void process_readlink(u_int32_t id);
static void process_symlink(u_int32_t id);
static void process_extended_posix_rename(u_int32_t id);
static void process_extended_hardlink(u_int32_t id);
static void process_extended_fsync(u_int32_t id);
static void process_extended(u_int32_t id);

struct sftp_handler {
	const char *name;	/* user-visible name for fine-grained perms */
	const char *ext_name;	/* extended request name */
	u_int type;		/* packet type, for non extended packets */
	void (*handler)(u_int32_t);
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
static void cleanup_exit(int) __attribute__((noreturn));

static void do_log(LogLevel level, const char *fmt, va_list args);

#define MINIMUM(a, b) (((a) < (b)) ? (a) : (b))
#define MAXIMUM(a, b) (((a) > (b)) ? (a) : (b))
#define HOWMANY(x, y) (((x)+((y)-1))/(y))
#define ROUNDUP(x, y) (HOWMANY(x, y) * (y))

#define MUL_NO_OVERFLOW	((size_t)1 << (sizeof(size_t) * 4))
#define SIZE_MAX ((unsigned long)-1)

static void *
xmalloc(size_t size)
{
	void *ptr;

	if (size == 0)
		fatal("xmalloc: zero size");
	ptr = malloc(size);
	if (ptr == NULL)
		fatal("xmalloc: out of memory (allocating %zu bytes)", size);
	return ptr;
}

static void *
xcalloc(size_t nmemb, size_t size)
{
	void *ptr;

	if (size == 0 || nmemb == 0)
		fatal("xcalloc: zero size");
	if (SIZE_MAX / nmemb < size)
		fatal("xcalloc: nmemb * size > SIZE_MAX");
	ptr = calloc(nmemb, size);
	if (ptr == NULL)
		fatal("xcalloc: out of memory (allocating %zu bytes)",
		    size * nmemb);
	return ptr;
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

static int
xasprintf(char **ret, const char *fmt, ...)
{
	va_list ap;
	int i;

	va_start(ap, fmt);
	i = vasprintf(ret, fmt, ap);
	va_end(ap);

	if (i < 0 || *ret == NULL)
		fatal("xasprintf: could not allocate memory");

	return (i);
}

static void *
reallocarray(void *optr, size_t nmemb, size_t size)
{
	if ((nmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
	    nmemb > 0 && SIZE_MAX / nmemb < size) {
		errno = ENOMEM;
		return NULL;
	}
	return realloc(optr, size * nmemb);
}

static void *
xreallocarray(void *ptr, size_t nmemb, size_t size)
{
	void *new_ptr;

	new_ptr = reallocarray(ptr, nmemb, size);
	if (new_ptr == NULL)
		fatal("xreallocarray: out of memory (%zu elements of %zu bytes)",
		    nmemb, size);
	return new_ptr;
}

static void
fatal(const char *fmt,...)
{
	va_list args;

	va_start(args, fmt);
	do_log(SYSLOG_LEVEL_FATAL, fmt, args);
	va_end(args);
	cleanup_exit(255);
}

static void
do_log(LogLevel level, const char *fmt, va_list args)
{
	char *txt = NULL;
	int saved_errno = errno;

	if (level > log_level)
		return;

	switch (level) {
	case SYSLOG_LEVEL_FATAL:
		txt = "fatal";
		break;
	case SYSLOG_LEVEL_ERROR:
		txt = "error";
		break;
	case SYSLOG_LEVEL_INFO:
		txt = "info";
		break;
	case SYSLOG_LEVEL_VERBOSE:
		break;
	case SYSLOG_LEVEL_DEBUG1:
		txt = "debug1";
		break;
	case SYSLOG_LEVEL_DEBUG2:
		txt = "debug2";
		break;
	case SYSLOG_LEVEL_DEBUG3:
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

	errno = saved_errno;
}

static void
verbose(const char *fmt,...)
{
	va_list args;

	va_start(args, fmt);
	do_log(SYSLOG_LEVEL_VERBOSE, fmt, args);
	va_end(args);
}

static void
logit(const char *fmt,...)
{
	va_list args;

	va_start(args, fmt);
	do_log(SYSLOG_LEVEL_INFO, fmt, args);
	va_end(args);
}

void
error(const char *fmt,...)
{
	va_list args;

	va_start(args, fmt);
	do_log(SYSLOG_LEVEL_ERROR, fmt, args);
	va_end(args);
}

void
debug(const char *fmt,...)
{
	va_list args;

	va_start(args, fmt);
	do_log(SYSLOG_LEVEL_DEBUG1, fmt, args);
	va_end(args);
}

static void
debug3(const char *fmt,...)
{
	va_list args;

	va_start(args, fmt);
	do_log(SYSLOG_LEVEL_DEBUG3, fmt, args);
	va_end(args);
}




#define	MAX_PROP	40
#define	SEP	","
static char *
match_list(const char *client, const char *server, u_int *next)
{
	char *sproposals[MAX_PROP];
	char *c, *s, *p, *ret, *cp, *sp;
	int i, j, nproposals;

	c = cp = xstrdup(client);
	s = sp = xstrdup(server);

	for ((p = strsep(&sp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&sp, SEP)), i++) {
		if (i < MAX_PROP)
			sproposals[i] = p;
		else
			break;
	}
	nproposals = i;

	for ((p = strsep(&cp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&cp, SEP)), i++) {
		for (j = 0; j < nproposals; j++) {
			if (strcmp(p, sproposals[j]) == 0) {
				ret = xstrdup(p);
				if (next != NULL)
					*next = (cp == NULL) ?
					    strlen(c) : (u_int)(cp - c);
				free(c);
				free(s);
				return ret;
			}
		}
	}
	if (next != NULL)
		*next = strlen(c);
	free(c);
	free(s);
	return NULL;
}

static void
debug2(const char *fmt,...)
{
	va_list args;

	va_start(args, fmt);
	do_log(SYSLOG_LEVEL_DEBUG2, fmt, args);
	va_end(args);
}

#define PEEK_U64(p) \
	(((u_int64_t)(((const u_char *)(p))[0]) << 56) | \
	 ((u_int64_t)(((const u_char *)(p))[1]) << 48) | \
	 ((u_int64_t)(((const u_char *)(p))[2]) << 40) | \
	 ((u_int64_t)(((const u_char *)(p))[3]) << 32) | \
	 ((u_int64_t)(((const u_char *)(p))[4]) << 24) | \
	 ((u_int64_t)(((const u_char *)(p))[5]) << 16) | \
	 ((u_int64_t)(((const u_char *)(p))[6]) << 8) | \
	  (u_int64_t)(((const u_char *)(p))[7]))
#define PEEK_U32(p) \
	(((u_int32_t)(((const u_char *)(p))[0]) << 24) | \
	 ((u_int32_t)(((const u_char *)(p))[1]) << 16) | \
	 ((u_int32_t)(((const u_char *)(p))[2]) << 8) | \
	  (u_int32_t)(((const u_char *)(p))[3]))
#define PEEK_U16(p) \
	(((u_int16_t)(((const u_char *)(p))[0]) << 8) | \
	  (u_int16_t)(((const u_char *)(p))[1]))

#define POKE_U64(p, v) \
	do { \
		const u_int64_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 56) & 0xff; \
		((u_char *)(p))[1] = (__v >> 48) & 0xff; \
		((u_char *)(p))[2] = (__v >> 40) & 0xff; \
		((u_char *)(p))[3] = (__v >> 32) & 0xff; \
		((u_char *)(p))[4] = (__v >> 24) & 0xff; \
		((u_char *)(p))[5] = (__v >> 16) & 0xff; \
		((u_char *)(p))[6] = (__v >> 8) & 0xff; \
		((u_char *)(p))[7] = __v & 0xff; \
	} while (0)
#define POKE_U32(p, v) \
	do { \
		const u_int32_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 24) & 0xff; \
		((u_char *)(p))[1] = (__v >> 16) & 0xff; \
		((u_char *)(p))[2] = (__v >> 8) & 0xff; \
		((u_char *)(p))[3] = __v & 0xff; \
	} while (0)
#define POKE_U16(p, v) \
	do { \
		const u_int16_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 8) & 0xff; \
		((u_char *)(p))[1] = __v & 0xff; \
	} while (0)


static u_int64_t
get_u64(const void *vp)
{
	const u_char *p = (const u_char *)vp;
	u_int64_t v;

	v  = (u_int64_t)p[0] << 56;
	v |= (u_int64_t)p[1] << 48;
	v |= (u_int64_t)p[2] << 40;
	v |= (u_int64_t)p[3] << 32;
	v |= (u_int64_t)p[4] << 24;
	v |= (u_int64_t)p[5] << 16;
	v |= (u_int64_t)p[6] << 8;
	v |= (u_int64_t)p[7];

	return (v);
}

static u_int32_t
get_u32(const void *vp)
{
	const u_char *p = (const u_char *)vp;
	u_int32_t v;

	v  = (u_int32_t)p[0] << 24;
	v |= (u_int32_t)p[1] << 16;
	v |= (u_int32_t)p[2] << 8;
	v |= (u_int32_t)p[3];

	return (v);
}

static u_int32_t
get_u32_le(const void *vp)
{
	const u_char *p = (const u_char *)vp;
	u_int32_t v;

	v  = (u_int32_t)p[0];
	v |= (u_int32_t)p[1] << 8;
	v |= (u_int32_t)p[2] << 16;
	v |= (u_int32_t)p[3] << 24;

	return (v);
}

static u_int16_t
get_u16(const void *vp)
{
	const u_char *p = (const u_char *)vp;
	u_int16_t v;

	v  = (u_int16_t)p[0] << 8;
	v |= (u_int16_t)p[1];

	return (v);
}

static void
put_u64(void *vp, u_int64_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 56) & 0xff;
	p[1] = (u_char)(v >> 48) & 0xff;
	p[2] = (u_char)(v >> 40) & 0xff;
	p[3] = (u_char)(v >> 32) & 0xff;
	p[4] = (u_char)(v >> 24) & 0xff;
	p[5] = (u_char)(v >> 16) & 0xff;
	p[6] = (u_char)(v >> 8) & 0xff;
	p[7] = (u_char)v & 0xff;
}

static void
put_u32(void *vp, u_int32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 24) & 0xff;
	p[1] = (u_char)(v >> 16) & 0xff;
	p[2] = (u_char)(v >> 8) & 0xff;
	p[3] = (u_char)v & 0xff;
}

static void
put_u32_le(void *vp, u_int32_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)v & 0xff;
	p[1] = (u_char)(v >> 8) & 0xff;
	p[2] = (u_char)(v >> 16) & 0xff;
	p[3] = (u_char)(v >> 24) & 0xff;
}

static void
put_u16(void *vp, u_int16_t v)
{
	u_char *p = (u_char *)vp;

	p[0] = (u_char)(v >> 8) & 0xff;
	p[1] = (u_char)v & 0xff;
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
	if ((ret = calloc(sizeof(*ret), 1)) == NULL)
		return NULL;
	ret->alloc = SSHBUF_SIZE_INIT;
	ret->max_size = SSHBUF_SIZE_MAX;
	if ((ret->d = calloc(1, ret->alloc)) == NULL) {
		free(ret);
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
	explicit_bzero(buf, sizeof(*buf));
	free(buf);
}

static size_t
sshbuf_len(const struct sshbuf *buf)
{
	if (sshbuf_check_sanity(buf) != 0)
		return 0;
	return buf->size - buf->off;
}

static const u_char *
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
sshbuf_reserve(struct sshbuf *buf, size_t len, u_char **dpp)
{
	size_t rlen, need;
	u_char *dp;
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
		if ((dp = realloc(buf->d, rlen)) == NULL) {
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
sshbuf_peek_string_direct(const struct sshbuf *buf, const u_char **valp,
			  size_t *lenp)
{
	u_int32_t len;
	const u_char *p = sshbuf_ptr(buf);

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
sshbuf_get_string_direct(struct sshbuf *buf, const u_char **valp, size_t *lenp)
{
	size_t len;
	const u_char *p;
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
sshbuf_get_string(struct sshbuf *buf, u_char **valp, size_t *lenp)
{
	const u_char *val;
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
sshbuf_get_cstring(struct sshbuf *buf, char **valp, size_t *lenp)
{
	size_t len;
	const u_char *p, *z;
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
	if ((r = sshbuf_skip_string(buf)) != 0)
		return -1;
	if (valp != NULL) {
		if ((*valp = malloc(len + 1)) == NULL) {
			return SSH_ERR_ALLOC_FAIL;
		}
		if (len != 0)
			memcpy(*valp, p, len);
		(*valp)[len] = '\0';
	}
	if (lenp != NULL)
		*lenp = (size_t)len;
	return 0;
}

static int
sshbuf_get(struct sshbuf *buf, void *v, size_t len)
{
	const u_char *p = sshbuf_ptr(buf);
	int r;

	if ((r = sshbuf_consume(buf, len)) < 0)
		return r;
	if (v != NULL && len != 0)
		memcpy(v, p, len);
	return 0;
}

static int
sshbuf_get_u64(struct sshbuf *buf, u_int64_t *valp)
{
	const u_char *p = sshbuf_ptr(buf);
	int r;

	if ((r = sshbuf_consume(buf, 8)) < 0)
		return r;
	if (valp != NULL)
		*valp = PEEK_U64(p);
	return 0;
}

static int
sshbuf_get_u32(struct sshbuf *buf, u_int32_t *valp)
{
	const u_char *p = sshbuf_ptr(buf);
	int r;

	if ((r = sshbuf_consume(buf, 4)) < 0)
		return r;
	if (valp != NULL)
		*valp = PEEK_U32(p);
	return 0;
}

static int
sshbuf_get_u16(struct sshbuf *buf, u_int16_t *valp)
{
	const u_char *p = sshbuf_ptr(buf);
	int r;

	if ((r = sshbuf_consume(buf, 2)) < 0)
		return r;
	if (valp != NULL)
		*valp = PEEK_U16(p);
	return 0;
}

static int
sshbuf_get_u8(struct sshbuf *buf, u_char *valp)
{
	const u_char *p = sshbuf_ptr(buf);
	int r;

	if ((r = sshbuf_consume(buf, 1)) < 0)
		return r;
	if (valp != NULL)
		*valp = (u_int8_t)*p;
	return 0;
}

static int
sshbuf_get_stringb(struct sshbuf *buf, struct sshbuf *v)
{
	u_int32_t len;
	u_char *p;
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
sshbuf_put_u64(struct sshbuf *buf, u_int64_t val)
{
	u_char *p;
	int r;

	if ((r = sshbuf_reserve(buf, 8, &p)) < 0)
		return r;
	POKE_U64(p, val);
	return 0;
}

static int
sshbuf_put_u32(struct sshbuf *buf, u_int32_t val)
{
	u_char *p;
	int r;

	if ((r = sshbuf_reserve(buf, 4, &p)) < 0)
		return r;
	POKE_U32(p, val);
	return 0;
}

static int
sshbuf_put_u16(struct sshbuf *buf, u_int16_t val)
{
	u_char *p;
	int r;

	if ((r = sshbuf_reserve(buf, 2, &p)) < 0)
		return r;
	POKE_U16(p, val);
	return 0;
}

static int
sshbuf_put_u8(struct sshbuf *buf, u_char val)
{
	u_char *p;
	int r;

	if ((r = sshbuf_reserve(buf, 1, &p)) < 0)
		return r;
	p[0] = val;
	return 0;
}

static int
sshbuf_put_string(struct sshbuf *buf, const void *v, size_t len)
{
	u_char *d;
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

static int
sshbuf_put_cstring(struct sshbuf *buf, const char *v)
{
	return sshbuf_put_string(buf, (u_char *)v, v == NULL ? 0 : strlen(v));
}

static int
sshbuf_put_stringb(struct sshbuf *buf, const struct sshbuf *v)
{
	return sshbuf_put_string(buf, sshbuf_ptr(v), sshbuf_len(v));
}

static int
sshbuf_put(struct sshbuf *buf, const void *v, size_t len)
{
	u_char *p;
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
	u_char *d;
	if (sshbuf_check_sanity(buf) == 0)
		explicit_bzero(buf->d, buf->alloc);
	buf->off = buf->size = 0;
	if (buf->alloc != SSHBUF_SIZE_INIT) {
		if ((d = realloc(buf->d, SSHBUF_SIZE_INIT)) != NULL) {
			buf->d = d;
			buf->alloc = SSHBUF_SIZE_INIT;
		}
	}
}

static int
request_permitted(struct sftp_handler *h)
{
	char *result;

	if (readonly && h->does_write) {
		verbose("Refusing %s request in read-only mode", h->name);
		return 0;
	}
	if (request_blacklist != NULL &&
	    ((result = match_list(h->name, request_blacklist, NULL))) != NULL) {
		free(result);
		verbose("Refusing blacklisted %s request", h->name);
		return 0;
	}
	if (request_whitelist != NULL &&
	    ((result = match_list(h->name, request_whitelist, NULL))) != NULL) {
		free(result);
		debug2("Permitting whitelisted %s request", h->name);
		return 1;
	}
	if (request_whitelist != NULL) {
		verbose("Refusing non-whitelisted %s request", h->name);
		return 0;
	}
	return 1;
}

static int
errno_to_portable(int unixerrno)
{
	int ret = 0;

	switch (unixerrno) {
	case 0:
		ret = SSH2_FX_OK;
		break;
	case ENOENT:
	case ENOTDIR:
	case EBADF:
	case ELOOP:
		ret = SSH2_FX_NO_SUCH_FILE;
		break;
	case EPERM:
	case EACCES:
	case EFAULT:
		ret = SSH2_FX_PERMISSION_DENIED;
		break;
	case ENAMETOOLONG:
	case EINVAL:
		ret = SSH2_FX_BAD_MESSAGE;
		break;
	case ENOSYS:
		ret = SSH2_FX_OP_UNSUPPORTED;
		break;
	default:
		ret = SSH2_FX_FAILURE;
		break;
	}
	return ret;
}

static int
flags_from_portable(int pflags)
{
	int flags = 0;

	if ((pflags & SSH2_FXF_READ) &&
	    (pflags & SSH2_FXF_WRITE)) {
		flags = O_RDWR;
	} else if (pflags & SSH2_FXF_READ) {
		flags = O_RDONLY;
	} else if (pflags & SSH2_FXF_WRITE) {
		flags = O_WRONLY;
	}
	if (pflags & SSH2_FXF_APPEND)
		flags |= O_APPEND;
	if (pflags & SSH2_FXF_CREAT)
		flags |= O_CREAT;
	if (pflags & SSH2_FXF_TRUNC)
		flags |= O_TRUNC;
	if (pflags & SSH2_FXF_EXCL)
		flags |= O_EXCL;
	return flags;
}

static const char *
string_from_portable(int pflags)
{
	static char ret[128];

	*ret = '\0';

#define PAPPEND(str)	{				\
		if (*ret != '\0')			\
			strlcat(ret, ",", sizeof(ret));	\
		strlcat(ret, str, sizeof(ret));		\
	}

	if (pflags & SSH2_FXF_READ)
		PAPPEND("READ")
	if (pflags & SSH2_FXF_WRITE)
		PAPPEND("WRITE")
	if (pflags & SSH2_FXF_APPEND)
		PAPPEND("APPEND")
	if (pflags & SSH2_FXF_CREAT)
		PAPPEND("CREATE")
	if (pflags & SSH2_FXF_TRUNC)
		PAPPEND("TRUNCATE")
	if (pflags & SSH2_FXF_EXCL)
		PAPPEND("EXCL")

	return ret;
}

/* handle handles */

typedef struct Handle Handle;
struct Handle {
	int use;
	DIR *dirp;
	int fd;
	int flags;
	char *name;
	u_int64_t bytes_read, bytes_write;
	int next_unused;
};

enum {
	HANDLE_UNUSED,
	HANDLE_DIR,
	HANDLE_FILE
};

Handle *handles = NULL;
u_int num_handles = 0;
int first_unused_handle = -1;

static void handle_unused(int i)
{
	handles[i].use = HANDLE_UNUSED;
	handles[i].next_unused = first_unused_handle;
	first_unused_handle = i;
}

static int
handle_new(int use, const char *name, int fd, int flags, DIR *dirp)
{
	int i;

	if (first_unused_handle == -1) {
		if (num_handles + 1 <= num_handles)
			return -1;
		num_handles++;
		handles = xreallocarray(handles, num_handles, sizeof(Handle));
		handle_unused(num_handles - 1);
	}

	i = first_unused_handle;
	first_unused_handle = handles[i].next_unused;

	handles[i].use = use;
	handles[i].dirp = dirp;
	handles[i].fd = fd;
	handles[i].flags = flags;
	handles[i].name = xstrdup(name);
	handles[i].bytes_read = handles[i].bytes_write = 0;

	return i;
}

static int
handle_is_ok(int i, int type)
{
	return i >= 0 && (u_int)i < num_handles && handles[i].use == type;
}

static int
handle_to_string(int handle, u_char **stringp, int *hlenp)
{
	if (stringp == NULL || hlenp == NULL)
		return -1;
	*stringp = xmalloc(sizeof(int32_t));
	put_u32(*stringp, handle);
	*hlenp = sizeof(int32_t);
	return 0;
}

static int
handle_from_string(const u_char *handle, u_int hlen)
{
	int val;

	if (hlen != sizeof(int32_t))
		return -1;
	val = get_u32(handle);
	if (handle_is_ok(val, HANDLE_FILE) ||
	    handle_is_ok(val, HANDLE_DIR))
		return val;
	return -1;
}

static char *
handle_to_name(int handle)
{
	if (handle_is_ok(handle, HANDLE_DIR)||
	    handle_is_ok(handle, HANDLE_FILE))
		return handles[handle].name;
	return NULL;
}

static DIR *
handle_to_dir(int handle)
{
	if (handle_is_ok(handle, HANDLE_DIR))
		return handles[handle].dirp;
	return NULL;
}

static int
handle_to_fd(int handle)
{
	if (handle_is_ok(handle, HANDLE_FILE))
		return handles[handle].fd;
	return -1;
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

static u_int64_t
handle_bytes_read(int handle)
{
	if (handle_is_ok(handle, HANDLE_FILE))
		return (handles[handle].bytes_read);
	return 0;
}

static u_int64_t
handle_bytes_write(int handle)
{
	if (handle_is_ok(handle, HANDLE_FILE))
		return (handles[handle].bytes_write);
	return 0;
}

static int
handle_close(int handle)
{
	int ret = -1;

	if (handle_is_ok(handle, HANDLE_FILE)) {
		ret = close(handles[handle].fd);
		free(handles[handle].name);
		handle_unused(handle);
	} else if (handle_is_ok(handle, HANDLE_DIR)) {
		ret = closedir(handles[handle].dirp);
		free(handles[handle].name);
		handle_unused(handle);
	} else {
		errno = ENOENT;
	}
	return ret;
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

static void
handle_log_exit(void)
{
	u_int i;

	for (i = 0; i < num_handles; i++)
		if (handles[i].use != HANDLE_UNUSED)
			handle_log_close(i, "forced");
}

static int
get_handle(struct sshbuf *queue, int *hp)
{
	u_char *handle;
	int r;
	size_t hlen;

	*hp = -1;
	if ((r = sshbuf_get_string(queue, &handle, &hlen)) != 0)
		return r;
	if (hlen < 256)
		*hp = handle_from_string(handle, hlen);
	free(handle);
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
status_to_message(u_int32_t status)
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
send_status(u_int32_t id, u_int32_t status)
{
	struct sshbuf *msg;
	int r;

	debug3("request %u: sent status %u", id, status);
	if (log_level > SYSLOG_LEVEL_VERBOSE ||
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
send_data_or_handle(char type, u_int32_t id, const u_char *data, int dlen)
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
send_data(u_int32_t id, const u_char *data, int dlen)
{
	debug("request %u: sent data len %d", id, dlen);
	send_data_or_handle(SSH2_FXP_DATA, id, data, dlen);
}

static void
send_handle(u_int32_t id, int handle)
{
	u_char *string;
	int hlen;

	handle_to_string(handle, &string, &hlen);
	debug("request %u: sent handle handle %d", id, handle);
	send_data_or_handle(SSH2_FXP_HANDLE, id, string, hlen);
	free(string);
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

static void
stat_to_attrib(const struct stat *st, Attrib *a)
{
	attrib_clear(a);
	a->flags = 0;
	a->flags |= SSH2_FILEXFER_ATTR_SIZE;
	a->size = st->st_size;
	a->flags |= SSH2_FILEXFER_ATTR_UIDGID;
	a->uid = st->st_uid;
	a->gid = st->st_gid;
	a->flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
	a->perm = st->st_mode;
	a->flags |= SSH2_FILEXFER_ATTR_ACMODTIME;
	a->atime = st->st_atime;
	a->mtime = st->st_mtime;
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
		u_char *data;
		size_t dlen;
		u_int i, count;

		if ((r = sshbuf_get_u32(b, &count)) != 0)
			fatal("%s: buffer error: %d", __func__, r);
		for (i = 0; i < count; i++) {
			if ((r = sshbuf_get_cstring(b, &type, NULL)) != 0 ||
			    (r = sshbuf_get_string(b, &data, &dlen)) != 0)
				return r;
			debug3("Got file attribute \"%.100s\" len %zu",
			    type, dlen);
			free(type);
			free(data);
		}
	}
	return 0;
}

static void
send_names(u_int32_t id, int count, const Stat *stats)
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
		if ((r = sshbuf_put_cstring(msg, stats[i].name)) != 0 ||
		    (r = sshbuf_put_cstring(msg, stats[i].long_name)) != 0 ||
		    (r = encode_attrib(msg, &stats[i].attrib)) != 0)
			fatal("%s: buffer error: %d", __func__, r);
	}
	send_msg(msg);
	sshbuf_free(msg);
}

static void
send_attrib(u_int32_t id, const Attrib *a)
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
process_open(u_int32_t id)
{
	u_int32_t pflags;
	Attrib a;
	char *name;
	int r, handle, fd, flags, mode, status = SSH2_FX_FAILURE;

	if ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &pflags)) != 0 || /* portable flags */
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug3("request %u: open flags %d", id, pflags);
	flags = flags_from_portable(pflags);
	mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ? a.perm : 0666;
	logit("open \"%s\" flags %s mode 0%o",
	    name, string_from_portable(pflags), mode);
	if (readonly &&
	    ((flags & O_ACCMODE) == O_WRONLY ||
	    (flags & O_ACCMODE) == O_RDWR)) {
		verbose("Refusing open request in read-only mode");
		status = SSH2_FX_PERMISSION_DENIED;
	} else {
		fd = open(name, flags, mode);
		if (fd < 0) {
			status = errno_to_portable(errno);
		} else {
			handle = handle_new(HANDLE_FILE, name, fd, flags, NULL);
			if (handle < 0) {
				close(fd);
			} else {
				send_handle(id, handle);
				status = SSH2_FX_OK;
			}
		}
	}
	if (status != SSH2_FX_OK)
		send_status(id, status);
	free(name);
}

static void
process_close(u_int32_t id)
{
	int r, handle, ret, status = SSH2_FX_FAILURE;

	if ((r = get_handle(iqueue, &handle)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug3("request %u: close handle %u", id, handle);
	handle_log_close(handle, NULL);
	ret = handle_close(handle);
	status = (ret == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
}

static void
process_read(u_int32_t id)
{
	u_char buf[64*1024];
	u_int32_t len;
	int r, handle, fd, ret, status = SSH2_FX_FAILURE;
	u_int64_t off;

	if ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &len)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug("request %u: read \"%s\" (handle %d) off %llu len %d",
	    id, handle_to_name(handle), handle, (unsigned long long)off, len);
	if (len > sizeof buf) {
		len = sizeof buf;
		debug2("read change len %d", len);
	}
	fd = handle_to_fd(handle);
	if (fd >= 0) {
		if (lseek(fd, off, SEEK_SET) < 0) {
			error("process_read: seek failed");
			status = errno_to_portable(errno);
		} else {
			ret = read(fd, buf, len);
			if (ret < 0) {
				status = errno_to_portable(errno);
			} else if (ret == 0) {
				status = SSH2_FX_EOF;
			} else {
				send_data(id, buf, ret);
				status = SSH2_FX_OK;
				handle_update_read(handle, ret);
			}
		}
	}
	if (status != SSH2_FX_OK)
		send_status(id, status);
}

static void
process_write(u_int32_t id)
{
	u_int64_t off;
	size_t len;
	int r, handle, fd, ret, status;
	u_char *data;

	if ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &off)) != 0 ||
	    (r = sshbuf_get_string(iqueue, &data, &len)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug("request %u: write \"%s\" (handle %d) off %llu len %zu",
	    id, handle_to_name(handle), handle, (unsigned long long)off, len);
	fd = handle_to_fd(handle);

	if (fd < 0)
		status = SSH2_FX_FAILURE;
	else {
		if (!(handle_to_flags(handle) & O_APPEND) &&
				lseek(fd, off, SEEK_SET) < 0) {
			status = errno_to_portable(errno);
			error("process_write: seek failed");
		} else {
/* XXX ATOMICIO ? */
			ret = write(fd, data, len);
			if (ret < 0) {
				error("process_write: write failed");
				status = errno_to_portable(errno);
			} else if ((size_t)ret == len) {
				status = SSH2_FX_OK;
				handle_update_write(handle, ret);
			} else {
				debug2("nothing at all written");
				status = SSH2_FX_FAILURE;
			}
		}
	}
	send_status(id, status);
	free(data);
}

static void
process_do_stat(u_int32_t id, int do_lstat)
{
	Attrib a;
	struct stat st;
	char *name;
	int r, status = SSH2_FX_FAILURE;

	if ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug3("request %u: %sstat", id, do_lstat ? "l" : "");
	verbose("%sstat name \"%s\"", do_lstat ? "l" : "", name);
	r = do_lstat ? lstat(name, &st) : stat(name, &st);
	if (r < 0) {
		status = errno_to_portable(errno);
	} else {
		stat_to_attrib(&st, &a);
		send_attrib(id, &a);
		status = SSH2_FX_OK;
	}
	if (status != SSH2_FX_OK)
		send_status(id, status);
	free(name);
}

static void
process_stat(u_int32_t id)
{
	process_do_stat(id, 0);
}

static void
process_lstat(u_int32_t id)
{
	process_do_stat(id, 1);
}

static void
process_fstat(u_int32_t id)
{
	Attrib a;
	struct stat st;
	int fd, r, handle, status = SSH2_FX_FAILURE;

	if ((r = get_handle(iqueue, &handle)) != 0)
		fatal("%s: buffer error: %d", __func__, r);
	debug("request %u: fstat \"%s\" (handle %u)",
	    id, handle_to_name(handle), handle);
	fd = handle_to_fd(handle);
	if (fd >= 0) {
		r = fstat(fd, &st);
		if (r < 0) {
			status = errno_to_portable(errno);
		} else {
			stat_to_attrib(&st, &a);
			send_attrib(id, &a);
			status = SSH2_FX_OK;
		}
	}
	if (status != SSH2_FX_OK)
		send_status(id, status);
}

static struct timeval *
attrib_to_tv(const Attrib *a)
{
	static struct timeval tv[2];

	tv[0].tv_sec = a->atime;
	tv[0].tv_usec = 0;
	tv[1].tv_sec = a->mtime;
	tv[1].tv_usec = 0;
	return tv;
}

static void
process_setstat(u_int32_t id)
{
	Attrib a;
	char *name;
	int r, status = SSH2_FX_OK;

	if ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug("request %u: setstat name \"%s\"", id, name);
	if (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
		logit("set \"%s\" size %llu",
		    name, (unsigned long long)a.size);
		r = truncate(name, a.size);
		if (r == -1)
			status = errno_to_portable(errno);
	}
	if (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		logit("set \"%s\" mode %04o", name, a.perm);
		r = chmod(name, a.perm & 07777);
		if (r == -1)
			status = errno_to_portable(errno);
	}
	if (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		char buf[64];
		time_t t = a.mtime;

		strftime(buf, sizeof(buf), "%Y%m%d-%H:%M:%S",
		    localtime(&t));
		logit("set \"%s\" modtime %s", name, buf);
		r = utimes(name, attrib_to_tv(&a));
		if (r == -1)
			status = errno_to_portable(errno);
	}
	if (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
		logit("set \"%s\" owner %lu group %lu", name,
		    (u_long)a.uid, (u_long)a.gid);
		r = chown(name, a.uid, a.gid);
		if (r == -1)
			status = errno_to_portable(errno);
	}
	send_status(id, status);
	free(name);
}

static void
process_fsetstat(u_int32_t id)
{
	Attrib a;
	int handle, fd, r;
	int status = SSH2_FX_OK;

	if ((r = get_handle(iqueue, &handle)) != 0 ||
	    (r = decode_attrib(iqueue, &a)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug("request %u: fsetstat handle %d", id, handle);
	fd = handle_to_fd(handle);
	if (fd < 0)
		status = SSH2_FX_FAILURE;
	else {
		char *name = handle_to_name(handle);

		if (a.flags & SSH2_FILEXFER_ATTR_SIZE) {
			logit("set \"%s\" size %llu",
			    name, (unsigned long long)a.size);
			r = ftruncate(fd, a.size);
			if (r == -1)
				status = errno_to_portable(errno);
		}
		if (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
			logit("set \"%s\" mode %04o", name, a.perm);
#ifdef HAVE_FCHMOD
			r = fchmod(fd, a.perm & 07777);
#else
			r = chmod(name, a.perm & 07777);
#endif
			if (r == -1)
				status = errno_to_portable(errno);
		}
		if (a.flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			char buf[64];
			time_t t = a.mtime;

			strftime(buf, sizeof(buf), "%Y%m%d-%H:%M:%S",
			    localtime(&t));
			logit("set \"%s\" modtime %s", name, buf);
#ifdef HAVE_FUTIMES
			r = futimes(fd, attrib_to_tv(&a));
#else
			r = utimes(name, attrib_to_tv(&a));
#endif
			if (r == -1)
				status = errno_to_portable(errno);
		}
		if (a.flags & SSH2_FILEXFER_ATTR_UIDGID) {
			logit("set \"%s\" owner %lu group %lu", name,
			    (u_long)a.uid, (u_long)a.gid);
#ifdef HAVE_FCHOWN
			r = fchown(fd, a.uid, a.gid);
#else
			r = chown(name, a.uid, a.gid);
#endif
			if (r == -1)
				status = errno_to_portable(errno);
		}
	}
	send_status(id, status);
}

static void
process_opendir(u_int32_t id)
{
	DIR *dirp = NULL;
	char *path;
	int r, handle, status = SSH2_FX_FAILURE;

	if ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug3("request %u: opendir", id);
	logit("opendir \"%s\"", path);
	dirp = opendir(path);
	if (dirp == NULL) {
		status = errno_to_portable(errno);
	} else {
		handle = handle_new(HANDLE_DIR, path, 0, 0, dirp);
		if (handle < 0) {
			closedir(dirp);
		} else {
			send_handle(id, handle);
			status = SSH2_FX_OK;
		}

	}
	if (status != SSH2_FX_OK)
		send_status(id, status);
	free(path);
}

#define	FMT_SCALED_STRSIZE	7
typedef enum { NONE = 0, KILO = 1, MEGA = 2, GIGA = 3, TERA = 4, PETA = 5, EXA = 6 } unit_type;

static unit_type scale_units[] = { NONE, KILO, MEGA, GIGA, TERA, PETA, EXA };
static char scale_chars[] = "BKMGTPE";
static long long scale_factors[] = {
	1LL,
	1024LL,
	1024LL*1024,
	1024LL*1024*1024,
	1024LL*1024*1024*1024,
	1024LL*1024*1024*1024*1024,
	1024LL*1024*1024*1024*1024*1024,
};
#define	SCALE_LENGTH (sizeof(scale_units)/sizeof(scale_units[0]))

#define MAX_DIGITS (SCALE_LENGTH * 3)	/* XXX strlen(sprintf("%lld", -1)? */


static int
fmt_scaled(long long number, char *result)
{
	long long abval, fract = 0;
	unsigned int i;
	unit_type unit = NONE;

	abval = (number < 0LL) ? -number : number;	/* no long long_abs yet */

	/* Not every negative long long has a positive representation.
	 * Also check for numbers that are just too darned big to format
	 */
	if (abval < 0 || abval / 1024 >= scale_factors[SCALE_LENGTH-1]) {
		errno = ERANGE;
		return -1;
	}

	/* scale whole part; get unscaled fraction */
	for (i = 0; i < SCALE_LENGTH; i++) {
		if (abval/1024 < scale_factors[i]) {
			unit = scale_units[i];
			fract = (i == 0) ? 0 : abval % scale_factors[i];
			number /= scale_factors[i];
			if (i > 0)
				fract /= scale_factors[i - 1];
			break;
		}
	}

	fract = (10 * fract + 512) / 1024;
	/* if the result would be >= 10, round main number */
	if (fract == 10) {
		if (number >= 0)
			number++;
		else
			number--;
		fract = 0;
	}

	if (number == 0)
		strlcpy(result, "0B", FMT_SCALED_STRSIZE);
	else if (unit == NONE || number >= 100 || number <= -100) {
		if (fract >= 5) {
			if (number >= 0)
				number++;
			else
				number--;
		}
		(void)snprintf(result, FMT_SCALED_STRSIZE, "%lld%c",
			number, scale_chars[unit]);
	} else
		(void)snprintf(result, FMT_SCALED_STRSIZE, "%lld.%1lld%c",
			number, fract, scale_chars[unit]);

	return 0;
}

#define	NCACHE	64			/* power of 2 */
#define	MASK	(NCACHE - 1)		/* bits to store with */
static char *
user_from_uid(uid_t uid, int nouser)
{
	static struct ncache {
		uid_t	uid;
		char	*name;
	} c_uid[NCACHE];
	static int pwopen;
	static char nbuf[15];		/* 32 bits == 10 digits */
	struct passwd *pw;
	struct ncache *cp;

	cp = c_uid + (uid & MASK);
	if (cp->uid != uid || cp->name == NULL) {
		if (pwopen == 0) {
#ifdef HAVE_SETPASSENT
			setpassent(1);
#endif
			pwopen = 1;
		}
		if ((pw = getpwuid(uid)) == NULL) {
			if (nouser)
				return (NULL);
			(void)snprintf(nbuf, sizeof(nbuf), "%u", uid);
		}
		cp->uid = uid;
		if (cp->name != NULL)
			free(cp->name);
		cp->name = strdup(pw ? pw->pw_name : nbuf);
	}
	return (cp->name);
}

static char *
group_from_gid(gid_t gid, int nogroup)
{
	static struct ncache {
		gid_t	gid;
		char	*name;
	} c_gid[NCACHE];
	static int gropen;
	static char nbuf[15];		/* 32 bits == 10 digits */
	struct group *gr;
	struct ncache *cp;

	cp = c_gid + (gid & MASK);
	if (cp->gid != gid || cp->name == NULL) {
		if (gropen == 0) {
#ifdef HAVE_SETGROUPENT
			setgroupent(1);
#endif
			gropen = 1;
		}
		if ((gr = getgrgid(gid)) == NULL) {
			if (nogroup)
				return (NULL);
			(void)snprintf(nbuf, sizeof(nbuf), "%u", gid);
		}
		cp->gid = gid;
		if (cp->name != NULL)
			free(cp->name);
		cp->name = strdup(gr ? gr->gr_name : nbuf);
	}
	return (cp->name);
}

static char *
ls_file(const char *name, const struct stat *st, int remote, int si_units)
{
	int ulen, glen, sz = 0;
	struct tm *ltime = localtime(&st->st_mtime);
	char *user, *group;
	char buf[1024], mode[11+1], tbuf[12+1], ubuf[11+1], gbuf[11+1];
	char sbuf[FMT_SCALED_STRSIZE];
	time_t now;

	strmode(st->st_mode, mode);
	if (!remote) {
		user = user_from_uid(st->st_uid, 0);
	} else {
		snprintf(ubuf, sizeof ubuf, "%u", (u_int)st->st_uid);
		user = ubuf;
	}
	if (!remote) {
		group = group_from_gid(st->st_gid, 0);
	} else {
		snprintf(gbuf, sizeof gbuf, "%u", (u_int)st->st_gid);
		group = gbuf;
	}
	if (ltime != NULL) {
		now = time(NULL);
		if (now - (365*24*60*60)/2 < st->st_mtime &&
		    now >= st->st_mtime)
			sz = strftime(tbuf, sizeof tbuf, "%b %e %H:%M", ltime);
		else
			sz = strftime(tbuf, sizeof tbuf, "%b %e  %Y", ltime);
	}
	if (sz == 0)
		tbuf[0] = '\0';
	ulen = MAXIMUM(strlen(user), 8);
	glen = MAXIMUM(strlen(group), 8);
	if (si_units) {
		fmt_scaled((long long)st->st_size, sbuf);
		snprintf(buf, sizeof buf, "%s %3u %-*s %-*s %8s %s %s", mode,
		    (u_int)st->st_nlink, ulen, user, glen, group,
		    sbuf, tbuf, name);
	} else {
		snprintf(buf, sizeof buf, "%s %3u %-*s %-*s %8llu %s %s", mode,
		    (u_int)st->st_nlink, ulen, user, glen, group,
		    (unsigned long long)st->st_size, tbuf, name);
	}
	return xstrdup(buf);
}

static void
process_readdir(u_int32_t id)
{
	DIR *dirp;
	struct dirent *dp;
	char *path;
	int r, handle;

	if ((r = get_handle(iqueue, &handle)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug("request %u: readdir \"%s\" (handle %d)", id,
	    handle_to_name(handle), handle);
	dirp = handle_to_dir(handle);
	path = handle_to_name(handle);
	if (dirp == NULL || path == NULL) {
		send_status(id, SSH2_FX_FAILURE);
	} else {
		struct stat st;
		char pathname[PATH_MAX];
		Stat *stats;
		int nstats = 10, count = 0, i;

		stats = xcalloc(nstats, sizeof(Stat));
		while ((dp = readdir(dirp)) != NULL) {
			if (count >= nstats) {
				nstats *= 2;
				stats = xreallocarray(stats, nstats, sizeof(Stat));
			}
/* XXX OVERFLOW ? */
			snprintf(pathname, sizeof pathname, "%s%s%s", path,
			    strcmp(path, "/") ? "/" : "", dp->d_name);
			if (lstat(pathname, &st) < 0)
				continue;
			stat_to_attrib(&st, &(stats[count].attrib));
			stats[count].name = xstrdup(dp->d_name);
			stats[count].long_name = ls_file(dp->d_name, &st, 0, 0);
			count++;
			/* send up to 100 entries in one message */
			/* XXX check packet size instead */
			if (count == 100)
				break;
		}
		if (count > 0) {
			send_names(id, count, stats);
			for (i = 0; i < count; i++) {
				free(stats[i].name);
				free(stats[i].long_name);
			}
		} else {
			send_status(id, SSH2_FX_EOF);
		}
		free(stats);
	}
}

static void
process_remove(u_int32_t id)
{
	char *name;
	int r, status = SSH2_FX_FAILURE;

	if ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug3("request %u: remove", id);
	logit("remove name \"%s\"", name);
	r = unlink(name);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	free(name);
}

static void
process_mkdir(u_int32_t id)
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
	r = mkdir(name, mode);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	free(name);
}

static void
process_rmdir(u_int32_t id)
{
	char *name;
	int r, status;

	if ((r = sshbuf_get_cstring(iqueue, &name, NULL)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug3("request %u: rmdir", id);
	logit("rmdir name \"%s\"", name);
	r = rmdir(name);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	free(name);
}

static void
process_realpath(u_int32_t id)
{
	char resolvedname[PATH_MAX];
	char *path;
	int r;

	if ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	if (path[0] == '\0') {
		free(path);
		path = xstrdup(".");
	}
	debug3("request %u: realpath", id);
	verbose("realpath \"%s\"", path);
	if (realpath(path, resolvedname) == NULL) {
		send_status(id, errno_to_portable(errno));
	} else {
		Stat s;
		attrib_clear(&s.attrib);
		s.name = s.long_name = resolvedname;
		send_names(id, 1, &s);
	}
	free(path);
}

static void
process_rename(u_int32_t id)
{
	char *oldpath, *newpath;
	int r, status;
	struct stat sb;

	if ((r = sshbuf_get_cstring(iqueue, &oldpath, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, NULL)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug3("request %u: rename", id);
	logit("rename old \"%s\" new \"%s\"", oldpath, newpath);
	status = SSH2_FX_FAILURE;
	if (lstat(oldpath, &sb) == -1)
		status = errno_to_portable(errno);
	else if (S_ISREG(sb.st_mode)) {
		/* Race-free rename of regular files */
		if (link(oldpath, newpath) == -1) {
			if (errno == EOPNOTSUPP || errno == ENOSYS
#ifdef EXDEV
			    || errno == EXDEV
#endif
#ifdef LINK_OPNOTSUPP_ERRNO
			    || errno == LINK_OPNOTSUPP_ERRNO
#endif
			    ) {
				struct stat st;

				/*
				 * fs doesn't support links, so fall back to
				 * stat+rename.  This is racy.
				 */
				if (stat(newpath, &st) == -1) {
					if (rename(oldpath, newpath) == -1)
						status =
						    errno_to_portable(errno);
					else
						status = SSH2_FX_OK;
				}
			} else {
				status = errno_to_portable(errno);
			}
		} else if (unlink(oldpath) == -1) {
			status = errno_to_portable(errno);
			/* clean spare link */
			unlink(newpath);
		} else
			status = SSH2_FX_OK;
	} else if (stat(newpath, &sb) == -1) {
		if (rename(oldpath, newpath) == -1)
			status = errno_to_portable(errno);
		else
			status = SSH2_FX_OK;
	}
	send_status(id, status);
	free(oldpath);
	free(newpath);
}

static void
process_readlink(u_int32_t id)
{
	int r, len;
	char buf[PATH_MAX];
	char *path;

	if ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug3("request %u: readlink", id);
	verbose("readlink \"%s\"", path);
	if ((len = readlink(path, buf, sizeof(buf) - 1)) == -1)
		send_status(id, errno_to_portable(errno));
	else {
		Stat s;

		buf[len] = '\0';
		attrib_clear(&s.attrib);
		s.name = s.long_name = buf;
		send_names(id, 1, &s);
	}
	free(path);
}

static void
process_symlink(u_int32_t id)
{
	char *oldpath, *newpath;
	int r, status;

	if ((r = sshbuf_get_cstring(iqueue, &oldpath, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, NULL)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug3("request %u: symlink", id);
	logit("symlink old \"%s\" new \"%s\"", oldpath, newpath);
	/* this will fail if 'newpath' exists */
	r = symlink(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	free(oldpath);
	free(newpath);
}

static void
process_extended_posix_rename(u_int32_t id)
{
	char *oldpath, *newpath;
	int r, status;

	if ((r = sshbuf_get_cstring(iqueue, &oldpath, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, NULL)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug3("request %u: posix-rename", id);
	logit("posix-rename old \"%s\" new \"%s\"", oldpath, newpath);
	r = rename(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	free(oldpath);
	free(newpath);
}

static void
process_extended_hardlink(u_int32_t id)
{
	char *oldpath, *newpath;
	int r, status;

	if ((r = sshbuf_get_cstring(iqueue, &oldpath, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &newpath, NULL)) != 0)
		fatal("%s: buffer error: %d", __func__, r);

	debug3("request %u: hardlink", id);
	logit("hardlink old \"%s\" new \"%s\"", oldpath, newpath);
	r = link(oldpath, newpath);
	status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	free(oldpath);
	free(newpath);
}

static void
process_extended_fsync(u_int32_t id)
{
	int handle, fd, r, status = SSH2_FX_OP_UNSUPPORTED;

	if ((r = get_handle(iqueue, &handle)) != 0)
		fatal("%s: buffer error: %d", __func__, r);
	debug3("request %u: fsync (handle %u)", id, handle);
	verbose("fsync \"%s\"", handle_to_name(handle));
	if ((fd = handle_to_fd(handle)) < 0)
		status = SSH2_FX_NO_SUCH_FILE;
	else if (handle_is_ok(handle, HANDLE_FILE)) {
		r = fsync(fd);
		status = (r == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	}
	send_status(id, status);
}

static void
process_extended(u_int32_t id)
{
	char *request;
	int i, r;

	if ((r = sshbuf_get_cstring(iqueue, &request, NULL)) != 0)
		fatal("%s: buffer error: %d", __func__, r);
	for (i = 0; extended_handlers[i].handler != NULL; i++) {
		if (strcmp(request, extended_handlers[i].ext_name) == 0) {
			if (!request_permitted(&extended_handlers[i]))
				send_status(id, SSH2_FX_PERMISSION_DENIED);
			else
				extended_handlers[i].handler(id);
			break;
		}
	}
	if (extended_handlers[i].handler == NULL) {
		error("Unknown extended request \"%.100s\"", request);
		send_status(id, SSH2_FX_OP_UNSUPPORTED);	/* MUST */
	}
	free(request);
}

/* stolen from ssh-agent */

static void
process(void)
{
	u_int msg_len;
	u_int buf_len;
	u_int consumed;
	u_char type;
	const u_char *cp;
	int i, r;
	u_int32_t id;

	buf_len = sshbuf_len(iqueue);
	if (buf_len < 5)
		return;		/* Incomplete message. */
	cp = sshbuf_ptr(iqueue);
	msg_len = get_u32(cp);
	if (msg_len > SFTP_MAX_MSG_LENGTH) {
		error("bad message from %s local user %s",
		    client_addr, pw->pw_name);
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
				if (!request_permitted(&handlers[i])) {
					send_status(id,
					    SSH2_FX_PERMISSION_DENIED);
				} else {
					handlers[i].handler(id);
				}
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
	if (pw != NULL && client_addr != NULL) {
		logit("session closed for local user %s from [%s]",
		    pw->pw_name, client_addr);
	}
	_exit(i);
}

static void
sftp_server_usage(void)
{
	extern char *__progname;

	fprintf(stderr,
	    "usage: %s [-ehR] [-d start_directory] [-f log_facility] "
	    "[-l log_level]\n\t[-P blacklisted_requests] "
	    "[-p whitelisted_requests] [-u umask]\n"
	    "       %s -Q protocol_feature\n",
	    __progname, __progname);
	exit(1);
}

static struct passwd *
pwcopy(struct passwd *pw)
{
	struct passwd *copy = xcalloc(1, sizeof(*copy));

	copy->pw_name = xstrdup(pw->pw_name);
	copy->pw_passwd = xstrdup(pw->pw_passwd);
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	copy->pw_gecos = xstrdup(pw->pw_gecos);
#endif
	copy->pw_uid = pw->pw_uid;
	copy->pw_gid = pw->pw_gid;
#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	copy->pw_expire = pw->pw_expire;
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	copy->pw_change = pw->pw_change;
#endif
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	copy->pw_class = xstrdup(pw->pw_class);
#endif
	copy->pw_dir = xstrdup(pw->pw_dir);
	copy->pw_shell = xstrdup(pw->pw_shell);
	return copy;
}

static struct {
	const char *name;
	LogLevel val;
} log_levels[] =
{
	{ "QUIET",	SYSLOG_LEVEL_QUIET },
	{ "FATAL",	SYSLOG_LEVEL_FATAL },
	{ "ERROR",	SYSLOG_LEVEL_ERROR },
	{ "INFO",	SYSLOG_LEVEL_INFO },
	{ "VERBOSE",	SYSLOG_LEVEL_VERBOSE },
	{ "DEBUG",	SYSLOG_LEVEL_DEBUG1 },
	{ "DEBUG1",	SYSLOG_LEVEL_DEBUG1 },
	{ "DEBUG2",	SYSLOG_LEVEL_DEBUG2 },
	{ "DEBUG3",	SYSLOG_LEVEL_DEBUG3 },
	{ NULL,		SYSLOG_LEVEL_NOT_SET }
};

static LogLevel
log_level_number(char *name)
{
	int i;

	if (name != NULL)
		for (i = 0; log_levels[i].name; i++)
			if (strcasecmp(log_levels[i].name, name) == 0)
				return log_levels[i].val;
	return SYSLOG_LEVEL_NOT_SET;
}

char *
tilde_expand_filename(const char *filename, uid_t uid)
{
	const char *path, *sep;
	char user[128], *ret;
	struct passwd *pw;
	u_int len, slash;

	if (*filename != '~')
		return (xstrdup(filename));
	filename++;

	path = strchr(filename, '/');
	if (path != NULL && path > filename) {		/* ~user/path */
		slash = path - filename;
		if (slash > sizeof(user) - 1)
			fatal("tilde_expand_filename: ~username too long");
		memcpy(user, filename, slash);
		user[slash] = '\0';
		if ((pw = getpwnam(user)) == NULL)
			fatal("tilde_expand_filename: No such user %s", user);
	} else if ((pw = getpwuid(uid)) == NULL)	/* ~/path */
		fatal("tilde_expand_filename: No such uid %ld", (long)uid);

	/* Make sure directory has a trailing '/' */
	len = strlen(pw->pw_dir);
	if (len == 0 || pw->pw_dir[len - 1] != '/')
		sep = "/";
	else
		sep = "";

	/* Skip leading '/' from specified path */
	if (path != NULL)
		filename = path + 1;

	if (xasprintf(&ret, "%s%s%s", pw->pw_dir, sep, filename) >= PATH_MAX)
		fatal("tilde_expand_filename: Path too long");

	return (ret);
}

static char *
percent_expand(const char *string, ...)
{
#define EXPAND_MAX_KEYS	16
	u_int num_keys, i, j;
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
sftp_server_main(int argc, char **argv, struct passwd *user_pw)
{
	fd_set *rset, *wset;
	int i, r, in, out, max, ch, skipargs = 0, log_stderr = 0;
	ssize_t len, olen, set_size;
	char *cp, *homedir = NULL, buf[4*4096];
	long mask;

	extern char *optarg;
	extern char *__progname;

	// __progname = ssh_get_progname(argv[0]);

	pw = pwcopy(user_pw);

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
			log_stderr = 1;
			break;
		case 'l':
			log_level = log_level_number(optarg);
			if (log_level == SYSLOG_LEVEL_NOT_SET)
				error("Invalid log level \"%s\"", optarg);
			break;
		case 'f':
			break;
		case 'd':
			cp = tilde_expand_filename(optarg, user_pw->pw_uid);
			homedir = percent_expand(cp, "d", user_pw->pw_dir,
			    "u", user_pw->pw_name, (char *)NULL);
			free(cp);
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
		case 'u':
			errno = 0;
			mask = strtol(optarg, &cp, 8);
			if (mask < 0 || mask > 0777 || *cp != '\0' ||
			    cp == optarg || (mask == 0 && errno != 0))
				fatal("Invalid umask \"%s\"", optarg);
			(void)umask((mode_t)mask);
			break;
		case 'h':
		default:
			sftp_server_usage();
		}
	}

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

	logit("session opened for local user %s from [%s]",
	    pw->pw_name, client_addr);

	in = STDIN_FILENO;
	out = STDOUT_FILENO;

#ifdef HAVE_CYGWIN
	setmode(in, O_BINARY);
	setmode(out, O_BINARY);
#endif

	max = 0;
	if (in > max)
		max = in;
	if (out > max)
		max = out;

	if ((iqueue = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((oqueue = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);

	rset = xcalloc(HOWMANY(max + 1, NFDBITS), sizeof(fd_mask));
	wset = xcalloc(HOWMANY(max + 1, NFDBITS), sizeof(fd_mask));

	if (homedir != NULL) {
		if (chdir(homedir) != 0) {
			error("chdir to \"%s\" failed: %s", homedir,
			    strerror(errno));
		}
	}

	set_size = HOWMANY(max + 1, NFDBITS) * sizeof(fd_mask);
	for (;;) {
		memset(rset, 0, set_size);
		memset(wset, 0, set_size);

		/*
		 * Ensure that we can read a full buffer and handle
		 * the worst-case length packet it can generate,
		 * otherwise apply backpressure by stopping reads.
		 */
		if ((r = sshbuf_check_reserve(iqueue, sizeof(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue,
		    SFTP_MAX_MSG_LENGTH)) == 0)
			FD_SET(in, rset);
		else if (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal("%s: sshbuf_check_reserve failed: %d",
			    __func__, r);

		olen = sshbuf_len(oqueue);
		if (olen > 0)
			FD_SET(out, wset);

		if (select(max+1, rset, wset, NULL, NULL) < 0) {
			if (errno == EINTR)
				continue;
			error("select: %s", strerror(errno));
			cleanup_exit(2);
		}

		/* copy stdin to iqueue */
		if (FD_ISSET(in, rset)) {
			len = read(in, buf, sizeof buf);
			if (len == 0) {
				debug("read eof");
				cleanup_exit(0);
			} else if (len < 0) {
				error("read: %s", strerror(errno));
				cleanup_exit(1);
			} else if ((r = sshbuf_put(iqueue, buf, len)) != 0) {
				fatal("%s: buffer error: %d",
				    __func__, r);
			}
		}
		/* send oqueue to stdout */
		if (FD_ISSET(out, wset)) {
			len = write(out, sshbuf_ptr(oqueue), olen);
			if (len < 0) {
				error("write: %s", strerror(errno));
				cleanup_exit(1);
			} else if ((r = sshbuf_consume(oqueue, len)) != 0) {
				fatal("%s: buffer error: %d",
				    __func__, r);
			}
		}

		/*
		 * Process requests from client if we can fit the results
		 * into the output buffer, otherwise stop processing input
		 * and let the output queue drain.
		 */
		r = sshbuf_check_reserve(oqueue, SFTP_MAX_MSG_LENGTH);
		if (r == 0)
			process();
		else if (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal("%s: sshbuf_check_reserve: %d",
			    __func__, r);
	}
}

static void
sanitise_stdfd(void)
{
	int nullfd, dupfd;

	if ((nullfd = dupfd = open("/dev/null", O_RDWR)) == -1) {
		fprintf(stderr, "Couldn't open /dev/null: %s\n",
		    strerror(errno));
		exit(1);
	}
	while (++dupfd <= STDERR_FILENO) {
		/* Only populate closed fds. */
		if (fcntl(dupfd, F_GETFL) == -1 && errno == EBADF) {
			if (dup2(nullfd, dupfd) == -1) {
				fprintf(stderr, "dup2: %s\n", strerror(errno));
				exit(1);
			}
		}
	}
	if (nullfd > STDERR_FILENO)
		close(nullfd);
}

int
main(int argc, char **argv)
{
	struct passwd *user_pw;

	sanitise_stdfd();

	if ((user_pw = getpwuid(getuid())) == NULL) {
		fprintf(stderr, "No user found for uid %lu\n",
		    (u_long)getuid());
		return 1;
	}

	return (sftp_server_main(argc, argv, user_pw));
}

