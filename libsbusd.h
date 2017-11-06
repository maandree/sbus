/* See LICENSE file for copyright and license details. */
#ifndef LIBSBUSD_H
#define LIBSBUSD_H

#include <sys/un.h>
#include <stdlib.h>

enum {
	LIBSBUS_AFUNIX_FD,
	LIBSBUS_AFUNIX_RANDOM,
	LIBSBUS_AFUNIX_ABSTRACT,
	LIBSBUS_AFUNIX_CONCRETE
};

#ifndef eprintf
# define eprintf(...) (libsbusd_weprintf(__VA_ARGS__), exit(1))
#endif

void libsbusd_weprintf(const char *, ...);
#ifndef weprintf
# define weprintf libsbusd_weprintf
#endif

int libsbusd_doessubmatch(const char *, const char *);
int libsbusd_issubed(char *const *, size_t, const char *);
void libsbusd_adduser(uid_t *, size_t *, const char *);
void libsbusd_daemonise(const char *, void (*)(int));
int libsbusd_afunix(struct sockaddr_un *, int *, const char *);
int libsbusd_mksocket(struct sockaddr_un *, const char *, int, mode_t);
void libsbusd_initalise(int, const char **, void (*)(int));

#endif
