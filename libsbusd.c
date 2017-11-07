/* See LICENSE file for copyright and license details. */
#include "libsbusd.h"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>


#define STYPE_MAX(T) (long long int)((1ULL << (8 * sizeof(T) - 1)) - 1)


extern char *argv0;


void
libsbusd_weprintf(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	fprintf(stderr, "%s: ", argv0);
	vfprintf(stderr, fmt, args);
        if (strchr(fmt, '\0')[-1] == ':') {
                fputc(' ', stderr);
                perror(NULL);
        }
	va_end(args);
}

int
libsbusd_who(int fd, char *buf, const char *prefix)
{
	struct ucred cred;
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &(socklen_t){sizeof(cred)}) < 0) {
		weprintf("getsockopt <client> SOL_SOCKET SO_PEERCRED:");
		return -1;
	}
	return sprintf(buf, "%s!/cred/%lli/%lli/%lli",
	               prefix,
	               (long long int)cred.gid,
	               (long long int)cred.uid,
	               (long long int)cred.pid);
}

int
libsbusd_iscredok(int fd, const char *key, const char *prefix)
{
	struct ucred cred;
	long long int tmp;
	const char *p;
	size_t n = strlen(prefix);
	if (strncmp(key, prefix, n))
		return 0;
	key = &key[n];
	if (strncmp(key, "!/cred/", sizeof("!/cred/") - 1))
		return 0;
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &(socklen_t){sizeof(cred)}) < 0) {
		weprintf("getsockopt <client> SOL_SOCKET SO_PEERCRED:");
		return -1;
	}
	errno = 0;
	p = &key[sizeof("!/cred/") - 1];
#define TEST_CRED(ID)\
	if (!*p) {\
		return 0;\
	} else if (*p++ != '/') {\
		if (!isdigit(*p))\
			return 0;\
		tmp = strtoll(p, (void *)&p, 10);\
		if (errno || (*p && *p != '/') || (ID##_t)tmp != cred.ID)\
			return 0;\
	}
	TEST_CRED(gid);
	TEST_CRED(uid);
	TEST_CRED(pid);
#undef TEST_CRED
	return 1;
}

int
libsbusd_checkuser(int fd, uid_t *users, size_t nusers)
{
	struct ucred cred;
	size_t i;
	if (fd < 0) {
		weprintf("accept <server>:");
		return -1;
	}
	if (nusers) {
		if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &(socklen_t){sizeof(cred)}) < 0) {
			weprintf("getsockopt <client> SOL_SOCKET SO_PEERCRED:");
			close(fd);
			return -1;
		}
		for (i = nusers; i--;)
			if (users[i] == cred.uid)
				return 0;
		weprintf("rejected connection from user %li\n", (long int)cred.uid);
		close(fd);
		return -1;
	}
	return 0;
}

int
libsbusd_doessubmatch(const char *sub, const char *key)
{
	const char *sub_start = sub;
	for (;;) {
		while (*sub && *sub == *key) {
			sub++;
			key++;
		}
		if (!*key)
			return !*sub;
		if (!*sub)
			return sub == sub_start || sub[-1] == '/';
		if (*sub == '*') {
			sub++;
			while (*key && *key != '/')
				key++;
			continue;
		}
		return 0;
	}
}

int
libsbusd_issubed(char *const *subs, size_t nsubs, const char *key)
{
	while (nsubs--)
		if (libsbusd_doessubmatch(subs[nsubs], key))
			return 1;
	return 0;
}

void
libsbusd_adduser(uid_t *users, size_t *nusers, const char *arg)
{
	struct passwd *user;
	long long int tmp;
	if (!isdigit(*arg))
		goto user_by_name;
	errno = 0;
	tmp = strtoll(arg, (void *)&arg, 10);
	if (errno || *arg || tmp < 0 || tmp > STYPE_MAX(uid_t))
		goto user_by_name;
	users[(*nusers)++] = (uid_t)tmp;
	return;
user_by_name:
	user = getpwnam(arg);
	if (!user)
		eprintf("getpwnam %s:", arg);
	users[(*nusers)++] = user->pw_uid;
}

static void
randomise(void *buf, size_t n)
{
	char *p = buf;
	while (n--)
		*p++ = rand();
}

static void
print_address(struct sockaddr_un *addr)
{
	char buf[2 * sizeof(addr->sun_path) + 1];
	char *p = buf;
	const unsigned char *a = (const unsigned char *)addr->sun_path;
	size_t n = sizeof(addr->sun_path);

	for (; n--; p += 2, a += 1) {
		p[0] = "0123456789abcdef"[(int)*a >> 4];
		p[1] = "0123456789abcdef"[(int)*a & 15];
	}
	*p = '\0';

	printf("/dev/unix/abstract/%s\n", buf);
	if (fflush(stdout) || ferror(stdout))
		eprintf("failed print generated address:");
}

int
libsbusd_afunix(struct sockaddr_un *addr, int *fdp, const char *address)
{
	const char *p, *q;
	long int tmp;
	int hi, lo;
	size_t n;
	char *a;

	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;

	if (strstr(address, "/dev/fd/") == address) {
		p = &address[sizeof("/dev/fd/") - 1];
		if (!isdigit(*p))
			goto def;
		errno = 0;
		tmp = strtol(p, &a, 10);
		if (errno || *a || tmp < 0) {
			errno = 0;
			goto def;
		}
		if (tmp > INT_MAX) {
			errno = EBADF;
			return -1;
		}
		*fdp = (int)tmp;
		return LIBSBUS_AFUNIX_FD;
	} else if (!strcmp(address, "/dev/unix/abstract")) {
		return LIBSBUS_AFUNIX_RANDOM;
	} else if (strstr(address, "/dev/unix/abstract/") == address) {
		p = &address[sizeof("/dev/unix/abstract/") - 1];
		n = strlen(p);
		if (n & 1)
			goto def;
		for (q = p; *q; q++)
			if (!isxdigit(*q))
				goto def;
		if (n > sizeof(addr->sun_path) * 2) {
			errno = ENAMETOOLONG;
			return -1;
		}
		a = addr->sun_path;
		for (; *p; p += 2) {
			hi = (p[0] & 15) + 9 * !isdigit(p[0]);
			lo = (p[1] & 15) + 9 * !isdigit(p[1]);
			*a++ = (hi << 4) | lo;
		}
		return LIBSBUS_AFUNIX_ABSTRACT;
	} else {
	def:
		if (strlen(address) >= sizeof(addr->sun_path)) {
			errno = ENAMETOOLONG;
			return -1;
		}
		strcpy(addr->sun_path, address);
		return LIBSBUS_AFUNIX_CONCRETE;
	}
}

int
libsbusd_mksocket(struct sockaddr_un *addr, const char *address, int reuse, mode_t mode)
{
	int fd, randaddr = 0, listening = 0;

	switch (libsbusd_afunix(addr, &fd, address)) {
	case LIBSBUS_AFUNIX_FD:
		reuse = 0;
		break;
	case LIBSBUS_AFUNIX_RANDOM:
		randaddr = 1;
		reuse = 0;
		fd = -1;
		break;
	case LIBSBUS_AFUNIX_ABSTRACT:
		reuse = 0;
		fd = -1;
		break;
	case LIBSBUS_AFUNIX_CONCRETE:
		fd = -1;
		break;
	default:
		eprintf("bad unix socket address:");
		exit(1);
	}

	if (reuse)
		unlink(addr->sun_path);

	if (fd < 0) {
		fd = socket(PF_UNIX, SOCK_SEQPACKET, 0);
		if (fd < 0)
			eprintf("socket PF_UNIX SOCK_SEQPACKET:");
		if (fchmod(fd, mode))
			eprintf("fchmod <socket> %o:", mode);
		if (randaddr) {
			srand((unsigned)time(NULL));
			for (;;) {
				randomise(&addr->sun_path[1], sizeof(addr->sun_path) - 1);
				if (!bind(fd, (void *)addr, sizeof(*addr)))
					break;
				else if (errno != EADDRINUSE)
					eprintf("bind <random abstract address>:");
			}
			print_address(addr);
		} else {
			if (bind(fd, (void *)addr, sizeof(*addr))) {
				if (*addr->sun_path)
					eprintf("bind %s:", addr->sun_path);
				else
					eprintf("bind <abstract:%s>:", &address[sizeof("/dev/unix/abstract/") - 1]);
			}
		}
	} else {
		if (mode & 0070)
			weprintf("ignoring -g due to using passed down socket\n");
		if (mode & 0007)
			weprintf("ignoring -o due to using passed down socket\n");
		if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &listening, &(socklen_t){sizeof(listening)}))
			eprintf("getsockopt SOL_SOCKET SO_ACCEPTCONN:");
	}

	if (!listening && listen(fd, SOMAXCONN))
		eprintf("listen:");

	return fd;
}

void
libsbusd_daemonise(const char *pidfile, void (*sigexit)(int))
{
	pid_t pid;
	int rw[2], status = 0, fd;
	FILE *fp;

	if (pipe(rw))
		eprintf("pipe:");

	switch ((pid = fork())) {
	case -1:
		eprintf("fork:");

	case 0:
		close(rw[0]);
		setsid();
		switch (fork()) {
		case -1:
			eprintf("fork:");

		case 0:
			if (signal(SIGHUP, SIG_IGN) == SIG_ERR)
				weprintf("signal SIGHUP SIG_IGN:");
			if (signal(SIGINT, sigexit) == SIG_ERR)
				weprintf("signal SIGINT <exit>:");
			if (pidfile) {
				pid = getpid();
				fd = open(pidfile, O_WRONLY | O_CREAT | O_EXCL, 0644);
				if (fd < 0)
					eprintf("open %s O_WRONLY O_CREAT O_EXCL:", pidfile);
				fp = fdopen(fd, "w");
				fprintf(fp, "%li\n", (long int)pid);
				if (fflush(fp) || ferror(fp))
					eprintf("fprintf %s:", pidfile);
				fclose(fp);
			}
			if (chdir("/"))
				eprintf("chdir /:");
			close(STDIN_FILENO);
			close(STDOUT_FILENO);
			if (isatty(STDERR_FILENO)) {
				fd = open("/dev/null", O_WRONLY);
				if (fd)
					eprintf("open /dev/null O_WRONLY:");
				if (dup2(fd, STDERR_FILENO) != STDERR_FILENO)
					eprintf("dup2 /dev/null /dev/stderr:");
				close(fd);
			}
			if (write(rw[1], &status, 1) < 1)
				eprintf("write <pipe>:");
			close(rw[1]);
			break;

		default:
			exit(0);
		}
		break;

	default:
		close(rw[1]);
		if (waitpid(pid, &status, 0) != pid)
			eprintf("waitpid:");
		if (status)
			exit(1);
		switch (read(rw[0], &status, 1)) {
		case -1:
			eprintf("read <pipe>:");
		case 0:
			exit(1);
		default:
			exit(0);
		}
	}
}

void
libsbusd_initalise(int foreground, const char **pidfilep, void (*sigexit)(int))
{
	if (foreground) {
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		if (signal(SIGHUP, sigexit) == SIG_ERR)
			weprintf("signal SIGHUP <exit>:");
		if (signal(SIGINT, sigexit) == SIG_ERR)
			weprintf("signal SIGINT <exit>:");
		*pidfilep = NULL;
	} else {
		if (!strcmp(*pidfilep, "/dev/null"))
			*pidfilep = NULL;
		libsbusd_daemonise(*pidfilep, sigexit);
	}
}
