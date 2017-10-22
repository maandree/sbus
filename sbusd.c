/* See LICENSE file for copyright and license details. */
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <alloca.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stropts.h>
#include <time.h>
#include <unistd.h>

#include "arg.h"

#define STYPE_MAX(T) (long long int)((1ULL << (8 * sizeof(T) - 1)) - 1)
#define eprintf(...) (weprintf(__VA_ARGS__), exit(1))

struct client {
	int fd;
	char **subs;
	size_t nsubs;
	size_t subs_siz;
	struct client *prev;
	struct client *next;
};

char *argv0;
static struct client head;
static struct client tail;
static int epfd;
static int had_client = 0;
static struct sockaddr_un addr;
static uid_t *users;
static size_t nusers;
static const char *pidfile = "/run/sbus.pid";

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-a address] [-f | -p pidfile] [-u user] ... [-cgor]\n", argv0);
	exit(1);
}

static void
weprintf(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
        if (strchr(fmt, '\0')[-1] == ':') {
                fputc(' ', stderr);
                perror(NULL);
        }
	va_end(args);
}

static void
sigexit(int signo)
{
	if (*addr.sun_path)
		if (unlink(addr.sun_path))
			weprintf("unlink %s:", addr.sun_path);
	if (pidfile)
		if (unlink(pidfile))
			weprintf("unlink %s:", pidfile);
	exit(0);
	(void) signo;
}

static struct client *
add_client(int fd)
{
	struct client *cl;
	cl = malloc(sizeof(*cl));
	if (!cl)
		return NULL;
	cl->fd = fd;
	cl->subs = NULL;
	cl->nsubs = 0;
	cl->subs_siz = 0;
	cl->next = &tail;
	cl->prev = tail.prev;
	tail.prev->next = cl;
	tail.prev = cl;
	return cl;
}

static void
remove_client(struct client *cl)
{
	close(cl->fd);
	cl->prev->next = cl->next;
	cl->next->prev = cl->prev;
	while (cl->nsubs--)
		free(cl->subs[cl->nsubs]);
	free(cl->subs);
	free(cl);
}

static void
accept_client(int fd)
{
	struct ucred cred;
	struct epoll_event ev;
	size_t i;
	if (fd < 0) {
		weprintf("accept <server>:");
		return;
	}
	if (nusers) {
		if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &(socklen_t){sizeof(cred)}) < 0) {
			weprintf("getsockopt <client> SOL_SOCKET SO_PEERCRED:");
			close(fd);
			return;
		}
		for (i = nusers; i--;)
			if (users[i] == cred.uid)
				goto cred_ok;
		weprintf("rejected connection from user %li\n", (long int)cred.uid);
		close(fd);
		return;
	}
cred_ok:
	ev.events = EPOLLIN | EPOLLRDHUP;
	ev.data.ptr = add_client(fd);
	if (!ev.data.ptr) {
		close(fd);
	} else if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev)) {
		weprintf("epoll_ctl EPOLL_CTL_ADD <client>:");
		remove_client((void *)ev.data.ptr);
	} else {
		had_client = 1;
	}
}

static int
is_subscription_match(const char *sub, const char *key)
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
			return sub == sub_start || sub[-1] == '.';
		if (*sub == '*') {
			sub++;
			while (*key && *key != '.')
				key++;
			continue;
		}
		return 0;
	}
}

static int
is_subscribed(const struct client *cl, const char *key)
{
	size_t i = cl->nsubs;
	while (i--)
		if (is_subscription_match(cl->subs[i], key))
			return 1;
	return 0;
}

static int
is_subscription_acceptable(struct client *cl, const char *key)
{
	struct ucred cred;
	long long int tmp;
	const char *p;
	if (!strncmp(key, "!.cred.", sizeof("!.cred.") - 1)) {
		if (getsockopt(cl->fd, SOL_SOCKET, SO_PEERCRED, &cred, &(socklen_t){sizeof(cred)}) < 0) {
			weprintf("getsockopt <client> SOL_SOCKET SO_PEERCRED:");
			return -1;
		}
		errno = 0;
		p = &key[sizeof("!.cred.") - 1];
#define TEST_CRED(ID)\
		if (!*p) {\
			return 0;\
		} else if (*p++ != '.') {\
			if (!isdigit(*p))\
				return 0;\
			tmp = strtoll(p, (void *)&p, 10);\
			if (errno || (*p && *p != '.') || (ID##_t)tmp != cred.ID)\
				return 0;\
		}
		TEST_CRED(gid);
		TEST_CRED(uid);
		TEST_CRED(pid);
#undef TEST_CRED
	}
	return 1;
}

static void
add_subscription(struct client *cl, const char *key)
{
	size_t n;
	char **new, *k;
	switch (is_subscription_acceptable(cl, key)) {
	case -1:
		remove_client(cl);
		return;
	case 0:
		weprintf("client subscribed unacceptable routing key\n");
		remove_client(cl);
		return;
	default:
		break;
	}
	if (cl->subs_siz == cl->nsubs) {
		n = cl->subs_siz ? (cl->subs_siz << 1) : 1;
		new = realloc(cl->subs, n * sizeof(char *));
		if (!new) {
			weprintf("realloc:");
			remove_client(cl);
			return;
		}
		cl->subs = new;
		cl->subs_siz = n;
	}
	k = strdup(key);
	if (!k) {
		weprintf("strdup:");
		remove_client(cl);
		return;
	}
	cl->subs[cl->nsubs++] = k;
}

static void
remove_subscription(struct client *cl, const char *key)
{
	size_t i = cl->nsubs;
	char **new;
	while (i--) {
		if (!strcmp(key, cl->subs[i])) {
			free(cl->subs[i]);
			memmove(&cl->subs[i], &cl->subs[i + 1], --(cl->nsubs) - i);
			if (cl->subs_siz >= 4 * cl->nsubs) {
				new = realloc(cl->subs, cl->nsubs * sizeof(char *));
				if (new) {
					cl->subs_siz = cl->nsubs;
					cl->subs = new;
				}
			}
			break;
		}
	}
}

static int
send_packet(struct client *cl, const char *buf, size_t n)
{
	/* TODO queue instead of block */
	return -(send(cl->fd, buf, n, 0) < 0);
}

static void
handle_cmsg(struct client *cl, const char *msg, size_t n)
{
	if (!strcmp(msg, "CMSG !.cred.prefix")) {
		n = sizeof("CMSG !.cred.prefix");
	} else {
		return;
	}
	if (send_packet(cl, msg, n)) {
		weprintf("send <client>:");
		remove_client(cl);
	}
}

static void
broadcast(const char *msg, size_t n)
{
	struct client *cl = head.next, *tmp;
	for (; cl->next; cl = cl->next) {
		if (!is_subscribed(cl, &msg[4]))
			continue;
		if (send_packet(cl, msg, n)) {
			cl = (tmp = cl)->prev;
			weprintf("send <client>:");
			remove_client(tmp);
		}
	}
}

static void
handle_message(struct client *cl)
{
	static char buf[3 << 17];
	int fd = cl->fd;
	ssize_t r;

	r = recv(fd, buf, sizeof(buf) - 1, 0);
	if (r < 0) {
		weprintf("recv <client>:");
		remove_client(cl);
		return;
	}
	buf[r] = '\0';

	if (!strncmp(buf, "MSG ", 4)) {
		broadcast(buf, r);
	} else if (!strncmp(buf, "UNSUB ", 6)) {
		remove_subscription(cl, &buf[6]);
	} else if (!strncmp(buf, "SUB ", 4)) {
		add_subscription(cl, &buf[4]);
	} else if (!strncmp(buf, "CMSG ", 5)) {
		handle_cmsg(cl, buf, r);
	} else {
		weprintf("received bad message\n");
		remove_client(cl);
	}
}

static void
randomise(void *buf, size_t n)
{
	char *p = buf;
	while (n--)
		*p++ = rand();
}

static void
print_address(void)
{
	char buf[2 * sizeof(addr.sun_path) + 1];
	char *p = buf;
	const unsigned char *a = (const unsigned char *)addr.sun_path;
	size_t n = sizeof(addr.sun_path);

	for (; n--; p += 2, a += 1) {
		p[0] = "0123456789abcdef"[(int)*a >> 4];
		p[1] = "0123456789abcdef"[(int)*a & 15];
	}
	*p = '\0';

	printf("/dev/unix/abstract/%s\n", buf);
	if (fflush(stdout) || ferror(stdout))
		eprintf("failed print generated address:");
}

static int
make_socket(const char *address, int reuse, mode_t mode)
{
	int fd = -1, randaddr = 0, hi, lo, listening = 0;
	long int tmp;
	size_t n;
	const char *p, *q;
	char *a;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

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
			goto bad_address;
		}
		fd = (int)tmp;
		reuse = 0;
	} else if (!strcmp(address, "/dev/unix/abstract")) {
		randaddr = 1;
		reuse = 0;
	} else if (strstr(address, "/dev/unix/abstract/") == address) {
		p = &address[sizeof("/dev/unix/abstract/") - 1];
		n = strlen(p);
		if (n & 1)
			goto def;
		for (q = p; *q; q++)
			if (!isxdigit(*q))
				goto def;
		if (n > sizeof(addr.sun_path) * 2) {
			errno = ENAMETOOLONG;
			goto bad_address;
		}
		a = addr.sun_path;
		for (; *p; p += 2) {
			hi = (p[0] & 15) + 9 * !isdigit(p[0]);
			lo = (p[1] & 15) + 9 * !isdigit(p[1]);
			*a++ = (hi << 4) | lo;
		}
		reuse = 0;
	} else {
	def:
		if (strlen(address) >= sizeof(addr.sun_path)) {
			errno = ENAMETOOLONG;
			goto bad_address;
		}
		strcpy(addr.sun_path, address);
	}

	if (reuse)
		unlink(addr.sun_path);

	if (fd < 0) {
		fd = socket(PF_UNIX, SOCK_SEQPACKET, 0);
		if (fd < 0)
			eprintf("socket PF_UNIX SOCK_SEQPACKET:");
		if (fchmod(fd, mode))
			eprintf("fchmod <socket> %o:", mode);
		if (randaddr) {
			srand((unsigned)time(NULL));
			for (;;) {
				randomise(&addr.sun_path[1], sizeof(addr.sun_path) - 1);
				if (!bind(fd, (void *)&addr, sizeof(addr)))
					break;
				else if (errno != EADDRINUSE)
					eprintf("bind <random abstract address>:");
			}
			print_address();
		} else {
			if (bind(fd, (void *)&addr, sizeof(addr))) {
				if (*addr.sun_path)
					eprintf("bind %s:", addr.sun_path);
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

bad_address:
	eprintf("bad unix socket address:");
	exit(1);
}

static void
daemonise(void)
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

int
main(int argc, char *argv[])
{
	struct epoll_event evs[32];
	const char *address = "/run/sbus.socket";
	int auto_close = 0;
	int foreground = 0;
	mode_t mode = 0700;
	int reuse_address = 0;
	struct passwd *user;
	int server, n;
	long long int tmp;
	char *arg;

	users = alloca(argc * sizeof(*users));

	ARGBEGIN {
	case 'a':
		address = EARGF();
		break;
	case 'c':
		auto_close = 1;
		break;
	case 'f':
		foreground = 1;
		break;
	case 'g':
		mode |= 0070;
		break;
	case 'o':
		mode |= 0007;
		break;
	case 'p':
		pidfile = EARGF();
		break;
	case 'r':
		reuse_address = 1;
		break;
	case 'u':
		arg = EARGF();
		if (!isdigit(*arg))
			goto user_by_name;
		errno = 0;
		tmp = strtoll(arg, &arg, 10);
		if (errno || *arg || tmp < 0 || tmp > STYPE_MAX(uid_t))
			goto user_by_name;
		users[nusers++] = (uid_t)tmp;
	user_by_name:
		user = getpwnam(arg);
		if (!user)
			eprintf("getpwnam %s:", arg);
		users[nusers++] = user->pw_uid;
		break;
	default:
		usage();
	} ARGEND;
	if (argc)
		usage();

	umask(0);
	server = make_socket(address, reuse_address, mode);
	if (foreground) {
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		if (signal(SIGHUP, sigexit) == SIG_ERR)
			weprintf("signal SIGHUP <exit>:");
		if (signal(SIGINT, sigexit) == SIG_ERR)
			weprintf("signal SIGINT <exit>:");
		pidfile = NULL;
	} else {
		if (!strcmp(pidfile, "/dev/null"))
			pidfile = NULL;
		daemonise();
	}

	if (nusers)
		users[nusers++] = getuid();

	head.next = &tail;
	tail.prev = &head;

	epfd = epoll_create1(0);
	if (epfd < 0)
		eprintf("epoll_create1:");

	evs->events = EPOLLIN;
	evs->data.ptr = NULL;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, server, evs))
		eprintf("epoll_ctl EPOLL_CTL_ADD <socket>:");

	while (!auto_close || !had_client || head.next->next) {
		n = epoll_wait(epfd, evs, sizeof(evs) / sizeof(*evs), -1);
		if (n < 0)
			eprintf("epoll_wait:");
		while (n--) {
			if (!evs[n].data.ptr)
				accept_client(accept(server, NULL, NULL));
			else if (evs[n].events & (EPOLLRDHUP | EPOLLHUP))
				remove_client((void *)evs[n].data.ptr);
			else
				handle_message((void *)evs[n].data.ptr);
		}
	}

	sigexit(0);
}
