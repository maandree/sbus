/* See LICENSE file for copyright and license details. */
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <alloca.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "arg.h"
#include "libsbusd.h"

enum blocking_mode {
	BLOCKING_QUEUE,
	BLOCKING_DISCARD,
	BLOCKING_BLOCK,
	BLOCKING_ERROR
};

enum order {
	ORDER_QUEUE = 0,
	ORDER_STACK = 1,
	ORDER_RANDOM_QUEUE = 2,
	ORDER_RANDOM_STACK = 3,
};
#define ORDER_RANDOM 2

enum client_flags {
	ECHO_OFF = 1
};

struct client {
	int fd;
	enum blocking_mode soft_blocking_mode;
	enum blocking_mode hard_blocking_mode;
	enum order order;
	enum client_flags flags;
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
static size_t nusers = 0;
static const char *pidfile = "/run/sbus.pid";
static const char *credprefix = "";

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-a address] [-f | -p pidfile] [-u user] ... [-cgor]\n", argv0);
	exit(1);
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
	cl->soft_blocking_mode = BLOCKING_QUEUE;
	cl->hard_blocking_mode = BLOCKING_DISCARD;
	cl->order = ORDER_RANDOM_QUEUE;
	cl->flags = 0;
	cl->subs = NULL;
	cl->nsubs = 0;
	cl->subs_siz = 0;
	DLLIST_ADD_BEFORE(cl, &tail);
	return cl;
}

static void
remove_client(struct client *cl)
{
	close(cl->fd);
	DLLIST_REMOVE(cl);
	while (cl->nsubs--)
		free(cl->subs[cl->nsubs]);
	free(cl->subs);
	free(cl);
}

static void
accept_client(int fd)
{
	struct epoll_event ev;
	if (libsbusd_checkuser(fd, users, nusers))
		return;
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
is_subscription_acceptable(struct client *cl, const char *key)
{
	if (!strncmp(key, "!/cred/", sizeof("!/cred/") - 1))
		return libsbusd_iscredok(cl->fd, key, credprefix);
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
		weprintf("client subscribed to unacceptable routing key\n");
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
	/* TODO honour cl->soft_blocking_mode, cl->hard_blocking_mode, and cl->order */
	return -(send(cl->fd, buf, n, 0) < 0);
}

static void
handle_cmsg(struct client *cl, char *buf, size_t n)
{
	int r;
	if (!strcmp(buf, "CMSG !/cred/whoami")) {
		n = sizeof("CMSG !/cred/whoami");
		n += (size_t)(r = libsbusd_who(cl->fd, &buf[n], credprefix));
		if (r < 0) {
			remove_client(cl);
			return;
		}
		if (send_packet(cl, buf, n)) {
			weprintf("send <client>:");
			remove_client(cl);
		}
	} else if (!strcmp(buf, "CMSG blocking/soft/queue")) {
		cl->soft_blocking_mode = BLOCKING_QUEUE;
	} else if (!strcmp(buf, "CMSG blocking/soft/discard")) {
		cl->soft_blocking_mode = BLOCKING_DISCARD;
	} else if (!strcmp(buf, "CMSG blocking/soft/block")) {
		cl->soft_blocking_mode = BLOCKING_BLOCK;
	} else if (!strcmp(buf, "CMSG blocking/soft/error")) {
		cl->soft_blocking_mode = BLOCKING_ERROR;
	} else if (!strcmp(buf, "CMSG blocking/hard/discard")) {
		cl->hard_blocking_mode = BLOCKING_DISCARD;
	} else if (!strcmp(buf, "CMSG blocking/hard/block")) {
		cl->hard_blocking_mode = BLOCKING_BLOCK;
	} else if (!strcmp(buf, "CMSG blocking/hard/error")) {
		cl->hard_blocking_mode = BLOCKING_ERROR;
	} else if (!strcmp(buf, "CMSG order/queue")) {
		cl->order = ORDER_QUEUE;
	} else if (!strcmp(buf, "CMSG order/stack")) {
		cl->order = ORDER_STACK;
	} else if (!strcmp(buf, "CMSG order/random")) {
		cl->order |= ORDER_RANDOM;
	} else if (!strcmp(buf, "CMSG echo/off")) {
		cl->flags |= ECHO_OFF;
	} else if (!strcmp(buf, "CMSG echo/on")) {
		cl->flags &= ~ECHO_OFF;
	}
}

static void
broadcast(const char *msg, size_t n, struct client *ignore)
{
	struct client *cl = head.next, *tmp;
	for (; cl->next; cl = cl->next) {
		if (cl == ignore)
			continue;
		if (!libsbusd_issubed(cl->subs, cl->nsubs, &msg[4]))
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
	static char buf[409600 + 1];
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
		broadcast(buf, r, (cl->flags & ECHO_OFF) ? cl : NULL);
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

int
main(int argc, char *argv[])
{
	struct epoll_event evs[32];
	const char *address = "/run/sbus.socket";
	int auto_close = 0;
	int foreground = 0;
	mode_t mode = 0700;
	int reuse_address = 0;
	int server, n;

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
		libsbusd_adduser(users, &nusers, EARGF());
		break;
	default:
		usage();
	} ARGEND;
	if (argc)
		usage();

	umask(0);
	server = libsbusd_mksocket(&addr, address, reuse_address, mode);
	libsbusd_initalise(foreground, &pidfile, sigexit);
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
