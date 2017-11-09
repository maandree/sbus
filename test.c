#include "libsbus.h"

#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static pid_t pid;

#define assert(e)\
	(errno = 0, (e) ? 0 :\
	 (fprintf(stderr, "FAILURE: %s; errno=%s; line=%i\n",\
	          #e, strerror(errno), __LINE__), exit(1), 0))

static void
touch(const char *path)
{
	int fd;
	assert((fd = open(path, O_WRONLY | O_CREAT, 0)) > 0);
	close(fd);
}

static void
pdeath()
{
	prctl(PR_SET_PDEATHSIG, SIGKILL);
}

static void
randomise(void *buf, size_t n)
{
	char *p = buf;
	while (n--)
		*p++ = rand();
}

static void
hexaddr(char *buf, const char *addr, size_t n)
{
	const unsigned char *a = (const unsigned char *)addr;
	for (; n--; a++, buf += 2) {
		buf[0] = "0123456789abcdef"[*a >> 4];
		buf[1] = "0123456789abcdef"[*a & 15];
	}
	*buf = '\0';
}


static int
start_random(int autoclose)
{
	struct sockaddr_un addr;
	const char *autoclose_str = "-c";
	char buf[512], *p;
	int rw[2], hi, lo, fd;
	size_t i;
	alarm(1);
	if (!autoclose)
		autoclose_str = NULL;
	assert(!pipe(rw));
	assert((pid = fork()) != -1);
	if (!pid) {
		alarm(1);
		close(rw[0]);
		pdeath();
		if (rw[1] != STDOUT_FILENO) {
			assert(dup2(rw[1], STDOUT_FILENO) == STDOUT_FILENO);
			close(rw[1]);
		}
		assert(!execl("./sbusd", "./sbusd", "-fa/dev/unix/abstract", autoclose_str, NULL));
		abort();
	}
	close(rw[1]);
	assert(read(rw[0], buf, sizeof(buf)) == sizeof("/dev/unix/abstract/") + 2 * sizeof(addr.sun_path));
	assert(buf[sizeof("/dev/unix/abstract/") + 2 * sizeof(addr.sun_path) - 1] == '\n');
	assert(!strncmp(buf, "/dev/unix/abstract/", sizeof("/dev/unix/abstract/") - 1));
	p = &buf[sizeof("/dev/unix/abstract/") - 1];
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	for (i = 0; i < sizeof(addr.sun_path); i++, p += 2) {
		assert(isxdigit(p[0]));
		assert(isxdigit(p[1]));
		hi = (p[0] & 15) + 9 * !isdigit(p[0]);
		lo = (p[1] & 15) + 9 * !isdigit(p[1]);
		addr.sun_path[i] = (hi << 4) | lo;
	}
	assert(!read(rw[0], buf, sizeof(buf)));
	close(rw[0]);
	assert((fd = socket(PF_UNIX, SOCK_SEQPACKET, 0)) >= 0);
	assert(!connect(fd, (struct sockaddr *)&addr, (socklen_t)sizeof(addr)));
	return fd;
}

static int
start_abstract(int autoclose)
{
	struct sockaddr_un addr;
	const char *autoclose_str = "-c";
	char buf[512];
	int rw[2], fd;
	alarm(1);
	if (!autoclose)
		autoclose_str = NULL;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	randomise(addr.sun_path, sizeof(addr.sun_path));
	*addr.sun_path = '\0';
	assert(!pipe(rw));
	assert((pid = fork()) != -1);
	if (!pid) {
		alarm(1);
		close(rw[0]);
		pdeath();
		if (rw[1] != STDOUT_FILENO) {
			assert(dup2(rw[1], STDOUT_FILENO) == STDOUT_FILENO);
			close(rw[1]);
		}
		sprintf(buf, "/dev/unix/abstract/");
		hexaddr(&buf[sizeof("/dev/unix/abstract/") - 1], addr.sun_path, sizeof(addr.sun_path));
		assert(!execl("./sbusd", "./sbusd", "-fa", buf, autoclose_str, NULL));
		abort();
	}
	close(rw[1]);
	assert(!read(rw[0], buf, sizeof(buf)));
	close(rw[0]);
	assert((fd = socket(PF_UNIX, SOCK_SEQPACKET, 0)) >= 0);
	assert(!connect(fd, (struct sockaddr *)&addr, (socklen_t)sizeof(addr)));
	return fd;
}

static int
start_fd(int autoclose, int call_listen)
{
	struct sockaddr_un addr;
	const char *autoclose_str = "-c";
	char buf[512];
	int rw[2], fd;
	alarm(1);
	if (!autoclose)
		autoclose_str = NULL;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	randomise(addr.sun_path, sizeof(addr.sun_path));
	*addr.sun_path = '\0';
	assert((fd = socket(PF_UNIX, SOCK_SEQPACKET, 0)) >= 0);
	if (fd < 3) {
		assert(dup2(fd, 9) == 9);
		close(fd);
		fd = 9;
	}
	assert(!bind(fd, (struct sockaddr *)&addr, (socklen_t)sizeof(addr)));
	if (call_listen)
		assert(!listen(fd, 1));
	assert(!pipe(rw));
	assert((pid = fork()) != -1);
	if (!pid) {
		alarm(1);
		close(rw[0]);
		pdeath();
		if (rw[1] != STDOUT_FILENO) {
			assert(dup2(rw[1], STDOUT_FILENO) == STDOUT_FILENO);
			close(rw[1]);
		}
		sprintf(buf, "/dev/fd/%i", fd);
		assert(!execl("./sbusd", "./sbusd", "-fa", buf, autoclose_str, NULL));
		abort();
	}
	close(rw[1]);
	assert(!read(rw[0], buf, sizeof(buf)));
	close(rw[0]);
	close(fd);
	assert((fd = socket(PF_UNIX, SOCK_SEQPACKET, 0)) >= 0);
	assert(!connect(fd, (struct sockaddr *)&addr, (socklen_t)sizeof(addr)));
	return fd;
}

static int
start_path(const char *path, int autoclose, int reuse, int group, int other)
{
	struct sockaddr_un addr;
	char flags[8], *p;
	const char *cflags;
	int rw[2], fd;
	alarm(1);
	p = flags;
	*p++ = '-';
	if (autoclose)
		*p++ = 'c';
	if (reuse)
		*p++ = 'r';
	if (group)
		*p++ = 'g';
	if (other)
		*p++ = 'o';
	*p++ = '\0';
	cflags = strlen(flags) > 1 ? flags : NULL;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);
	assert(!pipe(rw));
	assert((pid = fork()) != -1);
	if (!pid) {
		alarm(1);
		close(rw[0]);
		pdeath();
		if (rw[1] != STDOUT_FILENO) {
			assert(dup2(rw[1], STDOUT_FILENO) == STDOUT_FILENO);
			close(rw[1]);
		}
		assert(!execl("./sbusd", "./sbusd", "-fa", path, cflags, NULL));
		abort();
	}
	close(rw[1]);
	assert(!read(rw[0], &fd, 1));
	close(rw[0]);
	assert((fd = socket(PF_UNIX, SOCK_SEQPACKET, 0)) >= 0);
	assert(!connect(fd, (struct sockaddr *)&addr, (socklen_t)sizeof(addr)));
	return fd;
}

static void
check_mode(const char *path, mode_t mode)
{
	struct stat st;
	assert(!stat(path, &st));
	assert((st.st_mode & 07777) == mode);
}

static void
stop(int fd, int autoclose)
{
	int status;
	if (!autoclose)
		kill(pid, SIGINT);
	else
		close(fd);
	assert(waitpid(pid, &status, 0) == pid);
	assert(!status);
	if (!autoclose)
		close(fd);
}

static void
check(int fd)
{
	char buf[LIBSBUS_BUFFER_SIZE], key[512], msg[512];
	union libsbus_packet packet;
	size_t i;

	alarm(1);
	assert(!libsbus_subscribe(fd, "test/", 0, buf));
	assert(!libsbus_subscribe(fd, "discard", 0, buf));
	assert(!libsbus_unsubscribe(fd, "discard", 0, buf));
	assert(!libsbus_publish(fd, "discard", "not caught", strlen("not caught"), 0, buf));
	for (i = 0; i < 100; i++) {
		sprintf(key, "test/%zu", i);
		sprintf(msg, "%zu", i);
		assert(!libsbus_publish(fd, key, msg, strlen(msg), 0, buf));
	}
	for (i = 0; i < 100; i++) {
		sprintf(key, "test/%zu", i);
		sprintf(msg, "%zu", i);
		assert(!libsbus_receive(fd, 0, buf, &packet));
		assert(packet.type == LIBSBUS_MESSAGE);
		assert(!strcmp(packet.message.key, key));
		assert(packet.message.n == strlen(msg));
		assert(!memcmp(packet.message.msg, msg, strlen(msg)));
	}
	assert(libsbus_receive(fd, MSG_DONTWAIT, buf, &packet) < 0);
}

int
main(void)
{
	int fd, autoclose, status, reuse;
	struct stat _st;
	pid_t pid;

	srand((unsigned)time(NULL));

	for (autoclose = 0; autoclose < 2; autoclose++) {
		fd = start_random(autoclose);
		check(fd);
		stop(fd, autoclose);

		fd = start_abstract(autoclose);
		check(fd);
		stop(fd, autoclose);

		fd = start_fd(autoclose, 0);
		check(fd);
		stop(fd, autoclose);

		fd = start_fd(autoclose, 1);
		check(fd);
		stop(fd, autoclose);

		fd = start_path(".test.sock", autoclose, 1, 0, 0);
		check(fd);
		stop(fd, autoclose);

		assert(stat(".test.sock", &_st));
		touch(".test.sock");

		for (reuse = 2; reuse--;) {
			fd = start_path(".test.sock", autoclose, reuse, 0, 0);
			check_mode(".test.sock", 0700);
			check(fd);
			stop(fd, autoclose);

			fd = start_path(".test.sock", autoclose, reuse, 1, 0);
			check_mode(".test.sock", 0770);
			check(fd);
			stop(fd, autoclose);

			fd = start_path(".test.sock", autoclose, reuse, 0, 1);
			check_mode(".test.sock", 0707);
			check(fd);
			stop(fd, autoclose);

			fd = start_path(".test.sock", autoclose, reuse, 1, 1);
			check_mode(".test.sock", 0777);
			check(fd);
			stop(fd, autoclose);
		}
	}

	touch(".test.sock");
	assert((pid = fork()) != -1);
	alarm(1);
	if (!pid) {
		pdeath();
		fd = open("/dev/null", O_WRONLY);
		if (fd >= 0 && fd != STDERR_FILENO)
			dup2(fd, STDERR_FILENO);
		assert(!execl("./sbusd", "./sbusd", "-fa.test.sock", NULL));
		abort();
	}
	assert(waitpid(pid, &status, 0) == pid);
	assert(status);
	unlink(".test.sock");

	return 0;
}

/* TODO untested sbusd flags: -p[/dev/null] (-f) -u */
/* TODO test credentials */
/* TODO CMSG echo/{off,on} */
