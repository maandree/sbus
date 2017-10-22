/* See LICENSE file for copyright and license details. */
#include "libsbus.h"
#include <sys/socket.h>
#include <errno.h>
#include <string.h>

int
libsbus_subscribe(int fd, const char *pattern, int flags, char *buf)
{
	size_t n = strlen(pattern);
	if (n + 4 > LIBSBUS_BUFFER_SIZE) {
		errno = EMSGSIZE;
		return -1;
	}
	buf[0] = 'S', buf[1] = 'U', buf[2] = 'B', buf[3] = ' ';
	memcpy(&buf[4], pattern, n);
	return -(send(fd, buf, n + 4, flags) < 0);
}

int
libsbus_unsubscribe(int fd, const char *pattern, int flags, char *buf)
{
	size_t n = strlen(pattern);
	if (n + 6 > LIBSBUS_BUFFER_SIZE) {
		errno = EMSGSIZE;
		return -1;
	}
	buf[0] = 'U', buf[1] = 'N', buf[2] = 'S', buf[3] = 'U', buf[4] = 'B', buf[5] = ' ';
	memcpy(&buf[6], pattern, n);
	return -(send(fd, buf, n + 6, flags) < 0);
}

int
libsbus_publish(int fd, const char *key, const char *msg, size_t n, int flags, char *buf)
{
	size_t len = strlen(key) + 1;
	if (len + n > LIBSBUS_BUFFER_SIZE - 4) {
		errno = EMSGSIZE;
		return -1;
	}
	buf[0] = 'M', buf[1] = 'S', buf[2] = 'G', buf[3] = ' ';
	memcpy(&buf[4], key, len);
	memcpy(&buf[4 + len], msg, n);
	return -(send(fd, buf, len + n + 4, flags) < 0);
}

ssize_t
libsbuf_prepare_message(const char *key, char *buf, size_t *remaining)
{
	size_t len = strlen(key) + 1;
	if (len > LIBSBUS_BUFFER_SIZE - 4) {
		errno = EMSGSIZE;
		return -1;
	}
	buf[0] = 'M', buf[1] = 'S', buf[2] = 'G', buf[3] = ' ';
	memcpy(&buf[4], key, len);
	len += 4;
	*remaining = LIBSBUS_BUFFER_SIZE - len;
	return (ssize_t)len;
}

int
libsbus_send_cmsg(int fd, const char *key, const char *msg, size_t n, int flags, char *buf)
{
	size_t len = strlen(key) + 1;
	if (len + n > LIBSBUS_BUFFER_SIZE - 5) {
		errno = EMSGSIZE;
		return -1;
	}
	buf[0] = 'C', buf[1] = 'M', buf[2] = 'S', buf[3] = 'G', buf[4] = ' ';
	memcpy(&buf[5], key, len);
	memcpy(&buf[5 + len], msg, n);
	return -(send(fd, buf, len + n + 5, flags) < 0);
}

int
libsbus_receive(int fd, int flags, char *buf, union libsbus_packet *packet)
{
	ssize_t r;
	char *p;

	r = recv(fd, buf, LIBSBUS_BUFFER_SIZE, flags);
	if (r <= 0) {
		if (!r)
			errno = ECONNRESET;
		return -1;
	}

	if (r >= 4 && !strncmp(buf, "MSG ", 4)) {
		p = memchr(buf, '\0', r);
		if (!p++)
			goto unknown;
		packet->type = LIBSBUS_MESSAGE;
		packet->message.key = &buf[4];
		packet->message.msg = p;
		packet->message.n = (size_t)(r - (p - buf));
	} else if (r >= 5 && !strncmp(buf, "CMSG ", 5)) {
		p = memchr(buf, '\0', r);
		if (!p++)
			goto unknown;
		packet->type = LIBSBUS_CONTROL_MESSAGE;
		packet->message.key = &buf[4];
		packet->message.msg = p;
		packet->message.n = (size_t)(r - (p - buf));
	} else {
	unknown:
		packet->type = LIBSBUS_UNKNOWN;
		packet->unknown.n = (size_t)r;
	}
	return 0;
}
