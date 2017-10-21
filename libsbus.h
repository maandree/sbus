/* See LICENSE file for copyright and license details. */
#ifndef LIBSBUS_H
#define LIBSBUS_H

#include <stdlib.h>

#define LIBSBUS_BUFFER_SIZE ((3UL << 17) - 1UL)

enum libsbus_packet_type {
	LIBSBUS_UNKNOWN,
	LIBSBUS_MESSAGE
};

struct libsbus_unknown {
	enum libsbus_packet_type type;
	size_t n;
};

struct libsbus_message {
	enum libsbus_packet_type type;
	char *key;
	char *msg;
	size_t n;
};

union libsbus_packet {
	enum libsbus_packet_type type;
	struct libsbus_unknown unknown;
	struct libsbus_message message;
};

int libsbus_subscribe(int fd, const char *pattern, int flags, char *buf);
int libsbus_unsubscribe(int fd, const char *pattern, int flags, char *buf);
int libsbus_publish(int fd, const char *key, const char *msg, size_t n, int flags, char *buf);
ssize_t libsbuf_prepare_message(const char *key, char *buf, size_t *remaining);
int libsbus_receive(int fd, int flags, char *buf, union libsbus_packet *packet);

#endif
