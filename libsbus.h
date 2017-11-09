/* See LICENSE file for copyright and license details. */
#ifndef LIBSBUS_H
#define LIBSBUS_H

#include <stdlib.h>

#define LIBSBUS_BUFFER_SIZE 409600

#define LIBSBUS_CMSG_WHOAMI                "!/cred/whoami",         NULL, 0
#define LIBSBUS_CMSG_BLOCKING_SOFT_QUEUE   "blocking/soft/queue",   NULL, 0
#define LIBSBUS_CMSG_BLOCKING_SOFT_DISCARD "blocking/soft/discard", NULL, 0
#define LIBSBUS_CMSG_BLOCKING_SOFT_BLOCK   "blocking/soft/block",   NULL, 0
#define LIBSBUS_CMSG_BLOCKING_SOFT_ERROR   "blocking/soft/error",   NULL, 0
#define LIBSBUS_CMSG_BLOCKING_HARD_DISCARD "blocking/hard/discard", NULL, 0
#define LIBSBUS_CMSG_BLOCKING_HARD_BLOCK   "blocking/hard/block",   NULL, 0
#define LIBSBUS_CMSG_BLOCKING_HARD_ERROR   "blocking/hard/error",   NULL, 0
#define LIBSBUS_CMSG_ORDER_QUEUE           "order/queue",           NULL, 0
#define LIBSBUS_CMSG_ORDER_STACK           "order/stack",           NULL, 0
#define LIBSBUS_CMSG_ORDER_RANDOM          "order/random",          NULL, 0
#define LIBSBUS_CMSG_ECHO_OFF              "echo/off",              NULL, 0
#define LIBSBUS_CMSG_ECHO_ON               "echo/on",               NULL, 0

enum libsbus_packet_type {
	LIBSBUS_UNKNOWN,
	LIBSBUS_MESSAGE,
	LIBSBUS_CONTROL_MESSAGE
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
int libsbus_send_cmsg(int fd, const char *key, const char *msg, size_t n, int flags, char *buf);
ssize_t libsbuf_prepare_message(const char *key, char *buf, size_t *remaining);
int libsbus_receive(int fd, int flags, char *buf, union libsbus_packet *packet);

#endif
