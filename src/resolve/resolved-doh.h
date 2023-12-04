/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if ENABLE_DNS_OVER_HTTPS

#include <stdint.h>
#include <sys/uio.h>

typedef struct DnsServer DnsServer;
typedef struct DnsStream DnsStream;
typedef struct DnsHttpsManagerData DnsHttpsManagerData;
typedef struct DnsHttpsServerData DnsHttpsServerData;
typedef struct DnsHttpsStreamData DnsHttpsStreamData;
typedef struct Manager Manager;

#include "resolved-dnstls-openssl.h"

#define DOH_STREAM_CLOSED 1

int doh_stream_connect_tls(DnsStream *stream, DnsServer *server);
void doh_stream_free(DnsStream *stream);
int doh_stream_on_io(DnsStream *stream, uint32_t revents);
int doh_stream_shutdown(DnsStream *stream, int error);
ssize_t doh_stream_writev(DnsStream *stream, const struct iovec *iov, size_t iovcnt);
ssize_t doh_stream_read(DnsStream *stream, void *buf, size_t count);

void doh_server_free(DnsServer *server);

int doh_manager_init(Manager *manager);
void doh_manager_free(Manager *manager);

#endif /* ENABLE_DNS_OVER_TLS */
