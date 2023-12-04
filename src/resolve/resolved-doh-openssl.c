/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if !ENABLE_DNS_OVER_HTTPS
#error This source file requires DNS-over-HTTPS to be enabled and OpenSSL to be available.
#endif

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "io-util.h"
#include "openssl-util.h"
#include "resolved-dns-stream.h"
#include "resolved-doh.h"
#include "resolved-manager.h"

static char *doh_error_string(int ssl_error, char *buf, size_t count) {

        return "";
}

#define DOH_ERROR_BUFSIZE 256
#define DOH_ERROR_STRING(error) \
        doh_error_string((error), (char[DOH_ERROR_BUFSIZE]){}, DOH_ERROR_BUFSIZE)

static int doh_flush_write_buffer(DnsStream *stream) {

        return 0;
}

int doh_stream_connect_tls(DnsStream *stream, DnsServer *server) {

        return 0;
}

void doh_stream_free(DnsStream *stream) {

}

int doh_stream_on_io(DnsStream *stream, uint32_t revents) {

        return 0;
}

int doh_stream_shutdown(DnsStream *stream, int error) {

        return 0;
}

static ssize_t doh_stream_write(DnsStream *stream, const char *buf, size_t count) {

        return 8;
}

ssize_t doh_stream_writev(DnsStream *stream, const struct iovec *iov, size_t iovcnt) {

        return 8;
}

ssize_t doh_stream_read(DnsStream *stream, void *buf, size_t count) {

        return 8;
}

void doh_server_free(DnsServer *server) {

}

int doh_manager_init(Manager *manager) {

        return 0;
}

void doh_manager_free(Manager *manager) {

}
