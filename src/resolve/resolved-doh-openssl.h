/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if !ENABLE_DNS_OVER_HTTPS
#error This source file requires DNS-over-HTTPS to be enabled and OpenSSL to be available.
#endif

#include <openssl/ssl.h>
#include <stdbool.h>

struct DnsHttpsManagerData {
        SSL_CTX *ctx;
};

struct DnsHttpsServerData {
        SSL_SESSION *session;
};

struct DnsHttpsStreamData {
        int handshake;
        bool shutdown;
        SSL *ssl;
        BUF_MEM *write_buffer;
        size_t buffer_offset;
};

void ssl_with_fd(int sockfd);
