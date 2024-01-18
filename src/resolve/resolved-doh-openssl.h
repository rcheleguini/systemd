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


/* struct __attribute__((__packed__)) dns_header { */
struct dns_header {
  char id[2];
  char flags[2];
  char qdcount[2];
  char ancount[2];
  char nscount[2];
  char arcount[2];
};

typedef struct {
  char *http_status;
  char *http_header;
  int http_header_len;
  char *dns_data;
  int dns_data_len;
} doh_response;

typedef struct {
        char method[32];
        char header_host[40];
        char header_agent[40];
        char header_accept[12];
        char header_connection[16];
        char body[512];
} doh_request;

int parse_http(const char *req);
int doh_stream_split_http(DnsStream *s);
doh_response *parse_doh_response(char *response);
void free_doh_response(doh_response *doh);
char *base64url_encode_byte_by_byte(const unsigned char *data, size_t len);
char *base64url_encode(const uint8_t *data, size_t len);
void remove_padding(char *str);
