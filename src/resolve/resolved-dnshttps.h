
/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if !ENABLE_DNS_OVER_HTTPS
#error This source file requires DNS-over-HTTPS to be enabled and OpenSSL to be available.
#endif

typedef struct {
  char *http_status;
  char *http_header;
  int http_header_len;
  char *dns_data;
  int dns_data_len;
} dnshttps_response;

typedef struct {
        char method[32];
        char header_host[40];
        char header_agent[40];
        char header_accept[12];
        char header_connection[16];
        char body[512];
} dnshttps_request;

int dnshttps_stream_split_http(DnsStream *s);
dnshttps_response *parse_dnshttps_response(char *response);
void remove_padding(char *str);
