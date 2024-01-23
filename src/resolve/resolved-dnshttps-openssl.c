/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if !ENABLE_DNS_OVER_HTTPS
#error This source file requires DNS-over-HTTPS to be enabled and OpenSSL to be available.
#endif

#include "resolved-dns-stream.h"
#include "resolved-dnshttps.h"
#include "resolved-manager.h"
#include "hexdecoct.h"
#include "build.h"

dnshttps_response *parse_dnshttps_response(char *response) {

        puts("parse_dnshttps_response");
        int i = 0;
        int r;

        for (i = 0; i < 1024; ++i){
                printf("%c", response[i * sizeof(char)]);
        }

        dnshttps_response *dnshttps = malloc(sizeof(dnshttps_response));

        // find the start of response body (the DNS packet)
        char *dns_start = memmem(response, 1024, "\r\n\r\n", sizeof(char) * 4);

        /* if (!dns_start) { */
        /*         dnshttps->http_header = response; */
        /*         dnshttps->http_header_len = strlen(response); */
        /*         dnshttps->dns_data = NULL; */
        /*         dnshttps->dns_data_len = 0; */
        /*         return dnshttps; */
        /* } */

        dnshttps->http_header = response;
        dnshttps->http_header_len = dns_start - response;

        _cleanup_free_ char *header_copy = NULL;

        header_copy = malloc(dnshttps->http_header_len);
        memcpy(header_copy, dnshttps->http_header, dnshttps->http_header_len);

        puts("header_copy");

        char *header_status = NULL;
        header_status = strtok(header_copy, "\r\n");
        header_status = strtok(header_status, " ");
        header_status = strtok(NULL, " ");

        int status = atoi(header_status);

        switch(status){
        case 200:
                puts("HTTP 200 ok, proceeding to copy body content/dns packet...");
                // the 4 here is to skip the http separator "\r\n\r\n"
                dnshttps->dns_data = dns_start + 4;
                break;
        default:
                printf("\n\nHTTP not ok, fail now, reponse code: %d", status);
                /* TODO: handle errors here */
                break;
        }

        /* TODO: parse and confirm Content-Type: application/dns-message */

        return dnshttps;
}

int dnshttps_stream_split_http(DnsStream *s){
        puts("dnshttps_split_http");

        char *p_data;
        p_data = DNS_PACKET_DATA(s->read_packet);

        int i = 0;
        /* char* charPtr = (char*)s->read_packet; */

        for (i = 0; i < s->read_packet->size; ++i){
                printf("%c", p_data[i * sizeof(char)]);
        }

        dnshttps_response *dnshttps = parse_dnshttps_response(p_data);

        /* pure dns packet size is total read size minus headers */
        dnshttps->dns_data_len = s->read_packet->size - dnshttps->http_header_len;

        printf("\nHTTP header:\n%.*s\n", dnshttps->http_header_len, dnshttps->http_header);
        printf("DNS data:\n%.*s\n", dnshttps->dns_data_len, dnshttps->dns_data);

        /* replace the whole HTTP response with the pure DNS packet */
        memcpy(p_data, dnshttps->dns_data, dnshttps->dns_data_len);

        return 0;
}

// remove trailing '=' characters from a base64
void remove_padding(char *str) {
    size_t len = strlen(str);

    while (len > 0 && str[len - 1] == '=') {
        str[--len] = '\0';
    }
}

/* should take the packet wire format and construct a http request, wire format*/
int dnshttps_packet_to_base64url(DnsTransaction *t){
        printf("\n in tcp, about to make base64url...\n");

        uint8_t *p_data = DNS_PACKET_DATA(t->sent);
        uint16_t p_id = DNS_PACKET_ID(t->sent);

        /* puts("zeroing id..."); */
        p_data[0] = 0;
        p_data[1] = 0;

        p_id = DNS_PACKET_ID(t->sent);

        _cleanup_free_ char *dnshttps_url = NULL;

        puts("");

        // 40 bytes approx, is the packet size in wireshark
        /* TODO: what about the url safe base64? */
        int r = base64mem_full(p_data, t->sent->size, 56, &dnshttps_url);
        remove_padding(dnshttps_url);

        char get_request[512] = "";

        char header_host[32] = "";
        snprintf(header_host, sizeof(header_host), "Host: %s\r\n", t->server->server_string);

        char header_agent[64] = "";
        snprintf(header_agent, sizeof(header_agent), "User-Agent: systemd-resolved/%s\r\n", STRINGIFY(PROJECT_VERSION));


        strcpy(get_request, "GET /dns-query?dns=");
        strcat(get_request, dnshttps_url);
        strcat(get_request, " HTTP/1.1\r\n");
        strcat(get_request, header_host);
        strcat(get_request, header_agent);
        strcat(get_request, "Connection: Close\r\n");
        strcat(get_request, "\r\n");

        puts(get_request);
        printf("assigning request to stream: %p\n", t->stream);
        strcpy(t->stream->dnshttps_sent, get_request);

        return 0;
}
