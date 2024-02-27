/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if !ENABLE_DNS_OVER_HTTPS
#error This source file requires DNS-over-HTTPS to be enabled and OpenSSL to be available.
#endif

#include "resolved-dns-stream.h"
#include "resolved-dnshttps.h"
#include "resolved-manager.h"
#include "hexdecoct.h"
#include "build.h"
#include "string.h"
#include <curl/curl.h>
#include "curl-util.h"

static char *dnshttps_current_header_field = NULL;
static Hashmap *dnshttps_parser_data = NULL;



static void my_debug(){

}


static int curl_dnshttps_packet_to_base64url(DnsTransaction *t, char **output){
        printf("\n in tcp, about to make base64url...\n");

        uint8_t *p_data = DNS_PACKET_DATA(t->sent);
        size_t url_len;

        _cleanup_free_ char *dnshttps_url = NULL;

        /* puts("zeroing id..."); */
        p_data[0] = 0;
        p_data[1] = 0;


        /* TODO: what about base64url? Normal base64 seems to be working just fine*/
        int r = base64mem_full(p_data, t->sent->size, MAX_URL_LENGTH, output);
        if (r < 0){
                log_debug_errno(r, "Failed to encode DNS packet to base64.");
                return r;
        }

        // clean base64 trailing charecters
        /* url_len = strlen(dnshttps_url); */
        /* while (url_len > 0 && dnshttps_url[url_len - 1] == '=') { */
        /*         dnshttps_url[--url_len] = '\0'; */
        /* } */

        /* output = dnshttps_url; */

        return 0;

}

// Callback function to handle the response headers
static size_t headerCallback(void* contents, size_t size, size_t nmemb, void* userdata) {
    // Print the received headers
    printf("Received Headers:\n%.*s", (int)(size * nmemb), (char*)contents);
    return size * nmemb;
}

// Callback function to handle the response body
static size_t bodyCallback(void* contents, size_t size, size_t nmemb, void* userdata) {
    // Print the received body
    printf("Received Body:\n%.*s", (int)(size * nmemb), (char*)contents);
    size_t realsize = size * nmemb;

    char *data = (char *)userdata;

    memcpy(data, contents, realsize);
    return size * nmemb;
}

static curl_socket_t opensocket_callback(void *clientp, curlsocktype purpose, struct curl_sockaddr *address) {
  curl_socket_t sockfd;
  sockfd = *(curl_socket_t *)clientp;
  /* the actual externally set socket is passed in via the OPENSOCKETDATA
     option */

  return sockfd;
}

int dnshttps_curl_send(DnsTransaction *t, int fd, int af, DnsPacket *p){
        int r;
        CURL* curl;
        CURLcode res;

        /* r = dnshttps_packet_to_base64url(t); */
        /* if (r < 0) */
        /*         return r; */

        _cleanup_(curl_glue_unrefp) CurlGlue *g = NULL;
        CURL *curl2;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;

        r = curl_glue_new(&g, e);

        g->on_finished = my_debug;

        char *url_base64 = NULL;
        r = curl_dnshttps_packet_to_base64url(t, &url_base64);

        char get_request[512] = "";
        /* useragent = strjoina(program_invocation_short_name, "/" GIT_VERSION); */

        char *response_body_buf = NULL;
        response_body_buf = malloc(512);

        /* strcpy(get_request, "https://"); */
        /* strcat(get_request, t->server->server_string); */
        /* strcat(get_request, "/dns-query?dns="); */
        /* strcat(get_request, url_base64); */

        /* r = curl_glue_make(&curl2, get_request, response_body_buf); */

        /* curl_easy_setopt(curl2, CURLOPT_WRITEFUNCTION, bodyCallback); */
        /* curl_easy_setopt(curl2, CURLOPT_WRITEDATA, (void *)response_body_buf); */

        /* r = curl_glue_add(g, curl2); */

        /* return 0; */


        // old libcurl, working but reseting t->state to PENDING


        // Initialize libcurl
        curl_global_init(CURL_GLOBAL_DEFAULT);


        /* char *url_base64 = NULL; */
        r = curl_dnshttps_packet_to_base64url(t, &url_base64);

        /* char get_request[512] = ""; */
        /* useragent = strjoina(program_invocation_short_name, "/" GIT_VERSION); */

        strcpy(get_request, "https://");
        strcat(get_request, t->server->server_string);
        strcat(get_request, "/dns-query?dns=");
        strcat(get_request, url_base64);

        /* response */
        /* char *response_body_buf = NULL; */
        response_body_buf = malloc(512);
        memset(response_body_buf, 0, 512);

        // Create a curl handle
        curl = curl_easy_init();
        if (curl) {
                // Set the URL to send the request to
                /* curl_easy_setopt(curl, CURLOPT_URL, "https://google.com"); */
                curl_easy_setopt(curl, CURLOPT_URL, get_request);

                // Set the callback functions for headers and body
                curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, headerCallback);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, bodyCallback);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)response_body_buf);

                curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, opensocket_callback);
                curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, &fd);


                // Perform the HTTP request
                res = curl_easy_perform(curl);

                // Check for errors
                if (res != CURLE_OK)
                        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

                /* Check for content-type: application/dns-message */
                /* h = curl_easy_header(curl, "Content-Type", 0, CURLH_HEADER, -1, &type); */

                /* TODO: replace 1 with the body size */
                r = dns_packet_new(&t->received, DNS_PROTOCOL_DNS, 1, DNS_PACKET_SIZE_MAX);
                if (r < 0){
                        puts("bad dns packet new");
                        return -1;
                }



                uint8_t *p_data = DNS_PACKET_DATA(t->received);

                // Write response as received packet
                memcpy(p_data, response_body_buf, 512);

                t->received->size = 512;
                t->received->ipproto = IPPROTO_TCP;



                r = dns_packet_validate_reply(t->received);
                if (r < 0){
                        puts("bad validate");
                        return -1;
                }

                /* t->state = DNS_TRANSACTION_PENDING; */
                dns_transaction_process_reply(t, t->received, false);


                // Cleanup
                curl_easy_cleanup(curl);
        }

        // Cleanup libcurl
        curl_global_cleanup();

        return 0;
}


int dnshttps_stream_extract_dns(DnsStream *s) {
        int status, r;
        _cleanup_free_ char *header_copy = NULL;


        /* Our HTTP data at this moment */
        uint8_t *p_data;
        p_data = DNS_PACKET_DATA(s->read_packet);

        /* Our buffer to work on the HTTP data' */
        _cleanup_free_ char *http_response_buf = NULL;
        http_response_buf = malloc(s->read_packet->size);
        memcpy(http_response_buf, p_data, s->read_packet->size);

        char full_response[1024] = "HT";
        memcpy(&full_response[2], http_response_buf, 1022);


        /* Start parsing the HTTP */
        r = hashmap_ensure_allocated(&dnshttps_parser_data, NULL);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&s->response_headers, NULL);
        if (r < 0)
                return r;

        my_debug();

        puts(program_invocation_short_name);

        /*Parse request! */

        /* status = llhttp_get_status_code(&parser); */

        switch (status){
        case 200:
                puts("HTTP 200 ok, proceeding...");
                break;
        case 400:
                puts("HTTP 400...");
                return -EINVAL;
                break;
        case 414:
                puts("HTTP 414, URI too big...");
                return -EINVAL;
                break;
        case 429:
                puts("HTTP 429, too many requests...");
                return -EINVAL;
                break;
        case 500:
                puts("HTTP 500, internal server error...");
                return DNS_TRANSACTION_ABORTED;
                break;
        default:
                printf("\n\nHTTP not ok, fail now, reponse code: %d", status);
                /* TODO: handle errors */
                break;
        }


        /* HeaderFields enum_get; */
        /* http_header *ret_entry; */
        /* enum_get = BODY; */
        /* ret_entry = hashmap_get(dnshttps_parser_data, UINT_TO_PTR(enum_get)); */

        /* trying to replace http packet with dns packet from body */
        /* FIGURE OUT THE ACTUAL PACKET SIZE */

        /* memset(p_data, 0, ret_entry->len); */
        /* memset(p_data, 0, s->read_packet->size); */
        /* memcpy(p_data, ret_entry->at, ret_entry->len); */

        /* clean up hashmaps */
        /* hashmap_remove(dnshttps_parser_data, &parser); */
        /* enum_get = SERVER; */
        /* hashmap_remove(dnshttps_parser_data, UINT_TO_PTR(enum_get)); */
        /* enum_get = BODY; */
        /* hashmap_remove(dnshttps_parser_data, UINT_TO_PTR(enum_get)); */

        return 0;

}

/* should take the packet wire format and construct a http request, wire format*/
int dnshttps_packet_to_base64url(DnsTransaction *t){
        printf("\n in tcp, about to make base64url...\n");

        uint8_t *p_data = DNS_PACKET_DATA(t->sent);
        size_t url_len;

        _cleanup_free_ char *dnshttps_url = NULL;

        /* puts("zeroing id..."); */
        p_data[0] = 0;
        p_data[1] = 0;


        /* TODO: what about base64url? Normal base64 seems to be working just fine*/
        int r = base64mem_full(p_data, t->sent->size, MAX_URL_LENGTH, &dnshttps_url);
        if (r < 0){
                log_debug_errno(r, "Failed to encode DNS packet to base64.");
                return r;
        }

        // clean base64 trailing charecters
        url_len = strlen(dnshttps_url);
        while (url_len > 0 && dnshttps_url[url_len - 1] == '=') {
                dnshttps_url[--url_len] = '\0';
        }


        char get_request[512] = "";
        char header_host[32] = "";
        snprintf(header_host, sizeof(header_host), "Host: %s\r\n", t->server->server_string);

        char header_agent[64] = "";
        snprintf(header_agent, sizeof(header_agent), "User-Agent: systemd-resolved/%s\r\n", STRINGIFY(PROJECT_VERSION));
        /* useragent = strjoina(program_invocation_short_name, "/" GIT_VERSION); */



        strcpy(get_request, "GET /dns-query?dns=");
        strcat(get_request, dnshttps_url);
        strcat(get_request, " HTTP/1.1\r\n");
        strcat(get_request, header_host);
        strcat(get_request, header_agent);
        strcat(get_request, "Accept: application/dns-message\r\n");
        strcat(get_request, "Connection: Close\r\n");
        strcat(get_request, "\r\n");

        puts("request created:");
        puts(get_request);
        /* printf("assigning request to stream: %p\n", t->stream); */
        /* strcpy(t->stream->dnshttps_sent, get_request); */

        return 0;
}
