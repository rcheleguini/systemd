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
#include "hexdecoct.h"
#include "build.h"


static char *doh_error_string(int ssl_error, char *buf, size_t count) {

        return "";
}

#define DOH_ERROR_BUFSIZE 256
#define DOH_ERROR_STRING(error) \
        doh_error_string((error), (char[DOH_ERROR_BUFSIZE]){}, DOH_ERROR_BUFSIZE)

static int doh_flush_write_buffer(DnsStream *stream) {

        printf("\n doh_flush_write_buffer\n");

        ssize_t ss;

        assert(stream);
        assert(stream->encrypted_doh);

        if (stream->doh_data.buffer_offset < stream->doh_data.write_buffer->length) {
                assert(stream->doh_data.write_buffer->data);

                struct iovec iov[1];
                iov[0] = IOVEC_MAKE(stream->doh_data.write_buffer->data + stream->doh_data.buffer_offset,
                                    stream->doh_data.write_buffer->length - stream->doh_data.buffer_offset);
                ss = dns_stream_writev(stream, iov, 1, DNS_STREAM_WRITE_HTTPS_DATA);
                if (ss < 0) {
                        if (ss == -EAGAIN)
                                stream->doh_events |= EPOLLOUT;

                        return ss;
                } else {
                        stream->doh_data.buffer_offset += ss;

                        if (stream->doh_data.buffer_offset < stream->doh_data.write_buffer->length) {
                                stream->doh_events |= EPOLLOUT;
                                return -EAGAIN;
                        } else {
                                BIO_reset(SSL_get_wbio(stream->doh_data.ssl));
                                stream->doh_data.buffer_offset = 0;
                        }
                }
        }

        return 0;
}

int doh_stream_connect_tls(DnsStream *stream, DnsServer *server) {

        printf("\n doh_stream_connect_tls\n");

        /* ssl_simple(); */

        // Connect to the server
        if (connect(stream->fd, &stream->tfo_address.sa, stream->tfo_salen) == -1) {
                puts("connected");
        }

        /* Disabling TCP Fast Open */
        stream->tfo_salen = 0;

        /* ssl_with_fd(stream->fd); */



        _cleanup_(BIO_freep) BIO *rb = NULL, *wb = NULL;
        _cleanup_(SSL_freep) SSL *s = NULL;
        int error, r;

        assert(stream);
        assert(stream->manager);
        assert(server);

        rb = BIO_new_socket(stream->fd, 0);
        if (!rb)
                return -ENOMEM;

        wb = BIO_new(BIO_s_mem());
        if (!wb)
                return -ENOMEM;

        BIO_get_mem_ptr(wb, &stream->doh_data.write_buffer);
        stream->doh_data.buffer_offset = 0;

        s = SSL_new(stream->manager->doh_data.ctx);
        if (!s)
                return -ENOMEM;

        SSL_set_connect_state(s);
        r = SSL_set_session(s, server->doh_data.session);
        if (r == 0)
                return -EIO;
        SSL_set_bio(s, TAKE_PTR(rb), TAKE_PTR(wb));

        ERR_clear_error();
        stream->doh_data.handshake = SSL_do_handshake(s);
        if (stream->doh_data.handshake <= 0) {
                error = SSL_get_error(s, stream->doh_data.handshake);
                if (!IN_SET(error, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE))
                        return log_debug_errno(SYNTHETIC_ERRNO(ECONNREFUSED),
                                               "Failed to invoke SSL_do_handshake: %s", DOH_ERROR_STRING(error));
        }

        stream->encrypted_doh = true;
        stream->doh_data.ssl = TAKE_PTR(s);

        r = doh_flush_write_buffer(stream);
        if (r < 0 && r != -EAGAIN) {
                SSL_free(TAKE_PTR(stream->doh_data.ssl));
                return r;
        }


        return 0;
}

void doh_stream_free(DnsStream *stream) {

}

int doh_stream_on_io(DnsStream *stream, uint32_t revents) {
        printf("\n doh_stream_on_io \n");

        int error, r;

        assert(stream);
        assert(stream->encrypted_doh);
        assert(stream->doh_data.ssl);

        /* /\* Flush write buffer when requested by OpenSSL *\/ */
        if ((revents & EPOLLOUT) && (stream->doh_events & EPOLLOUT)) {
                r = doh_flush_write_buffer(stream);
                if (r < 0)
                        return r;
        }

        if (stream->doh_data.shutdown) {
                ERR_clear_error();
                r = SSL_shutdown(stream->doh_data.ssl);
                if (r == 0) {
                        stream->doh_events = 0;

                        r = doh_flush_write_buffer(stream);
                        if (r < 0)
                                return r;

                        return -EAGAIN;
                } else if (r < 0) {
                        error = SSL_get_error(stream->doh_data.ssl, r);
                        if (IN_SET(error, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE)) {
                                stream->doh_events = error == SSL_ERROR_WANT_READ ? EPOLLIN : EPOLLOUT;

                                r = doh_flush_write_buffer(stream);
                                if (r < 0)
                                        return r;

                                return -EAGAIN;
                        } else if (error == SSL_ERROR_SYSCALL) {
                                if (errno > 0)
                                        log_debug_errno(errno, "doh Failed to invoke SSL_shutdown, ignoring: %m");
                        } else
                                log_debug("doh Failed to invoke SSL_shutdown, ignoring: %s", DOH_ERROR_STRING(error));
                }

                stream->doh_events = 0;
                stream->doh_data.shutdown = false;

                r = doh_flush_write_buffer(stream);
                if (r < 0)
                        return r;

                dns_stream_unref(stream);
                return DOH_STREAM_CLOSED;
        } else if (stream->doh_data.handshake <= 0) {
                ERR_clear_error();
                stream->doh_data.handshake = SSL_do_handshake(stream->doh_data.ssl);
                if (stream->doh_data.handshake <= 0) {
                        error = SSL_get_error(stream->doh_data.ssl, stream->doh_data.handshake);
                        if (IN_SET(error, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE)) {
                                stream->doh_events = error == SSL_ERROR_WANT_READ ? EPOLLIN : EPOLLOUT;
                                puts("want read or want write...");
                                r = doh_flush_write_buffer(stream);
                                if (r < 0)
                                        return r;

                                return -EAGAIN;
                        } else
                                return log_debug_errno(SYNTHETIC_ERRNO(ECONNREFUSED),
                                                       "doh Failed to invoke SSL_do_handshake: %s",
                                                       DOH_ERROR_STRING(error));
                }

                stream->doh_events = 0;
                r = doh_flush_write_buffer(stream);
                if (r < 0)
                        return r;
        }

        return 0;
}

int doh_stream_shutdown(DnsStream *stream, int error) {
        int ssl_error, r;
        SSL_SESSION *s;

        assert(stream);
        assert(stream->encrypted_doh);
        assert(stream->doh_data.ssl);

        if (stream->server) {
                s = SSL_get1_session(stream->doh_data.ssl);
                if (s) {
                        if (stream->server->doh_data.session)
                                SSL_SESSION_free(stream->server->doh_data.session);

                        stream->server->doh_data.session = s;
                }
        }

        if (error == ETIMEDOUT) {
                ERR_clear_error();
                r = SSL_shutdown(stream->doh_data.ssl);
                if (r == 0) {
                        if (!stream->doh_data.shutdown) {
                                stream->doh_data.shutdown = true;
                                dns_stream_ref(stream);
                        }

                        stream->doh_events = 0;

                        r = doh_flush_write_buffer(stream);
                        if (r < 0)
                                return r;

                        return -EAGAIN;
                } else if (r < 0) {
                        ssl_error = SSL_get_error(stream->doh_data.ssl, r);
                        if (IN_SET(ssl_error, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE)) {
                                stream->doh_events = ssl_error == SSL_ERROR_WANT_READ ? EPOLLIN : EPOLLOUT;
                                r = doh_flush_write_buffer(stream);
                                if (r < 0 && r != -EAGAIN)
                                        return r;

                                if (!stream->doh_data.shutdown) {
                                        stream->doh_data.shutdown = true;
                                        dns_stream_ref(stream);
                                }
                                return -EAGAIN;
                        } else if (ssl_error == SSL_ERROR_SYSCALL) {
                                if (errno > 0)
                                        log_debug_errno(errno, "Failed to invoke SSL_shutdown, ignoring: %m");
                        } else
                                log_debug("Failed to invoke SSL_shutdown, ignoring: %s", DOH_ERROR_STRING(ssl_error));
                }

                stream->doh_events = 0;
                r = doh_flush_write_buffer(stream);
                if (r < 0)
                        return r;
        }

        return 0;
}

static ssize_t doh_stream_write(DnsStream *stream, const char *buf, size_t count) {

        printf("\n doh_stream_write\n");
        printf("to stream: %p\n", stream);

        int error, r;
        ssize_t ss;

        int i = 0;


        /* todo find way to remove the hard coded 512 */
        ERR_clear_error();
        ss = r = SSL_write(stream->doh_data.ssl, stream->doh_sent, 512);

        /* ERR_clear_error(); */
        /* ss = r = SSL_write(stream->doh_data.ssl, buf, count); */

        if (r <= 0) {
                error = SSL_get_error(stream->doh_data.ssl, r);
                if (IN_SET(error, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE)) {
                        stream->doh_events = error == SSL_ERROR_WANT_READ ? EPOLLIN : EPOLLOUT;
                        ss = -EAGAIN;
                } else if (error == SSL_ERROR_ZERO_RETURN) {
                        stream->doh_events = 0;
                        ss = 0;
                } else {
                        log_debug("Failed to invoke SSL_write: %s", DOH_ERROR_STRING(error));
                        stream->doh_events = 0;
                        ss = -EPIPE;
                }
        } else
                stream->doh_events = 0;

        r = doh_flush_write_buffer(stream);
        if (r < 0)
                return r;

        return ss;
}

ssize_t doh_stream_writev(DnsStream *stream, const struct iovec *iov, size_t iovcnt) {

        printf("\n doh_stream_writev\n");
        printf("to stream: %p\n", stream);
        printf("request: %s\n", stream->doh_sent);

        _cleanup_free_ char *buf = NULL;
        size_t count;

        assert(stream);
        assert(stream->encrypted_doh);
        assert(stream->doh_data.ssl);
        assert(iov);
        assert(iovec_total_size(iov, iovcnt) > 0);

        if (iovcnt == 1)
                return doh_stream_write(stream, iov[0].iov_base, iov[0].iov_len);

        /* As of now, OpenSSL cannot accumulate multiple writes, so join into a
           single buffer. Suboptimal, but better than multiple SSL_write calls. */
        count = iovec_total_size(iov, iovcnt);
        printf("size of iovec: %lu\n", count);
        buf = new(char, count);
        for (size_t i = 0, pos = 0; i < iovcnt; pos += iov[i].iov_len, i++)
                memcpy(buf + pos, iov[i].iov_base, iov[i].iov_len);

        return doh_stream_write(stream, buf, count);
}

ssize_t doh_stream_read(DnsStream *stream, void *buf, size_t count) {

        printf("\n doh_stream_read\n");

        int error, r;
        ssize_t ss;

        assert(stream);
        assert(stream->encrypted_doh);
        assert(stream->doh_data.ssl);
        assert(buf);




        ERR_clear_error();
        ss = r = SSL_read(stream->doh_data.ssl, buf, count);

        /* ERR_clear_error(); */
        /* ss = r = SSL_read(stream->doh_data.ssl, buf, 1024); */

        int i = 0;
        char* charPtr = (char*)buf;

        for (i = 0; i < 1024; ++i){
                /* printf("%x", response[i]); */
                /* printf("%c", charPtr[i * sizeof(char)]); */
                printf("%c", charPtr[i]);
                /* if (charPtr[i * sizeof(char)] == 'H') */
                /*         parse_http(buf); */
        }




        if (r <= 0) {
                error = SSL_get_error(stream->doh_data.ssl, r);
                printf("\n\nssl read is less than 0...");
                if (IN_SET(error, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE)) {
                        /* If we receive SSL_ERROR_WANT_READ here, there are two possible scenarios:
                         * OpenSSL needs to renegotiate (so we want to get an EPOLLIN event), or
                         * There is no more application data is available, so we can just return
                         And apparently there's no nice way to distinguish between the two.
                         To handle this, never set EPOLLIN and just continue as usual.
                         If OpenSSL really wants to read due to renegotiation, it will tell us
                         again on SSL_write (at which point we will request EPOLLIN force a read);
                         or we will just eventually read data anyway while we wait for a packet */
                        stream->doh_events = error == SSL_ERROR_WANT_READ ? 0 : EPOLLOUT;
                        puts("setting to -EAGAIN...");
                        ss = -EAGAIN;
                } else if (error == SSL_ERROR_ZERO_RETURN) {
                        puts("error SSL_ERROR_ZERO_RETURN...");
                        stream->doh_events = 0;
                        ss = 0;
                } else {
                        log_debug("Failed to invoke SSL_read: %s", DOH_ERROR_STRING(error));
                        stream->doh_events = 0;
                        ss = -EPIPE;
                }
        } else
                stream->doh_events = 0;

        stream->doh_events = 0;
        return ss;

        /* todo, this breaks dns over https, from original tls
        /* /\* flush write buffer in case of renegotiation *\/ */
        /* r = doh_flush_write_buffer(stream); */
        /* if (r < 0) */
        /*         return r; */

        /* return ss; */

}

void doh_server_free(DnsServer *server) {

}

int doh_manager_init(Manager *manager) {
        printf("\n doh_manager_init\n");

        int r;

        assert(manager);

        SSL_library_init();
        ERR_load_crypto_strings();
        SSL_load_error_strings();

        manager->doh_data.ctx = SSL_CTX_new(TLS_client_method());
        if (!manager->doh_data.ctx)
                return -ENOMEM;

        r = SSL_CTX_set_min_proto_version(manager->doh_data.ctx, TLS1_2_VERSION);
        if (r == 0)
                return -EIO;

        /* (void) SSL_CTX_set_options(manager->doh_data.ctx, SSL_OP_NO_COMPRESSION); */

        /* r = SSL_CTX_set_default_verify_paths(manager->doh_data.ctx); */
        /* if (r == 0) */
        /*         return log_warning_errno(SYNTHETIC_ERRNO(EIO), */
        /*                                  "Failed to load system trust store: %s", */
        /*                                  ERR_error_string(ERR_get_error(), NULL)); */

        return 0;
}

void doh_manager_free(Manager *manager) {

}

int doh_stream_split_http(DnsStream *s){
        puts("doh_split_http");

        uint8_t *p_data;
        p_data = DNS_PACKET_DATA(s->read_packet);

        int i = 0;
        /* char* charPtr = (char*)s->read_packet; */

        for (i = 0; i < s->read_packet->size; ++i){
                printf("%c", p_data[i * sizeof(char)]);
        }



        doh_response *doh = parse_doh_response(p_data);

        /* dns packet size is total read size minus headers */
        doh->dns_data_len = s->read_packet->size - doh->http_header_len;

        /* need to take the Content Length header */

        printf("\nHTTP header:\n%.*s\n", doh->http_header_len, doh->http_header);
        printf("DNS data:\n%.*s\n", doh->dns_data_len, doh->dns_data);


        /* need to process more than 56 bytes */
        /* e.g. debian.org answer has 103 bytes */

        /* memcpy(p_data, doh->dns_data, 56); */
        memcpy(p_data, doh->dns_data, doh->dns_data_len);


        /* /\* free_doh_response(doh); *\/ */
        /* for (i = 0; i < 45; ++i){ */
        /*         printf("%c", doh->dns_data[i * sizeof(char)]); */
        /* } */

        /* for (i = 0; i < 45; ++i){ */
        /*         memcpy(p_data, doh->dns_data, sizeof(char)); */
        /*         p_data++; */
        /*         doh->dns_data++; */
        /* } */


        return 0;
}

doh_response *parse_doh_response(char *response) {

        puts("parse_doh_response");
        int i = 0;
        int r;

        for (i = 0; i < 1024; ++i){
                printf("%c", response[i * sizeof(char)]);
        }


        doh_response *doh = malloc(sizeof(doh_response));

        // Find the start of the DNS data
        char *dns_start = memmem(response, 1024, "\r\n\r\n", sizeof(char) * 4);

        if (!dns_start) {
                doh->http_header = response;
                doh->http_header_len = strlen(response);
                doh->dns_data = NULL;
                doh->dns_data_len = 0;
                return doh;
        }

        doh->http_header = response;
        doh->http_header_len = dns_start - response;

        _cleanup_free_ char *header_copy = NULL;

        header_copy = malloc(doh->http_header_len);
        memcpy(header_copy, doh->http_header, doh->http_header_len);

        puts("header_copy");

        char *header_status = NULL;
        header_status = strtok(header_copy, "\r\n");
        header_status = strtok(header_status, " ");
        header_status = strtok(NULL, " ");

        int status = atoi(header_status);

        switch(status){
        case 200:
                puts("HTTP 200 ok, proceeding to copy body content/dns packet...");
                doh->dns_data = dns_start + 4; // the 4 here is to skip the "\r\n\r\n"
                /* doh->dns_data_len = strlen(doh->dns_data); */
                break;
        default:
                printf("\n\nHTTP not ok, fail now, reponse code: %d", status);
                /* handle errors here */
                break;
        }

        return doh;
}

void free_doh_response(doh_response *doh) {
        if (doh) {
                free(doh->http_header);
                free(doh);
        }
}


// Function to remove trailing '=' characters from a Base64url-encoded string
void remove_padding(char *str) {
    size_t len = strlen(str);

    while (len > 0 && str[len - 1] == '=') {
        str[--len] = '\0';
    }
}

/* should take the packet wire format and construct a http request*/
int doh_packet_to_base64url(DnsTransaction *t){
        printf("\n in tcp, about to make base64url...\n");

        DnsPacketHeader *p_header = DNS_PACKET_HEADER(t->sent);
        uint8_t *p_data = DNS_PACKET_DATA(t->sent);
        uint16_t p_id = DNS_PACKET_ID(t->sent);

        uint16_t i = 0;

        /* struct DohRequest get_request; */


        /* puts("zeroing id..."); */
        p_data[0] = 0;
        p_data[1] = 0;

        p_id = DNS_PACKET_ID(t->sent);

        _cleanup_free_ char *doh_url = NULL;

        puts("");

        // Convert binary data to Base64
        // 40 bytes is the packet size in wireshark
        int r = base64mem_full(p_data, t->sent->size, 56, &doh_url);
        remove_padding(doh_url);

        char get_request[512] = "";

        /* new solution */
        char header_host[32] = "";
        snprintf(header_host, sizeof(header_host), "Host: %s\r\n", t->server->server_string);

        char header_agent[64] = "";
        snprintf(header_agent, sizeof(header_agent), "User-Agent: systemd-resolved/%s\r\n", STRINGIFY(PROJECT_VERSION));


        strcpy(get_request, "GET /dns-query?dns=");
        strcat(get_request, doh_url);
        strcat(get_request, " HTTP/1.1\r\n");
        strcat(get_request, header_host);
        strcat(get_request, header_agent);
        strcat(get_request, "Connection: Close\r\n");
        strcat(get_request, "\r\n");

        /* todo construct t->sent_url and remove the hard corded url in write() */

        puts(get_request);
        printf("assigning request to stream: %p\n", t->stream);
        strcpy(t->stream->doh_sent, get_request);
        /* t->stream->write_packet = (struct DnsPacket *)&get_request; */
        /* t->stream->write_packet->size = sizeof(get_request); */


        return 0;
}
