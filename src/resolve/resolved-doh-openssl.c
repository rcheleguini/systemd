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

        printf("\n doh_flush_write_buffer\n");

        ssize_t ss;

        assert(stream);
        assert(stream->encrypted_doh);

        if (stream->doh_data.buffer_offset < stream->doh_data.write_buffer->length) {
                assert(stream->doh_data.write_buffer->data);

                struct iovec iov[1];
                iov[0] = IOVEC_MAKE(stream->doh_data.write_buffer->data + stream->doh_data.buffer_offset,
                                    stream->doh_data.write_buffer->length - stream->doh_data.buffer_offset);
                ss = dns_stream_writev(stream, iov, 1, DNS_STREAM_WRITE_TLS_DATA);
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


        /* char name[1024]; */
        /* char request[1024]; */
        /* char response[1024]; */

        /* const SSL_METHOD* method = TLSv1_2_client_method(); */

        /* SSL_CTX* ctx = SSL_CTX_new(method); */

        /* BIO* bio = BIO_new_ssl_connect(ctx); */

        /* SSL* ssl = NULL; */

        /* /\* link bio channel, SSL session, and server endpoint *\/ */
        /* /\* hostname = "dns.google"; *\/ */
        /* char *hostname = "8.8.8.8"; */
        /* sprintf(name, "%s:%s", hostname, "https"); */
        /* BIO_get_ssl(bio, &ssl); /\* session *\/ */
        /* SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY); /\* robustness *\/ */
        /* BIO_set_conn_hostname(bio, name); /\* prepare to connect *\/ */

        /* /\* const char *connect_str = "www.google.com:443"; *\/ */
        /* const char *connect_str = "8.8.8.8:443"; */
        /* BIO_set_conn_hostname(bio, connect_str); */

        /* /\* try to connect *\/ */
        /* if (BIO_do_connect(bio) <= 0) { */
        /*         puts("need BIO cleanup"); */
        /* } */

        /* /\* verify truststore, check cert *\/ */
        /* if (!SSL_CTX_load_verify_locations(ctx, */
        /*                                    "/etc/ssl/certs/ca-certificates.crt", /\* truststore *\/ */
        /*                                    "/etc/ssl/certs/")) /\* more truststore *\/ */
        /*         puts("error SSL ctx"); */

        /* long verify_flag = SSL_get_verify_result(ssl); */
        /* if (verify_flag != X509_V_OK) */
        /*         fprintf(stderr, */
        /*                 "##### Certificate verification error (%i) but continuing...\n", */
        /*                 (int) verify_flag); */

        /* /\* now fetch the homepage as sample data *\/ */
        /* /\* sprintf(request, *\/ */
        /* /\*         "GET / HTTP/1.1\x0D\x0AHost: %s\x0D\x0A\x43onnection: Close\x0D\x0A\x0D\x0A", *\/ */
        /* /\*         hostname); *\/ */
        /* sprintf(request, */
        /*         /\* working *\/ */
        /*         /\* "GET /dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE HTTP/1.1\x0D\x0AHost: %s\x0D\x0A\x43onnection: Close\x0D\x0A\x0D\x0A", *\/ */
        /*         /\* simulating curl *\/ */
        /*         "GET /dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE HTTP/1.1\x0D\x0AHost: %s\x0D\x0AUser-Agent: curl/8.2.1\x0D\x0AAccept: *\/\*\x0D\x0A\x43onnection: Close\x0D\x0A\x0D\x0A", */
        /*         hostname); */
        /* printf("\nrequest: %s\n", request); */
        /* BIO_puts(bio, request); */

        /* /\* read HTTP response from server and print to stdout *\/ */
        /* memset(response, '\0', sizeof(response)); */
        /* while (1) { */
        /*         int n = BIO_read(bio, response, 1024); */
        /*         if (n <= 0) break; /\* 0 is end-of-stream, < 0 is an error *\/ */
        /*         /\* puts(response); *\/ */
        /* } */


        /* int i = 0; */

        /* for (i = 0; i < sizeof(response); ++i){ */
        /*         /\* printf("%x", response[i]); *\/ */
        /*         printf("%c", response[i]); */
        /* } */



        puts("end test");


        /* start default ssl */

        _cleanup_(BIO_freep) BIO *rb = NULL, *wb = NULL;
        _cleanup_(SSL_freep) SSL *s = NULL;
        int error, r;


        assert(stream);
        assert(stream->manager);
        assert(server);

        struct sockaddr_in server_addr;

        // Create a TCP socket and connect to the server
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
                // Handle socket creation error
                perror("socket");
                return 1;
        }

        // Set up server address
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(443);  // Replace with your port
        inet_pton(AF_INET, "8.8.8.8", &(server_addr.sin_addr));  // Replace with your server IP address

        // Connect to the server
        if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
                puts("connected");
        }


        // Create an SSL context
        SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!ssl_ctx) {
                // Handle error
                ERR_print_errors_fp(stderr);
                return 1;
        }


        if (SSL_CTX_load_verify_locations(ssl_ctx,
                                           "/etc/ssl/certs/ca-certificates.crt", /* truststore */
                                          "/etc/ssl/certs/") != 1) {
                // Handle error
                ERR_print_errors_fp(stderr);
                SSL_CTX_free(ssl_ctx);
                return 1;
        }

        // Create an SSL structure
        SSL* ssl = SSL_new(ssl_ctx);
        if (!ssl) {
                // Handle error
                ERR_print_errors_fp(stderr);
                close(sockfd);
                return 1;
        }



        // Set up the BIOs for the SSL structure
        BIO* rbio = BIO_new_socket(sockfd, BIO_NOCLOSE);
        BIO* wbio = BIO_new_socket(sockfd, BIO_NOCLOSE);

        SSL_set_bio(ssl, rbio, wbio);

        SSL_set_connect_state(ssl);


        // Perform the SSL/TLS handshake
        if (SSL_connect(ssl) <= 0) {
                // Handle error
                ERR_print_errors_fp(stderr);
                return 1;
        }


        char *hostname = "8.8.8.8";
        char request[1024];
        sprintf(request,
                /* working */
                /* "GET /dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE HTTP/1.1\x0D\x0AHost: %s\x0D\x0A\x43onnection: Close\x0D\x0A\x0D\x0A", */
                /* simulating curl */
                "GET /dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE HTTP/1.1\x0D\x0AHost: %s\x0D\x0AUser-Agent: curl/8.2.1\x0D\x0AAccept: */*\x0D\x0A\x43onnection: Close\x0D\x0A\x0D\x0A",
                hostname);
        printf("\nrequest: %s\n", request);

        int written = SSL_write(ssl, request, strlen(request));
        if (written <= 0) {
                // Handle write error
                int ssl_error = SSL_get_error(stream->doh_data.ssl, written);
                // Handle the error appropriately
                return -1;
        }

        // Read the server's response (you need to implement this)
        char response[1024];

        /* read HTTP response from server and print to stdout */
        memset(response, '\0', sizeof(response));
        while (1) {
                int n = SSL_read(ssl, response, 1024);
                if (n <= 0) break; /* 0 is end-of-stream, < 0 is an error */
                /* puts(response); */
        }

        int i = 0;

        for (i = 0; i < sizeof(response); ++i){
                /* printf("%x", response[i]); */
                printf("%c", response[i]);
        }

        /* end 2nd test */

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
        r = SSL_set_session(s, server->dnshttps_data.session);
        if (r == 0)
                return -EIO;
        SSL_set_bio(s, TAKE_PTR(rb), TAKE_PTR(wb));

        if (server->manager->dns_over_https_mode == DNS_OVER_HTTPS_YES) {
                X509_VERIFY_PARAM *v;

                SSL_set_verify(s, SSL_VERIFY_PEER, NULL);
                v = SSL_get0_param(s);
                if (server->server_name) {
                        X509_VERIFY_PARAM_set_hostflags(v, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
                        if (X509_VERIFY_PARAM_set1_host(v, server->server_name, 0) == 0)
                                return -ECONNREFUSED;
                } else {
                        const unsigned char *ip;
                        ip = server->family == AF_INET ? (const unsigned char*) &server->address.in.s_addr : server->address.in6.s6_addr;
                        if (X509_VERIFY_PARAM_set1_ip(v, ip, FAMILY_ADDRESS_SIZE(server->family)) == 0)
                                return -ECONNREFUSED;
                }
        }

        server->server_name = "8.8.8.8";
        if (server->server_name) {
                r = SSL_set_tlsext_host_name(s, server->server_name);
                if (r <= 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Failed to set server name: %s", DOH_ERROR_STRING(SSL_ERROR_SSL));
        }




        ERR_clear_error();
        stream->doh_data.handshake = SSL_do_handshake(s);
        if (stream->doh_data.handshake <= 0) {
                printf("\n handshake error\n");
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

        /* Flush write buffer when requested by OpenSSL */
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

        return 0;
}

static ssize_t doh_stream_write(DnsStream *stream, const char *buf, size_t count) {

        printf("\n doh_stream_write\n");

        int error, r;
        ssize_t ss;





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
        if (r <= 0) {
                error = SSL_get_error(stream->doh_data.ssl, r);
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
                        ss = -EAGAIN;
                } else if (error == SSL_ERROR_ZERO_RETURN) {
                        stream->doh_events = 0;
                        ss = 0;
                } else {
                        log_debug("Failed to invoke SSL_read: %s", DOH_ERROR_STRING(error));
                        stream->doh_events = 0;
                        ss = -EPIPE;
                }
        } else
                stream->doh_events = 0;

        /* flush write buffer in cache of renegotiation */
        r = doh_flush_write_buffer(stream);
        if (r < 0)
                return r;

        return ss;

}

void doh_server_free(DnsServer *server) {

}

int doh_manager_init(Manager *manager) {
        printf("\n doh_manager_init\n");

        int r;

        assert(manager);

        ERR_load_crypto_strings();
        SSL_load_error_strings();

        manager->doh_data.ctx = SSL_CTX_new(TLS_client_method());
        if (!manager->doh_data.ctx)
                return -ENOMEM;

        r = SSL_CTX_set_min_proto_version(manager->doh_data.ctx, TLS1_2_VERSION);
        if (r == 0)
                return -EIO;

        (void) SSL_CTX_set_options(manager->doh_data.ctx, SSL_OP_NO_COMPRESSION);

        r = SSL_CTX_set_default_verify_paths(manager->doh_data.ctx);
        if (r == 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EIO),
                                         "Failed to load system trust store: %s",
                                         ERR_error_string(ERR_get_error(), NULL));

        return 0;
}

void doh_manager_free(Manager *manager) {

}
