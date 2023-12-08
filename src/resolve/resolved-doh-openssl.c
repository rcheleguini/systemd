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

void ssl_simple(){
        int i, written;
        char *hostname = "8.8.8.8";
        char request[1024];
        char response[1024];

        struct sockaddr_in server_addr;

        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
                // Handle socket creation error
                perror("socket");
                puts("new socket error");
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
                puts("ssl ctx new error");
        }


        if (SSL_CTX_load_verify_locations(ssl_ctx,
                                           "/etc/ssl/certs/ca-certificates.crt", /* truststore */
                                          "/etc/ssl/certs/") != 1) {
                // Handle error
                ERR_print_errors_fp(stderr);
                SSL_CTX_free(ssl_ctx);
                puts("ssl verify files error");
        }

        // Create an SSL structure
        SSL* ssl = SSL_new(ssl_ctx);
        if (!ssl) {
                // Handle error
                ERR_print_errors_fp(stderr);
                close(sockfd);
                puts("ssl new error");
        }



        // Set up the BIOs for the SSL structure
        BIO* rbio = BIO_new_socket(sockfd, BIO_NOCLOSE);
        BIO* wbio = BIO_new_socket(sockfd, BIO_NOCLOSE);

        SSL_set_bio(ssl, rbio, wbio);

        SSL_set_connect_state(ssl);



        if (SSL_connect(ssl) <= 0) {
                // Handle error
                ERR_print_errors_fp(stderr);
                puts("ssl connect error");
        }


        sprintf(request,
                /* working */
                /* "GET /dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE HTTP/1.1\x0D\x0AHost: %s\x0D\x0A\x43onnection: Close\x0D\x0A\x0D\x0A", */
                /* simulating curl */
                "GET /dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE HTTP/1.1\x0D\x0AHost: %s\x0D\x0AUser-Agent: curl/8.2.1\x0D\x0AAccept: */*\x0D\x0A\x43onnection: Close\x0D\x0A\x0D\x0A",
                hostname);
        printf("\nrequest: %s\n", request);

        written = SSL_write(ssl, request, strlen(request));
        if (written <= 0) {
                // Handle write error
                puts("ssl error");
                // Handle the error appropriately
        }

        // Read the server's response (you need to implement this)

        /* read HTTP response from server and print to stdout */
        memset(response, '\0', sizeof(response));
        while (1) {
                int n = SSL_read(ssl, response, 1024);
                if (n <= 0) break; /* 0 is end-of-stream, < 0 is an error */
                /* puts(response); */
        }

        i = 0;

        for (i = 0; i < sizeof(response); ++i){
                /* printf("%x", response[i]); */
                printf("%c", response[i]);
        }
}

void ssl_with_fd(int sockfd){
        int i, written;
        char *hostname = "8.8.8.8";
        char request[1024];
        char response[1024];

        struct sockaddr_in server_addr;

        // Set up server address
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(443);  // Replace with your port
        inet_pton(AF_INET, "8.8.8.8", &(server_addr.sin_addr));  // Replace with your server IP address

        /* // Connect to the server */
        /* if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) { */
        /*         puts("connected"); */
        /* } */




        /* SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method()); */
        /* if (ctx == NULL) { */
        /*         puts("ctx error"); */
        /* } */

        /* SSL *ssl1 = SSL_new(ctx); */
        /* if (ssl1 == NULL) { */
        /*         puts("new error"); */
        /*         // Handle error */
        /* } */

        /* if (SSL_set_fd(ssl1, sockfd) == 0) { */
        /*         // Handle error */
        /*         puts("set fd error"); */
        /* } */

        /* int ret = SSL_connect(ssl1); */
        /* if (ret <= 0) { */
        /*         puts("connect error"); */
        /*         // Handle SSL connection error */
        /* } */

        // Create an SSL context
        SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!ssl_ctx) {
                // Handle error
                ERR_print_errors_fp(stderr);
                puts("ssl ctx new error");
        }


        if (SSL_CTX_load_verify_locations(ssl_ctx,
                                           "/etc/ssl/certs/ca-certificates.crt", /* truststore */
                                          "/etc/ssl/certs/") != 1) {
                // Handle error
                ERR_print_errors_fp(stderr);
                SSL_CTX_free(ssl_ctx);
                puts("ssl verify files error");
        }

        // Create an SSL structure
        SSL* ssl = SSL_new(ssl_ctx);
        if (!ssl) {
                // Handle error
                ERR_print_errors_fp(stderr);
                close(sockfd);
                puts("ssl new error");
        }



        // Set up the BIOs for the SSL structure
        BIO* rbio = BIO_new_socket(sockfd, BIO_NOCLOSE);
        BIO* wbio = BIO_new_socket(sockfd, BIO_NOCLOSE);

        SSL_set_bio(ssl, rbio, wbio);

        SSL_set_connect_state(ssl);

        // Perform the SSL/TLS handshake
        int handshake_result = SSL_do_handshake(ssl);

        if (handshake_result != 1) {
                int ssl_error = SSL_get_error(ssl, handshake_result);
                if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
                        puts("ssl handshake error");
                        ERR_print_errors_fp(stderr);
                        SSL_free(ssl);
                        close(sockfd);
                }
        }



        // Non-blocking I/O after handshake
        fd_set read_fds, write_fds;
        struct timeval timeout;

        char buffer[1024];
        int bytes_read, bytes_written;

        while (1) {
                FD_ZERO(&read_fds);
                FD_ZERO(&write_fds);

                FD_SET(sockfd, &read_fds);
                FD_SET(sockfd, &write_fds);

                timeout.tv_sec = 5;  // Set a timeout (5 seconds)
                timeout.tv_usec = 0;

                int ready = select(sockfd + 1, &read_fds, &write_fds, NULL, &timeout);

                if (ready == 0) {
                        // Timeout
                        continue;
                } else if (ready < 0) {
                        // Error
                        perror("select");
                        break;
                }

                if (FD_ISSET(sockfd, &read_fds)) {
                        // Socket is ready for reading

                        memset(response, '\0', sizeof(response));
                        bytes_read = SSL_read(ssl, response, 1024);

                        if (bytes_read <= 0) {
                                int ssl_error = SSL_get_error(ssl, bytes_read);
                                if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
                                        ERR_print_errors_fp(stderr);
                                        break;
                                }
                        } else {
                                i = 0;

                                for (i = 0; i < sizeof(response); ++i){
                                        /* printf("%x", response[i]); */
                                        printf("%c", response[i]);
                                }
                        }
                }

                if (FD_ISSET(sockfd, &write_fds)) {
                        // Socket is ready for writing

                        sprintf(request,
                                /* working */
                                /* "GET /dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE HTTP/1.1\x0D\x0AHost: %s\x0D\x0A\x43onnection: Close\x0D\x0A\x0D\x0A", */
                                /* simulating curl */
                                "GET /dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE HTTP/1.1\x0D\x0AHost: %s\x0D\x0AUser-Agent: curl/8.2.1\x0D\x0AAccept: */*\x0D\x0A\x43onnection: Close\x0D\x0A\x0D\x0A",
                                hostname);
                        printf("\nrequest: %s\n", request);

                        bytes_written = SSL_write(ssl, request, strlen(request));
                        if (written <= 0) {
                                // Handle write error
                                puts("ssl error");
                                // Handle the error appropriately
                        }

                        if (bytes_written <= 0) {
                                int ssl_error = SSL_get_error(ssl, bytes_written);
                                if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
                                        ERR_print_errors_fp(stderr);
                                        break;
                                }
                        } else {
                                // Data sent successfully
                                // ...
                        }
                }
        }


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

        return 0;
}

static ssize_t doh_stream_write(DnsStream *stream, const char *buf, size_t count) {

        printf("\n doh_stream_write\n");

        int error, r;
        ssize_t ss;

        int i = 0;

        for (i = 0; i < count; ++i){
                /* printf("%x", response[i]); */
                printf("%c", buf[i * sizeof(buf)]);
        }



        ERR_clear_error();
        ss = r = SSL_write(stream->doh_data.ssl, buf, count);
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

        int i = 0;


        ERR_clear_error();
        ss = r = SSL_read(stream->doh_data.ssl, buf, count);

        char* charPtr = (char*)buf;

        for (i = 0; i < count; ++i){
                /* printf("%x", response[i]); */
                printf("%c", charPtr[i * sizeof(char)]);
        }


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
