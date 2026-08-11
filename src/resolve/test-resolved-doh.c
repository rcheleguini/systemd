/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <net/if.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sd-event.h"

#include "dns-packet.h"
#include "dns-question.h"
#include "dns-rr.h"
#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "random-util.h"
#include "resolved-dns-server.h"
#include "resolved-dns-transaction.h"
#include "resolved-dnstls.h"
#include "resolved-manager.h"
#include "sparse-endian.h"
#include "tests.h"
#include "time-util.h"

static union sockaddr_union server_address;

static int base64_decode_full(const char *s, uint8_t **ret, size_t *ret_size, int flags);

/* A simple raw HTTP parser */
static int read_http_request(int fd, char **ret_path) {
        _cleanup_free_ char *line = NULL;
        char *path = NULL, *verb = NULL, *version = NULL;
        FILE *f;
        int r;

        f = fdopen(fd, "r");
        if (!f)
                return -errno;

        r = read_line(f, LONG_LINE_MAX, &line);
        if (r < 0)
                return r;

        r = sscanf(line, "%ms %ms %ms", &verb, &path, &version);
        if (r != 3) {
                free(verb);
                free(path);
                free(version);
                return -EINVAL;
        }

        free(verb);
        free(version);

        /* Skip headers */
        for (;;) {
                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (isempty(line) || streq(line, "\r"))
                        break;
        }

        *ret_path = path;
        return 0;
}

static void send_http_response(int fd, const uint8_t *answer, size_t answer_size) {
        _cleanup_free_ char *header = NULL;
        int r;

        r = asprintf(&header,
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: application/dns-message\r\n"
                     "Content-Length: %zu\r\n"
                     "\r\n",
                     answer_size);
        assert_se(r >= 0);

        assert_se(write(fd, header, strlen(header)) == (ssize_t) strlen(header));
        assert_se(write(fd, answer, answer_size) == (ssize_t) answer_size);
}

static void doh_server_handle(int fd) {
        _cleanup_free_ char *path = NULL;
        char *p, *dns_base64;
        _cleanup_free_ uint8_t *dns_raw = NULL;
        size_t dns_raw_len;
        int r;

        r = read_http_request(fd, &path);
        assert_se(r >= 0);

        p = strstr(path, "dns=");
        assert_se(p);
        dns_base64 = p + 4;

        r = base64_decode_full(dns_base64, &dns_raw, &dns_raw_len, 0);
        assert_se(r >= 0);

        /* For now, just send a dummy response */
        uint8_t dummy_answer[] = {
                0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
                0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x05, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04
        };

        send_http_response(fd, dummy_answer, sizeof(dummy_answer));
}

static int base64_decode_full(const char *s, uint8_t **ret, size_t *ret_size, int flags) {
        static const char B64_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        const size_t len = strlen(s);
        uint8_t *buffer;
        size_t i, j = 0;
        uint32_t group = 0;
        int bits = 0;

        if (len % 4 != 0)
                return -EINVAL;

        buffer = new(uint8_t, len / 4 * 3 + 1);
        if (!buffer)
                return -ENOMEM;

        for (i = 0; i < len; i++) {
                const char *p = strchr(B64_CHARS, s[i]);
                if (!p) {
                        if (s[i] == '=') {
                                /* End of data */
                                if (i < len - 2) {
                                        free(buffer);
                                        return -EINVAL;
                                }
                                break;
                        }
                        free(buffer);
                        return -EINVAL;
                }

                group = (group << 6) | (p - B64_CHARS);
                bits += 6;

                if (bits >= 8) {
                        bits -= 8;
                        buffer[j++] = (uint8_t)(group >> bits);
                }
        }

        *ret = buffer;
        *ret_size = j;
        return 0;
}

/*
 * Spawns a DNS DOH server using the command line "openssl s_server" tool.
 */
static void *https_doh_server(void *p) {
        int r;
        _cleanup_close_ int fd_server = -EBADF, fd_tls = -EBADF;
        _cleanup_free_ char *cert_path = NULL, *key_path = NULL;
        _cleanup_free_ char *bind_str = NULL;
        _cleanup_(pidref_done) PidRef openssl_pidref = PIDREF_NULL;

        assert_se(get_testdata_dir("test-resolve/selfsigned.cert", &cert_path) >= 0);
        assert_se(get_testdata_dir("test-resolve/selfsigned.key", &key_path) >= 0);

        assert_se(asprintf(&bind_str, "127.0.0.1:%d", be16toh(server_address.in.sin_port)) >= 0);

        /* We will hook one of the socketpair ends to OpenSSL's TLS server
         * stdin/stdout, so we will be able to read and write plaintext
         * from the other end's file descriptor like an usual TCP server */
        {
                int fd[2];
                assert_se(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) >= 0);
                fd_server = fd[0];
                fd_tls = fd[1];
        }

        r = ASSERT_OK(pidref_safe_fork_full(
                        "(test-resolved-doh-openssl)",
                        (int[]) { fd_tls, fd_tls, STDOUT_FILENO },
                        NULL, 0,
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_REARRANGE_STDIO|FORK_LOG|FORK_REOPEN_LOG,
                        &openssl_pidref));
        if (r == 0) {
                /* Child */
                close(fd_tls);
                close(fd_server);

                execlp("openssl", "openssl", "s_server", "-accept", bind_str,
                       "-key", key_path, "-cert", cert_path,
                       "-quiet", "-naccept", "1", "-www", NULL);
                log_error("exec failed, is something wrong with the 'openssl' command?");
                _exit(EXIT_FAILURE);
        } else {
                pthread_mutex_t *server_lock = (pthread_mutex_t *)p;

                close(fd_tls);
                doh_server_handle(fd_server);

                /* Once the test is done kill the TLS server to release the port */
                assert_se(pthread_mutex_lock(server_lock) == 0);
                assert_se(pidref_kill(&openssl_pidref, SIGTERM) >= 0);
                assert_se(pidref_wait_for_terminate(&openssl_pidref, NULL) >= 0);
                assert_se(pthread_mutex_unlock(server_lock) == 0);
        }

        return NULL;
}

static void test_doh(void) {
        log_info("test-resolve-doh: Not implemented yet.");
}

static int try_isolate_network(void) {
        _cleanup_close_ int socket_fd = -EBADF;
        int r;

        /* First test if CLONE_NEWUSER/CLONE_NEWNET can actually work for us, i.e. we can open the namespaces
         * and then still access the build dir we are run from. We do that in a child process since it's
         * nasty if we have to go back from the namespace once we entered it and realized it cannot work. */
        r = pidref_safe_fork("(usernstest)", FORK_DEATHSIG_SIGKILL|FORK_LOG|FORK_WAIT, NULL);
        if (r == 0) { /* child */
                _cleanup_free_ char *rt = NULL, *d = NULL;

                if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
                        log_warning_errno(errno, "test-resolved-doh: Can't create user and network ns, running on host: %m");
                        _exit(EXIT_FAILURE);
                }

                assert_se(get_process_exe(0, &rt) >= 0);
                assert_se(path_extract_directory(rt, &d) >= 0);

                if (access(d, F_OK) < 0) {
                        log_warning_errno(errno, "test-resolved-doh: Can't access /proc/self/exe from user/network ns, running on host: %m");
                        _exit(EXIT_FAILURE);
                }

                _exit(EXIT_SUCCESS);
        }
        if (r == -EPROTO) /* EPROTO means nonzero exit code of child, i.e. the tests in the child failed */
                return 0;
        assert_se(r > 0);

        /* Now that we know that the unshare() is safe, let's actually do it */
        assert_se(unshare(CLONE_NEWUSER | CLONE_NEWNET) >= 0);

        /* Bring up the loopback interface on the newly created network namespace */
        struct ifreq req = { .ifr_ifindex = 1 };
        assert_se((socket_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)) >= 0);
        assert_se(ioctl(socket_fd, SIOCGIFNAME, &req) >= 0);
        assert_se(ioctl(socket_fd, SIOCGIFFLAGS, &req) >= 0);
        assert_se(FLAGS_SET(req.ifr_flags, IFF_LOOPBACK));
        req.ifr_flags |= IFF_UP;
        /* Do not assert on this, fails in the Ubuntu 24.04 CI environment */
        r = RET_NERRNO(ioctl(socket_fd, SIOCSIFFLAGS, &req));
        if (r < 0)
                return r;

        return 0;
}

int main(int argc, char **argv) {
        server_address = (union sockaddr_union) {
                .in.sin_family = AF_INET,
                .in.sin_port = htobe16(random_u64_range(UINT16_MAX - 1024) + 1024),
                .in.sin_addr.s_addr = htobe32(INADDR_LOOPBACK)
        };
        int r;

        test_setup_logging(LOG_DEBUG);

        r = try_isolate_network();
        if (r == -EPERM)
                return log_tests_skipped("Not running as root, and user/network namespacing not available.");
        assert_se(r >= 0);

        if (system("openssl version >/dev/null 2>&1") != 0)
                return log_tests_skipped("Skipping DOH test since the 'openssl' command does not seem to be available");

        test_doh();

        return 0;
}
