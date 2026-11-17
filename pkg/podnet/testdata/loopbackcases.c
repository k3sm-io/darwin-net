/*
 * Copyright The k3sm Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * loopbackcases: the case harness for the shim's loopback rung
 * (TestShimLoopbackConnectReachesOwnPodListener). It plays one pod: it opens
 * the pod's own listeners the way an application would (wildcard binds, which
 * the bind rung moves onto K3SM_POD_IP), then dials them through loopback, and
 * prints one line per case:
 *
 *   CASE=<name> RC=<0|-1> ERRNO=<n> GOT=<who answered>
 *
 * GOT is "pod" when one of this process's own listeners accepted the dial,
 * "host" when the host-side listener the Go test runs answered (it writes the
 * byte 'H' on accept), and "none" otherwise.
 *
 * usage: loopbackcases <base-port> <host-port> <shared-port> <absent-port> [<denied-port> <wild-port>]
 *   base-port..base-port+3  ports this harness listens on
 *   host-port               a 127.0.0.1 listener the test runs outside the pod
 *   shared-port             the test listens on 127.0.0.1:<shared-port> and
 *                           this harness on the wildcard, so both own the port
 *   absent-port             nothing listens there anywhere
 *   denied-port             (rig leg) a port the pod profile denies; dialled
 *                           through loopback and at $K3SM_POD_IP, both must be
 *                           EPERM. 0 skips both cases.
 *   wild-port               (rig leg) a host listener on the WILDCARD address
 *                           owned by another uid; the dial must still reach it.
 *                           0 skips the case.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int listen_on(int family, int type, const char *addr, int port, int v6only) {
    int s = socket(family, type, 0);
    if (s < 0) {
        perror("socket");
        exit(2);
    }
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    int rc;
    if (family == AF_INET) {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_len = sizeof sa;
        sa.sin_port = htons((unsigned short)port);
        inet_pton(AF_INET, addr, &sa.sin_addr);
        rc = bind(s, (struct sockaddr *)&sa, sizeof sa);
    } else {
        setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof v6only);
        struct sockaddr_in6 sa;
        memset(&sa, 0, sizeof sa);
        sa.sin6_family = AF_INET6;
        sa.sin6_len = sizeof sa;
        sa.sin6_port = htons((unsigned short)port);
        inet_pton(AF_INET6, addr, &sa.sin6_addr);
        rc = bind(s, (struct sockaddr *)&sa, sizeof sa);
    }
    if (rc != 0) {
        fprintf(stderr, "bind %s:%d: %s\n", addr, port, strerror(errno));
        exit(2);
    }
    if (type == SOCK_STREAM && listen(s, 8) != 0) {
        perror("listen");
        exit(2);
    }
    return s;
}

static int readable(int s, int ms) {
    struct pollfd p = {.fd = s, .events = POLLIN};
    return poll(&p, 1, ms) == 1;
}

/* who reports which side answered a connected stream socket c, given the
 * pod listener l that might have accepted it (l < 0: none). */
static const char *who(int c, int l) {
    if (l >= 0 && readable(l, 500)) {
        int a = accept(l, NULL, NULL);
        if (a >= 0) {
            close(a);
            return "pod";
        }
    }
    char b = 0;
    if (readable(c, 500) && recv(c, &b, 1, 0) == 1 && b == 'H') {
        return "host";
    }
    return "none";
}

static void report(const char *name, int rc, int err, const char *got) {
    printf("CASE=%s RC=%d ERRNO=%d GOT=%s\n", name, rc, rc == 0 ? 0 : err, got);
    fflush(stdout);
}

static void dial4(const char *name, int type, const char *dst, int port, int listener) {
    int c = socket(AF_INET, type, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_len = sizeof sa;
    sa.sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, dst, &sa.sin_addr);
    int rc = connect(c, (struct sockaddr *)&sa, sizeof sa);
    int err = errno;
    const char *got = "none";
    if (rc == 0 && type == SOCK_STREAM) {
        got = who(c, listener);
    } else if (rc == 0) {
        send(c, "x", 1, 0);
        char b;
        got = (readable(listener, 500) && recv(listener, &b, 1, 0) == 1) ? "pod" : "none";
    }
    report(name, rc, err, got);
    close(c);
}

static void dial6(const char *name, const char *dst, int port, int listener) {
    int c = socket(AF_INET6, SOCK_STREAM, 0);
    int zero = 0;
    setsockopt(c, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero);
    struct sockaddr_in6 sa;
    memset(&sa, 0, sizeof sa);
    sa.sin6_family = AF_INET6;
    sa.sin6_len = sizeof sa;
    sa.sin6_port = htons((unsigned short)port);
    inet_pton(AF_INET6, dst, &sa.sin6_addr);
    int rc = connect(c, (struct sockaddr *)&sa, sizeof sa);
    int err = errno;
    report(name, rc, err, rc == 0 ? who(c, listener) : "none");
    close(c);
}

int main(int argc, char **argv) {
    if (argc != 5 && argc != 7) {
        fprintf(stderr, "usage: loopbackcases <base-port> <host-port> <shared-port> <absent-port> "
                        "[<denied-port> <wild-port>]\n");
        return 2;
    }
    int base = atoi(argv[1]), host = atoi(argv[2]), shared = atoi(argv[3]), absent = atoi(argv[4]);
    int denied = argc == 7 ? atoi(argv[5]) : 0, wild = argc == 7 ? atoi(argv[6]) : 0;

    int l4 = listen_on(AF_INET, SOCK_STREAM, "0.0.0.0", base, 0);
    int ldual = listen_on(AF_INET6, SOCK_STREAM, "::", base + 1, 0);
    int lu = listen_on(AF_INET, SOCK_DGRAM, "0.0.0.0", base + 2, 0);
    int llo = listen_on(AF_INET, SOCK_STREAM, "127.0.0.1", base + 3, 0);
    int lshared = listen_on(AF_INET, SOCK_STREAM, "0.0.0.0", shared, 0);

    dial4("own_tcp", SOCK_STREAM, "127.0.0.1", base, l4);
    dial4("own_tcp_other_loopback", SOCK_STREAM, "127.0.0.2", base, l4);
    dial4("own_dualstack_via_v4", SOCK_STREAM, "127.0.0.1", base + 1, ldual);
    dial6("own_dualstack_via_v6", "::1", base + 1, ldual);
    dial4("own_udp_connected", SOCK_DGRAM, "127.0.0.1", base + 2, lu);

    /* An unconnected datagram: the sendto() interpose. */
    {
        int c = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_len = sizeof sa;
        sa.sin_port = htons((unsigned short)(base + 2));
        inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
        ssize_t n = sendto(c, "y", 1, 0, (struct sockaddr *)&sa, sizeof sa);
        int err = errno;
        char b;
        const char *got = (n == 1 && readable(lu, 500) && recv(lu, &b, 1, 0) == 1) ? "pod" : "none";
        report("own_udp_sendto", n == 1 ? 0 : -1, err, got);
        close(c);
    }

    dial4("own_explicit_loopback", SOCK_STREAM, "127.0.0.1", base + 3, llo);
    dial4("host_loopback", SOCK_STREAM, "127.0.0.1", host, -1);
    dial4("shared_port_pod_wins", SOCK_STREAM, "127.0.0.1", shared, lshared);
    dial4("absent", SOCK_STREAM, "127.0.0.1", absent, -1);
    if (denied > 0) {
        const char *podip = getenv("K3SM_POD_IP");
        dial4("denied_loopback", SOCK_STREAM, "127.0.0.1", denied, -1);
        if (podip != NULL) {
            dial4("denied_podip", SOCK_STREAM, podip, denied, -1);
        }
    }
    if (wild > 0) {
        dial4("host_wildcard", SOCK_STREAM, "127.0.0.1", wild, -1);
    }

    close(l4);
    close(ldual);
    close(lu);
    close(llo);
    close(lshared);
    return 0;
}
