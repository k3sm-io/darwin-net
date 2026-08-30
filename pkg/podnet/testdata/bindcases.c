/*
 * bindcases.c — the table-driven bind() case harness behind
 * hack/acceptance/B216.sh (the B216 gate).
 *
 * It walks a TABLE OF SOCKADDR SHAPES, calls bind(2) on each, and prints what
 * the kernel actually ended up with:
 *
 *     CASE=<name> RC=<rc> ERRNO=<n> LOCAL=<observed local address> REUSE=<0|1>
 *
 * LOCAL comes from getsockname(2) and REUSE from getsockopt(SO_REUSEADDR), so
 * every assertion the gate makes is about the SOCKET, never about what the shim
 * said it did. The K3SM_BIND_DEBUG trace is asserted separately and in addition;
 * neither channel alone would be enough (a trace can lie about the outcome, and
 * an outcome cannot say which branch produced it).
 *
 * The harness is deliberately shim-agnostic: it is the SAME binary in the
 * shim-injected and the control runs, so any difference between the two runs is
 * caused by the dylib and nothing else.
 *
 * Usage:  bindcases <base-port> <low-port> <unix-dir>
 *   base-port  a free high port; case i uses base-port + i.
 *   low-port   a port below K3SM_BIND_MIN_PORT (the privileged-range carve).
 *   unix-dir   a writable directory for the AF_UNIX case's socket path.
 *
 * NOTE ON THE POD IP USED BY THE GATE: the gate sets K3SM_POD_IP=127.0.0.1
 * rather than a 100.64/10 pod address. That keeps the whole gate hermetic and
 * ROOTLESS — a rewritten bind must land on an address that exists on this host,
 * and creating a lo0 alias needs root. 127.0.0.1 is a specific (non-wildcard)
 * local address, which is the only property the interpose's logic depends on,
 * and it makes the rewrite directly observable: 0.0.0.0 -> 127.0.0.1.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* Which address goes into the sockaddr under test. */
enum addr_kind {
    ADDR_WILDCARD = 0, /* INADDR_ANY / in6addr_any — the rewritable shape */
    ADDR_LOCAL,        /* 127.0.0.1 / ::1 — a specific, bindable local address */
    ADDR_FOREIGN,      /* 192.0.2.7 (RFC 5737 TEST-NET-1) — specific, NOT local */
    ADDR_UNIX,         /* a filesystem path — a family the shim must not cast */
};

/* Which port goes into the sockaddr under test. */
enum port_kind {
    PORT_HIGH = 0, /* base + index: at or above K3SM_BIND_MIN_PORT */
    PORT_LOW,      /* the privileged range: the low-port passthrough carve */
    PORT_ZERO,     /* an ephemeral client bind */
};

typedef struct {
    const char *name;
    int family;
    int socktype;
    enum addr_kind addr;
    enum port_kind port;
    /* v6only: -1 leave the socket's default, else set IPV6_V6ONLY to this. */
    int v6only;
    /* short_addrlen: pass an addrlen one byte SHORTER than the sockaddr, to
     * exercise the interpose's length validation (the kernel answers EINVAL;
     * what matters is that the shim did not cast and rewrite it anyway). */
    int short_addrlen;
} bindcase_t;

static const bindcase_t cases[] = {
    /* --- AF_INET --- */
    {"af_inet_wildcard", AF_INET, SOCK_STREAM, ADDR_WILDCARD, PORT_HIGH, -1, 0},
    {"af_inet_udp_wildcard", AF_INET, SOCK_DGRAM, ADDR_WILDCARD, PORT_HIGH, -1, 0},
    {"af_inet_lowport", AF_INET, SOCK_STREAM, ADDR_WILDCARD, PORT_LOW, -1, 0},
    {"af_inet_ephemeral", AF_INET, SOCK_STREAM, ADDR_WILDCARD, PORT_ZERO, -1, 0},
    {"af_inet_specific_local", AF_INET, SOCK_STREAM, ADDR_LOCAL, PORT_HIGH, -1, 0},
    {"af_inet_specific_foreign", AF_INET, SOCK_STREAM, ADDR_FOREIGN, PORT_HIGH, -1, 0},
    {"af_inet_short_addrlen", AF_INET, SOCK_STREAM, ADDR_WILDCARD, PORT_HIGH, -1, 1},
    /* --- AF_INET6 --- */
    {"af_inet6_any_dual", AF_INET6, SOCK_STREAM, ADDR_WILDCARD, PORT_HIGH, 0, 0},
    {"af_inet6_any_v6only", AF_INET6, SOCK_STREAM, ADDR_WILDCARD, PORT_HIGH, 1, 0},
    {"af_inet6_any_lowport", AF_INET6, SOCK_STREAM, ADDR_WILDCARD, PORT_LOW, 0, 0},
    {"af_inet6_specific_local", AF_INET6, SOCK_STREAM, ADDR_LOCAL, PORT_HIGH, 0, 0},
    /* --- a family the interpose must pass through before any cast --- */
    {"af_unix", AF_UNIX, SOCK_STREAM, ADDR_UNIX, PORT_HIGH, -1, 0},
};

static const size_t ncases = sizeof cases / sizeof cases[0];

/* render_local formats the socket's ACTUAL local address from getsockname(2). */
static void render_local(int fd, char *out, size_t cap) {
    struct sockaddr_storage ss;
    socklen_t slen = (socklen_t)sizeof ss;
    memset(&ss, 0, sizeof ss);
    if (getsockname(fd, (struct sockaddr *)&ss, &slen) != 0) {
        snprintf(out, cap, "-");
        return;
    }
    if (ss.ss_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)&ss;
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &in->sin_addr, buf, sizeof buf);
        snprintf(out, cap, "%s:%u", buf, (unsigned)ntohs(in->sin_port));
        return;
    }
    if (ss.ss_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)&ss;
        char buf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &in6->sin6_addr, buf, sizeof buf);
        snprintf(out, cap, "[%s]:%u", buf, (unsigned)ntohs(in6->sin6_port));
        return;
    }
    if (ss.ss_family == AF_UNIX) {
        const struct sockaddr_un *un = (const struct sockaddr_un *)&ss;
        snprintf(out, cap, "unix:%s", un->sun_path);
        return;
    }
    snprintf(out, cap, "family=%d", (int)ss.ss_family);
}

static int reuseaddr_of(int fd) {
    int on = -1;
    socklen_t olen = (socklen_t)sizeof on;
    if (getsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, &olen) != 0) {
        return -1;
    }
    return on != 0 ? 1 : 0;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s <base-port> <low-port> <unix-dir>\n", argv[0]);
        return 2;
    }
    unsigned base = (unsigned)strtoul(argv[1], NULL, 10);
    unsigned low = (unsigned)strtoul(argv[2], NULL, 10);
    const char *unixdir = argv[3];

    for (size_t i = 0; i < ncases; i++) {
        const bindcase_t *c = &cases[i];
        int fd = socket(c->family, c->socktype, 0);
        if (fd < 0) {
            printf("CASE=%s RC=-1 ERRNO=%d LOCAL=- REUSE=-1\n", c->name, errno);
            continue;
        }
        if (c->family == AF_INET6 && c->v6only >= 0) {
            int v = c->v6only;
            if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v, sizeof v) != 0) {
                printf("CASE=%s RC=-1 ERRNO=%d LOCAL=- REUSE=-1\n", c->name, errno);
                close(fd);
                continue;
            }
        }

        unsigned port = c->port == PORT_LOW ? low : c->port == PORT_ZERO ? 0 : base + (unsigned)i;

        struct sockaddr_storage ss;
        socklen_t slen = 0;
        memset(&ss, 0, sizeof ss);
        if (c->family == AF_INET) {
            struct sockaddr_in *in = (struct sockaddr_in *)&ss;
            in->sin_family = AF_INET;
            in->sin_len = (unsigned char)sizeof *in;
            in->sin_port = htons((unsigned short)port);
            if (c->addr == ADDR_LOCAL) {
                in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            } else if (c->addr == ADDR_FOREIGN) {
                inet_pton(AF_INET, "192.0.2.7", &in->sin_addr);
            } else {
                in->sin_addr.s_addr = htonl(INADDR_ANY);
            }
            slen = (socklen_t)sizeof *in;
        } else if (c->family == AF_INET6) {
            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&ss;
            in6->sin6_family = AF_INET6;
            in6->sin6_len = (unsigned char)sizeof *in6;
            in6->sin6_port = htons((unsigned short)port);
            if (c->addr == ADDR_LOCAL) {
                in6->sin6_addr = in6addr_loopback;
            } else {
                in6->sin6_addr = in6addr_any;
            }
            slen = (socklen_t)sizeof *in6;
        } else {
            struct sockaddr_un *un = (struct sockaddr_un *)&ss;
            un->sun_family = AF_UNIX;
            snprintf(un->sun_path, sizeof un->sun_path, "%s/b216-%zu.sock", unixdir, i);
            un->sun_len = (unsigned char)sizeof *un;
            (void)unlink(un->sun_path);
            slen = (socklen_t)sizeof *un;
        }
        if (c->short_addrlen && slen > 0) {
            slen--;
        }

        errno = 0;
        int rc = bind(fd, (const struct sockaddr *)&ss, slen);
        int err = rc == 0 ? 0 : errno;
        char local[128];
        if (rc == 0) {
            render_local(fd, local, sizeof local);
        } else {
            snprintf(local, sizeof local, "-");
        }
        printf("CASE=%s RC=%d ERRNO=%d LOCAL=%s REUSE=%d\n", c->name, rc, err, local,
               reuseaddr_of(fd));
        fflush(stdout);
        close(fd);
    }
    return 0;
}
