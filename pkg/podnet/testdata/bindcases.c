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
 * MODES (B218 added the second). With three arguments the harness runs the BIND
 * table and nothing else, byte-for-byte as it did for B216 — that is a contract,
 * not a coincidence: the B216 gate diffs whole arms against each other, so a new
 * line in the default output would red a gate about a different rung. The
 * connect table runs only when it is asked for by name.
 *
 * Usage:  bindcases <base-port> <low-port> <unix-dir>
 *         bindcases <base-port> <low-port> <unix-dir> connect <in-dst> <out-dst>
 *   base-port  a free high port; case i uses base-port + i.
 *   low-port   a port below K3SM_BIND_MIN_PORT (the privileged-range carve).
 *   unix-dir   a writable directory for the AF_UNIX case's socket path.
 *   in-dst     an IPv4 address the caller HAS declared in K3SM_CLUSTER_CIDRS.
 *   out-dst    an IPv4 address the caller has NOT declared there.
 * The two destinations are supplied rather than compiled in so the gate owns ONE
 * copy of the in-scope/out-of-scope fact — the env it exports and the addresses
 * it dials cannot drift apart.
 *
 * WHAT THE CONNECT TABLE OBSERVES, AND WHY IT USES TEST-NET DESTINATIONS. The
 * connect() rung's whole claim is about SOURCE selection, so a case is only
 * meaningful where the kernel's own choice differs from the pod address. On a
 * rootless host there is exactly ONE usable loopback address (127.0.0.2 is not
 * bindable without an alias, hence without root), so a loopback destination
 * would be source-selected to 127.0.0.1 with or without the rung and prove
 * nothing. An RFC 5737 TEST-NET destination fixes that: the kernel source-selects
 * the outbound interface's address for it, so a rewrite to 127.0.0.1 is visible
 * in getsockname(2) — and it stays hermetic, because a connect(2) on a SOCK_DGRAM
 * socket only fills in the pcb. NOTHING IS SENT by any UDP case here. The one
 * case that completes a real handshake (connect_tcp_in_cluster) dials a listener
 * this same process opened on 127.0.0.1.
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

/* ============================ the connect table ======================== */

/*
 * Which destination a connect case dials. IN and OUT are the two argv-supplied
 * TEST-NET addresses; LIVE is the loopback listener this process opens, and is
 * the only case that completes a handshake.
 */
enum dst_kind {
    DST_IN = 0,  /* inside the caller's declared K3SM_CLUSTER_CIDRS */
    DST_OUT,     /* outside it — an external dial that must NEVER be pinned */
    DST_LIVE,    /* 127.0.0.1:<this process's listener> */
    DST_V6,      /* [::1] — out of the rung's v1 scope */
    DST_PATH,    /* an AF_UNIX path — a family that must not be cast */
};

typedef struct {
    const char *name;
    int family;
    int socktype;
    enum dst_kind dst;
    /* prebind: bind the socket to 0.0.0.0:0 BEFORE connect. An application that
     * bound its own source made an explicit choice and the rung must respect it;
     * the kernel then re-selects the source address at connect while KEEPING the
     * port, so the observable is the address, not the port. */
    int prebind;
    /* short_addrlen: pass an addrlen one byte shorter than the sockaddr. The
     * kernel answers EINVAL; what matters is that the shim did not cast first. */
    int short_addrlen;
} conncase_t;

static const conncase_t conncases[] = {
    {"connect_udp_in_cluster", AF_INET, SOCK_DGRAM, DST_IN, 0, 0},
    {"connect_udp_out_cluster", AF_INET, SOCK_DGRAM, DST_OUT, 0, 0},
    {"connect_udp_prebound", AF_INET, SOCK_DGRAM, DST_IN, 1, 0},
    {"connect_tcp_in_cluster", AF_INET, SOCK_STREAM, DST_LIVE, 0, 0},
    {"connect_tcp_prebound", AF_INET, SOCK_STREAM, DST_LIVE, 1, 0},
    {"connect_inet6_loopback", AF_INET6, SOCK_DGRAM, DST_V6, 0, 0},
    {"connect_unix", AF_UNIX, SOCK_STREAM, DST_PATH, 0, 0},
    {"connect_short_addrlen", AF_INET, SOCK_DGRAM, DST_IN, 0, 1},
};

static const size_t nconncases = sizeof conncases / sizeof conncases[0];

/* The port dialled on the two TEST-NET destinations. Nothing is ever sent to it
 * (every case using it is SOCK_DGRAM, where connect(2) is a pcb-local
 * operation), so any port does; a fixed one keeps the output stable. */
#define B218_DEAD_PORT 9999

/*
 * run_connect_cases opens one loopback listener for the DST_LIVE cases, walks
 * the table, and prints one line per case in the same shape the bind table uses
 * plus PEER for the case that is accepted:
 *
 *     CASE=<name> RC=<rc> ERRNO=<n> LOCAL=<getsockname> REUSE=<0|1> [PEER=<addr>]
 *
 * LOCAL is the SOURCE the socket ended up with — the whole point of the rung.
 * REUSE is printed because the connect rung deliberately does NOT set
 * SO_REUSEADDR (unlike the bind rung), and a gate can only assert that if the
 * harness reports it. PEER is what the ACCEPTING side sees, which is the exact
 * observation B215 P1d made about source fidelity.
 */
static int run_connect_cases(const char *unixdir, const char *in_dst, const char *out_dst) {
    struct in_addr in_a, out_a;
    if (inet_pton(AF_INET, in_dst, &in_a) != 1 || inet_pton(AF_INET, out_dst, &out_a) != 1) {
        fprintf(stderr, "bindcases: <in-dst>/<out-dst> must be IPv4 literals\n");
        return 2;
    }

    /* The live listener. Its bind is SPECIFIC (127.0.0.1), so the bind rung
     * passes it through untouched and it cannot perturb the connect cases. */
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in la;
    memset(&la, 0, sizeof la);
    la.sin_family = AF_INET;
    la.sin_len = (unsigned char)sizeof la;
    la.sin_port = 0;
    la.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (ls < 0 || bind(ls, (const struct sockaddr *)&la, (socklen_t)sizeof la) != 0 ||
        listen(ls, 4) != 0) {
        fprintf(stderr, "bindcases: could not open the loopback listener (errno=%d)\n", errno);
        return 2;
    }
    socklen_t llen = (socklen_t)sizeof la;
    if (getsockname(ls, (struct sockaddr *)&la, &llen) != 0) {
        fprintf(stderr, "bindcases: getsockname on the listener failed (errno=%d)\n", errno);
        return 2;
    }

    for (size_t i = 0; i < nconncases; i++) {
        const conncase_t *c = &conncases[i];
        int fd = socket(c->family, c->socktype, 0);
        if (fd < 0) {
            printf("CASE=%s RC=-1 ERRNO=%d LOCAL=- REUSE=-1\n", c->name, errno);
            continue;
        }
        if (c->prebind) {
            struct sockaddr_in pb;
            memset(&pb, 0, sizeof pb);
            pb.sin_family = AF_INET;
            pb.sin_len = (unsigned char)sizeof pb;
            pb.sin_port = 0;
            pb.sin_addr.s_addr = htonl(INADDR_ANY);
            if (bind(fd, (const struct sockaddr *)&pb, (socklen_t)sizeof pb) != 0) {
                printf("CASE=%s RC=-1 ERRNO=%d LOCAL=- REUSE=-1\n", c->name, errno);
                close(fd);
                continue;
            }
        }

        struct sockaddr_storage ds;
        socklen_t dlen = 0;
        memset(&ds, 0, sizeof ds);
        if (c->family == AF_INET) {
            struct sockaddr_in *d = (struct sockaddr_in *)&ds;
            d->sin_family = AF_INET;
            d->sin_len = (unsigned char)sizeof *d;
            if (c->dst == DST_LIVE) {
                d->sin_port = la.sin_port;
                d->sin_addr = la.sin_addr;
            } else {
                d->sin_port = htons(B218_DEAD_PORT);
                d->sin_addr = c->dst == DST_IN ? in_a : out_a;
            }
            dlen = (socklen_t)sizeof *d;
        } else if (c->family == AF_INET6) {
            struct sockaddr_in6 *d6 = (struct sockaddr_in6 *)&ds;
            d6->sin6_family = AF_INET6;
            d6->sin6_len = (unsigned char)sizeof *d6;
            d6->sin6_port = htons(B218_DEAD_PORT);
            d6->sin6_addr = in6addr_loopback;
            dlen = (socklen_t)sizeof *d6;
        } else {
            struct sockaddr_un *un = (struct sockaddr_un *)&ds;
            un->sun_family = AF_UNIX;
            snprintf(un->sun_path, sizeof un->sun_path, "%s/b218-%zu.sock", unixdir, i);
            un->sun_len = (unsigned char)sizeof *un;
            dlen = (socklen_t)sizeof *un;
        }
        if (c->short_addrlen && dlen > 0) {
            dlen--;
        }

        errno = 0;
        int rc = connect(fd, (const struct sockaddr *)&ds, dlen);
        int err = rc == 0 ? 0 : errno;
        char local[128];
        render_local(fd, local, sizeof local);

        char peer[128];
        peer[0] = '\0';
        if (rc == 0 && c->dst == DST_LIVE) {
            struct sockaddr_in pa;
            socklen_t plen = (socklen_t)sizeof pa;
            memset(&pa, 0, sizeof pa);
            int as = accept(ls, (struct sockaddr *)&pa, &plen);
            if (as >= 0) {
                char pb[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &pa.sin_addr, pb, sizeof pb);
                /* What a PolicyTable keyed on the peer address would see. */
                snprintf(peer, sizeof peer, " PEER=%s:%u", pb, (unsigned)ntohs(pa.sin_port));
                close(as);
            } else {
                snprintf(peer, sizeof peer, " PEER=-");
            }
        }

        printf("CASE=%s RC=%d ERRNO=%d LOCAL=%s REUSE=%d%s\n", c->name, rc, err, local,
               reuseaddr_of(fd), peer);
        fflush(stdout);
        close(fd);
    }
    close(ls);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 4 && !(argc == 7 && strcmp(argv[4], "connect") == 0)) {
        fprintf(stderr,
                "usage: %s <base-port> <low-port> <unix-dir>\n"
                "       %s <base-port> <low-port> <unix-dir> connect <in-dst> <out-dst>\n",
                argv[0], argv[0]);
        return 2;
    }
    unsigned base = (unsigned)strtoul(argv[1], NULL, 10);
    unsigned low = (unsigned)strtoul(argv[2], NULL, 10);
    const char *unixdir = argv[3];

    /* The connect table REPLACES the bind table rather than following it: the
     * B216 gate diffs whole arms of the default output, so the three-argument
     * form must stay byte-identical to what it printed before B218. */
    if (argc == 7) {
        return run_connect_cases(unixdir, argv[5], argv[6]);
    }

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
