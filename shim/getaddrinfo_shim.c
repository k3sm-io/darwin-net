/*
 * k3sm getaddrinfo DYLD interpose shim.
 *
 * macOS getaddrinfo() routes through mDNSResponder/configd and ignores
 * /etc/resolv.conf, so a pod cannot be pointed at the cluster resolver the
 * normal way (k3sm/docs/DESIGN.md §3). This dylib, loaded via
 * DYLD_INSERT_LIBRARIES, interposes getaddrinfo() and resolves cluster names by
 * querying CoreDNS over the cluster DNS VIP itself, applying resolv.conf-style
 * ndots/search expansion. Its algorithm mirrors the Go reference resolver in
 * ../pkg/dns (expand.go + resolver.go); keep the two in lockstep.
 *
 * It is plain C built with clang (see ../hack/build-shim.sh), NOT Go cgo:
 * darwin-net's Go stays CGO_ENABLED=0, and a DYLD interposer must be a C dylib
 * with a __DATA,__interpose section regardless.
 *
 * Configuration comes from the environment (the runtime sets these per pod):
 *   K3SM_DNS_SERVER  - cluster DNS VIP (IPv4), e.g. "10.43.0.10"
 *   K3SM_DNS_PORT    - DNS port (optional, default 53)
 *   K3SM_DNS_DOMAIN  - cluster domain, e.g. "cluster.local"
 *   K3SM_DNS_SEARCH  - space-separated search list
 *   K3SM_DNS_NDOTS   - ndots (optional, default 5)
 *
 * If K3SM_DNS_SERVER is unset, the shim transparently defers to the real
 * getaddrinfo for every call, so a non-pod process loading it is unaffected.
 */

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* -------- DYLD interpose plumbing -------- */

typedef struct interpose_s {
    const void *replacement;
    const void *original;
} interpose_t;

int k3sm_getaddrinfo(const char *node, const char *service,
                     const struct addrinfo *hints, struct addrinfo **res);

__attribute__((used)) static const interpose_t k3sm_interposers[]
    __attribute__((section("__DATA,__interpose"))) = {
        {(const void *)k3sm_getaddrinfo, (const void *)getaddrinfo},
};

/* -------- config from environment -------- */

#define K3SM_MAX_SEARCH 8
#define K3SM_MAX_NAME 256

typedef struct {
    int enabled;
    char server[64];
    char port[8];
    char domain[K3SM_MAX_NAME];
    char search[K3SM_MAX_SEARCH][K3SM_MAX_NAME];
    int nsearch;
    int ndots;
} k3sm_cfg_t;

static void k3sm_load_cfg(k3sm_cfg_t *c) {
    memset(c, 0, sizeof(*c));
    const char *server = getenv("K3SM_DNS_SERVER");
    if (server == NULL || server[0] == '\0') {
        c->enabled = 0;
        return;
    }
    c->enabled = 1;
    snprintf(c->server, sizeof(c->server), "%s", server);

    const char *port = getenv("K3SM_DNS_PORT");
    if (port == NULL || port[0] == '\0') {
        port = "53";
    }
    snprintf(c->port, sizeof(c->port), "%s", port);

    const char *domain = getenv("K3SM_DNS_DOMAIN");
    if (domain != NULL) {
        snprintf(c->domain, sizeof(c->domain), "%s", domain);
    }

    const char *ndots = getenv("K3SM_DNS_NDOTS");
    c->ndots = (ndots != NULL && ndots[0] != '\0') ? atoi(ndots) : 5;
    if (c->ndots < 0) {
        c->ndots = 5;
    }

    const char *search = getenv("K3SM_DNS_SEARCH");
    c->nsearch = 0;
    if (search != NULL && search[0] != '\0') {
        char buf[K3SM_MAX_SEARCH * K3SM_MAX_NAME];
        snprintf(buf, sizeof(buf), "%s", search);
        char *save = NULL;
        for (char *tok = strtok_r(buf, " \t", &save);
             tok != NULL && c->nsearch < K3SM_MAX_SEARCH;
             tok = strtok_r(NULL, " \t", &save)) {
            /* strip a single trailing dot */
            size_t l = strlen(tok);
            if (l > 0 && tok[l - 1] == '.') {
                tok[l - 1] = '\0';
            }
            if (tok[0] == '\0') {
                continue;
            }
            snprintf(c->search[c->nsearch], K3SM_MAX_NAME, "%s", tok);
            c->nsearch++;
        }
    }
}

/* count interior dots, ignoring a single trailing dot */
static int k3sm_count_dots(const char *name) {
    int dots = 0;
    size_t n = strlen(name);
    if (n > 0 && name[n - 1] == '.') {
        n--; /* ignore trailing dot */
    }
    for (size_t i = 0; i < n; i++) {
        if (name[i] == '.') {
            dots++;
        }
    }
    return dots;
}

/*
 * Build the ordered candidate FQDN list for name, mirroring
 * pkg/dns/expand.go: absolute (trailing dot) -> just the name; dots >= ndots ->
 * absolute first then search; else search first then absolute. Returns the
 * count; candidates are written into out (each up to K3SM_MAX_NAME).
 */
static int k3sm_candidates(const k3sm_cfg_t *c, const char *name,
                           char out[][K3SM_MAX_NAME], int max) {
    int n = 0;
    size_t len = strlen(name);

    if (len > 0 && name[len - 1] == '.') {
        if (n < max) {
            snprintf(out[n], K3SM_MAX_NAME, "%.*s", (int)(len - 1), name);
            n++;
        }
        return n;
    }

    int dots = k3sm_count_dots(name);
    int absolute_first = (dots >= c->ndots);

    if (absolute_first && n < max) {
        snprintf(out[n], K3SM_MAX_NAME, "%s", name);
        n++;
    }
    for (int i = 0; i < c->nsearch && n < max; i++) {
        snprintf(out[n], K3SM_MAX_NAME, "%s.%s", name, c->search[i]);
        n++;
    }
    if (!absolute_first && n < max) {
        snprintf(out[n], K3SM_MAX_NAME, "%s", name);
        n++;
    }
    return n;
}

/* -------- minimal DNS A query over UDP -------- */

/* Encode a dotted name into DNS wire label format. Returns bytes written or -1. */
static int k3sm_encode_name(const char *name, uint8_t *buf, size_t cap) {
    size_t pos = 0;
    const char *p = name;
    while (*p != '\0') {
        const char *dot = strchr(p, '.');
        size_t label = dot ? (size_t)(dot - p) : strlen(p);
        if (label == 0) { /* skip empty label (e.g. trailing dot) */
            if (dot == NULL) break;
            p = dot + 1;
            continue;
        }
        if (label > 63 || pos + label + 1 >= cap) {
            return -1;
        }
        buf[pos++] = (uint8_t)label;
        memcpy(buf + pos, p, label);
        pos += label;
        if (dot == NULL) break;
        p = dot + 1;
    }
    if (pos + 1 >= cap) {
        return -1;
    }
    buf[pos++] = 0; /* root label */
    return (int)pos;
}

/*
 * Query the configured DNS server for an A record of fqdn. On success writes the
 * 4-byte IPv4 address into addr4 and returns 0; returns -1 on any failure
 * (timeout, NXDOMAIN, no A record).
 */
static int k3sm_query_a(const k3sm_cfg_t *c, const char *fqdn,
                        uint8_t addr4[4]) {
    uint8_t qbuf[512];
    /* DNS header: id, flags(RD), qd=1 */
    uint16_t id = 0x1234;
    memset(qbuf, 0, 12);
    qbuf[0] = (uint8_t)(id >> 8);
    qbuf[1] = (uint8_t)(id & 0xff);
    qbuf[2] = 0x01; /* RD */
    qbuf[5] = 0x01; /* QDCOUNT=1 */
    int npos = k3sm_encode_name(fqdn, qbuf + 12, sizeof(qbuf) - 12);
    if (npos < 0) {
        return -1;
    }
    size_t pos = 12 + (size_t)npos;
    if (pos + 4 > sizeof(qbuf)) {
        return -1;
    }
    qbuf[pos++] = 0x00;
    qbuf[pos++] = 0x01; /* QTYPE=A */
    qbuf[pos++] = 0x00;
    qbuf[pos++] = 0x01; /* QCLASS=IN */

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)atoi(c->port));
    if (inet_pton(AF_INET, c->server, &sa.sin_addr) != 1) {
        close(fd);
        return -1;
    }

    if (sendto(fd, qbuf, pos, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }

    uint8_t rbuf[1500];
    ssize_t rn = recvfrom(fd, rbuf, sizeof(rbuf), 0, NULL, NULL);
    close(fd);
    if (rn < 12) {
        return -1;
    }

    /* Verify id and that it is a response. */
    if (rbuf[0] != qbuf[0] || rbuf[1] != qbuf[1]) {
        return -1;
    }
    int qdcount = (rbuf[4] << 8) | rbuf[5];
    int ancount = (rbuf[6] << 8) | rbuf[7];
    if (ancount < 1) {
        return -1;
    }

    /* Skip the question section. */
    size_t off = 12;
    for (int q = 0; q < qdcount; q++) {
        while (off < (size_t)rn && rbuf[off] != 0) {
            if ((rbuf[off] & 0xc0) == 0xc0) { /* compression pointer */
                off += 2;
                goto qname_done;
            }
            off += rbuf[off] + 1;
        }
        off += 1; /* root label */
    qname_done:
        off += 4; /* QTYPE + QCLASS */
    }

    /* Walk answers for the first A record. */
    for (int a = 0; a < ancount && off + 12 <= (size_t)rn; a++) {
        /* name (may be a compression pointer) */
        if ((rbuf[off] & 0xc0) == 0xc0) {
            off += 2;
        } else {
            while (off < (size_t)rn && rbuf[off] != 0) {
                off += rbuf[off] + 1;
            }
            off += 1;
        }
        if (off + 10 > (size_t)rn) {
            return -1;
        }
        int type = (rbuf[off] << 8) | rbuf[off + 1];
        int rdlen = (rbuf[off + 8] << 8) | rbuf[off + 9];
        off += 10;
        if (off + (size_t)rdlen > (size_t)rn) {
            return -1;
        }
        if (type == 1 && rdlen == 4) { /* A */
            memcpy(addr4, rbuf + off, 4);
            return 0;
        }
        off += rdlen;
    }
    return -1;
}

/* Build a one-entry struct addrinfo result for an IPv4 address. */
static int k3sm_make_result(const uint8_t addr4[4], const char *service,
                            const struct addrinfo *hints,
                            struct addrinfo **res) {
    struct addrinfo *ai = (struct addrinfo *)calloc(1, sizeof(struct addrinfo));
    if (ai == NULL) {
        return EAI_MEMORY;
    }
    struct sockaddr_in *sin =
        (struct sockaddr_in *)calloc(1, sizeof(struct sockaddr_in));
    if (sin == NULL) {
        free(ai);
        return EAI_MEMORY;
    }
    sin->sin_family = AF_INET;
    sin->sin_len = sizeof(struct sockaddr_in);
    memcpy(&sin->sin_addr, addr4, 4);
    if (service != NULL && service[0] != '\0') {
        sin->sin_port = htons((uint16_t)atoi(service));
    }

    ai->ai_family = AF_INET;
    ai->ai_socktype = hints ? hints->ai_socktype : 0;
    ai->ai_protocol = hints ? hints->ai_protocol : 0;
    ai->ai_addrlen = sizeof(struct sockaddr_in);
    ai->ai_addr = (struct sockaddr *)sin;
    ai->ai_next = NULL;
    *res = ai;
    return 0;
}

/*
 * The interposed getaddrinfo. When the shim is configured (K3SM_DNS_SERVER set)
 * and the request is a plain hostname (not a numeric literal, not a service-only
 * lookup), it resolves via CoreDNS using ndots/search expansion. Anything it
 * cannot or should not handle falls through to the real getaddrinfo.
 */
int k3sm_getaddrinfo(const char *node, const char *service,
                     const struct addrinfo *hints, struct addrinfo **res) {
    k3sm_cfg_t cfg;
    k3sm_load_cfg(&cfg);

    /* Not configured, or no hostname to resolve: defer to the system. */
    if (!cfg.enabled || node == NULL || node[0] == '\0') {
        return getaddrinfo(node, service, hints, res);
    }
    /* AI_NUMERICHOST or a literal IPv4: let the system parse it. */
    struct in_addr tmp;
    if (inet_pton(AF_INET, node, &tmp) == 1) {
        return getaddrinfo(node, service, hints, res);
    }
    if (hints != NULL && (hints->ai_flags & AI_NUMERICHOST)) {
        return getaddrinfo(node, service, hints, res);
    }
    /* Only IPv4 is served by the cluster path; for AF_INET6-only requests defer. */
    if (hints != NULL && hints->ai_family == AF_INET6) {
        return getaddrinfo(node, service, hints, res);
    }

    char cands[K3SM_MAX_SEARCH + 1][K3SM_MAX_NAME];
    int ncand = k3sm_candidates(&cfg, node, cands, K3SM_MAX_SEARCH + 1);
    for (int i = 0; i < ncand; i++) {
        uint8_t addr4[4];
        if (k3sm_query_a(&cfg, cands[i], addr4) == 0) {
            return k3sm_make_result(addr4, service, hints, res);
        }
    }
    /* Cluster resolver had no answer: fall through so external names still work. */
    return getaddrinfo(node, service, hints, res);
}
