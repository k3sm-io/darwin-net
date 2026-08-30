/*
 * k3sm pod DYLD interpose shim — getaddrinfo() AND bind().
 *
 * SCOPE BANNER (widened by B216). This file started life as the getaddrinfo
 * interposer and now owns TWO interposes in ONE dylib: the cluster-DNS
 * getaddrinfo() below, and the per-pod bind() discipline at the bottom of the
 * file. They share nothing but the __DATA,__interpose table and the
 * environment-configured, transparent-passthrough idiom; each reads its own
 * K3SM_* env and is independently inert when that env is absent. The artifact is
 * still named libk3sm_getaddrinfo_shim.dylib because the name is coupled to the
 * install path and to the k3sm.io/dyld-insert-libraries annotation that injects
 * it; renaming it is a deliberate non-goal here, so this banner carries the
 * truth instead.
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
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* -------- DYLD interpose plumbing -------- */

/*
 * DYLD-strip ceiling (detection deferred — documented, not enforced here):
 * DYLD_INSERT_LIBRARIES (hence this interposer) is IGNORED for a process whose
 * main executable is an Apple-platform binary, runs under the hardened runtime,
 * or enables library validation. In those cases the shim silently never loads
 * and getaddrinfo() takes its normal mDNSResponder path, so a cluster name gets
 * an NXDOMAIN instead of being resolved. runtimed spawns pods via its
 * NON-platform exec-shim precisely so the injection survives (see
 * ../pkg/dns/doc.go); a workload that re-execs into a platform/hardened binary
 * loses cluster DNS. Auto-detecting that condition from inside the shim is a
 * future item; for now it is a known operational boundary, not a runtime error.
 */

typedef struct interpose_s {
    const void *replacement;
    const void *original;
} interpose_t;

int k3sm_getaddrinfo(const char *node, const char *service,
                     const struct addrinfo *hints, struct addrinfo **res);
int k3sm_bind(int fd, const struct sockaddr *addr, socklen_t len);

__attribute__((used)) static const interpose_t k3sm_interposers[]
    __attribute__((section("__DATA,__interpose"))) = {
        {(const void *)k3sm_getaddrinfo, (const void *)getaddrinfo},
        {(const void *)k3sm_bind, (const void *)bind},
};

/* -------- config from environment -------- */

#define K3SM_MAX_SEARCH 8

/*
 * K3SM_DNS_MAX_NAME_LEN is the ONE shared boundary for how long a candidate name
 * may be, measured as this shim stores it: PRESENTATION form, dotted labels, NO
 * trailing dot, no NUL. Every length check in this file compares against it. The
 * buffer capacities nearby (K3SM_MAX_NAME below, the 500-byte wire budget in
 * k3sm_build_query) are incidental sizes and must NEVER be used as the boundary
 * — that conflation is exactly the bug this constant closes.
 *
 * DERIVED FROM THE GO REFERENCE (pkg/dns/resolver.go queryA), not from RFC
 * memory, because the two engines must accept and reject the SAME names:
 *   - queryA encodes ensureFQDN(candidate) — the candidate WITH a trailing dot
 *     appended — through dnsmessage.NewName then Message.Pack.
 *   - dnsmessage.Name.pack rejects Length > nonEncodedNameMax == 254, so the
 *     dotted form is encodable iff it is <= 254 bytes. (NewName alone only
 *     bounds <= 255, so a 255-byte dotted name gets past it and dies in Pack;
 *     either way the Go side yields a definitive miss with zero wire I/O.)
 *   - candidate + '.'  <= 254   <=>   candidate <= 253.
 * So a name of exactly 253 bytes is encodable on BOTH sides and 254 is rejected
 * on BOTH. Independently confirmed by the wire arithmetic: a presentation name
 * of L bytes with k labels encodes to L + 2 octets (each of the k-1 dots becomes
 * a length byte, plus one leading length byte and the root label), so L = 253 is
 * exactly the RFC 1035 255-octet wire ceiling, and by dnsmessage's unpack guard,
 * which refuses a decoded name once it would reach 254 bytes.
 *
 * pkg/dns/env_test.go TestShimMaxNameLenMatchesGo binds this value to the Go
 * encoder behaviourally (it must be the largest length the reference resolver
 * still puts on the wire), and the wire differential pins the boundary and
 * boundary+1 cases on both engines.
 */
#define K3SM_DNS_MAX_NAME_LEN 253

/*
 * Storage capacity for one presentation name: the boundary, plus its NUL, plus
 * slack. This is a BUFFER SIZE, never a policy: a candidate is judged against
 * K3SM_DNS_MAX_NAME_LEN *before* it is written here, so bumping this number can
 * never widen what the shim will encode or put on the wire. Shrinking it below
 * K3SM_DNS_MAX_NAME_LEN + 1 would silently truncate a LEGAL name, which the
 * assertion below refuses at compile time.
 */
#define K3SM_MAX_NAME 256

_Static_assert(K3SM_MAX_NAME >= K3SM_DNS_MAX_NAME_LEN + 1,
               "candidate buffer must hold a boundary-length name plus its NUL");

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
 *
 * bad[i] is set when candidate i's would-be PRESENTATION length exceeds
 * K3SM_DNS_MAX_NAME_LEN — precisely the names the Go reference refuses to
 * encode. The length is computed from the INPUTS, before the snprintf, because
 * afterwards the stored bytes are truncated to K3SM_MAX_NAME and strlen(out[i])
 * can no longer tell an over-long name from a merely long one.
 *
 * An over-long candidate KEEPS ITS SLOT: out[i] holds the truncated bytes and
 * the returned count is unchanged. The list must walk in per-candidate lockstep
 * with the Go resolver's, and the wire differential asserts exactly ONE debug
 * trace line per candidate, so shrinking the list would break both. The caller
 * short-circuits a bad slot to a definitive miss, without classifying it and
 * without touching the wire.
 *
 * The same test is applied identically before EACH of the three would-be-length
 * computations below, and ALL THREE now have WIRE-LEVEL coverage in
 * ../pkg/dns/differential_integration_test.go — named case by named case, never
 * a blanket "covered":
 *
 *   - ABSOLUTE, `len - 1 > MAX` (the trailing-dot branch): boundary_max_name
 *     pins the FALSE polarity (a name at exactly MAX still reaches the wire on
 *     both engines) and boundary_over_max_name the TRUE one (one byte past MAX
 *     reaches neither engine's wire).
 *   - SEARCH-SUFFIXED, `len + 1 + strlen(search) > MAX` (the search loop):
 *     search_suffix_over_boundary pins the TRUE polarity — one dedicated search
 *     domain calibrated so the bare name is under MAX but the suffixed candidate
 *     is over it, so the two candidates of ONE request straddle the boundary and
 *     exactly the suffixed one shows a miss with zero wire I/O. Its FALSE
 *     polarity is the ordinary in-pod path, pinned behaviourally by
 *     TestGetaddrinfoShimResolvesViaStub (a short name's search-expanded
 *     candidate reaches the stub and HITs).
 *   - PLAIN, `len > MAX` (two physical occurrences of one check):
 *     plain_over_boundary pins the TRUE polarity at the TAIL site (ndots high,
 *     an over-long bare name makes every candidate bad, zero observed queries),
 *     absolute_first_over_boundary pins the TRUE polarity at the ABSOLUTE-FIRST
 *     site (the same name with ndots 1, dots >= ndots), and
 *     search_suffix_over_boundary's second candidate pins the FALSE one (the
 *     under-MAX bare name does reach the wire).
 *
 * Keep the sites literally parallel: the differential compares the two engines
 * per CANDIDATE NAME, so a site that computed its length differently would show
 * up as a missing key rather than as a silently wrong verdict.
 */
static int k3sm_candidates(const k3sm_cfg_t *c, const char *name,
                           char out[][K3SM_MAX_NAME], int *bad, int max) {
    int n = 0;
    size_t len = strlen(name);

    if (len > 0 && name[len - 1] == '.') {
        if (n < max) {
            /* would-be length: the name minus its trailing dot */
            bad[n] = (len - 1 > (size_t)K3SM_DNS_MAX_NAME_LEN);
            snprintf(out[n], K3SM_MAX_NAME, "%.*s", (int)(len - 1), name);
            n++;
        }
        return n;
    }

    int dots = k3sm_count_dots(name);
    int absolute_first = (dots >= c->ndots);

    if (absolute_first && n < max) {
        /* would-be length: the name itself */
        bad[n] = (len > (size_t)K3SM_DNS_MAX_NAME_LEN);
        snprintf(out[n], K3SM_MAX_NAME, "%s", name);
        n++;
    }
    for (int i = 0; i < c->nsearch && n < max; i++) {
        /* would-be length: name + '.' + search domain */
        bad[n] = (len + 1 + strlen(c->search[i]) > (size_t)K3SM_DNS_MAX_NAME_LEN);
        snprintf(out[n], K3SM_MAX_NAME, "%s.%s", name, c->search[i]);
        n++;
    }
    if (!absolute_first && n < max) {
        /* would-be length: the name itself */
        bad[n] = (len > (size_t)K3SM_DNS_MAX_NAME_LEN);
        snprintf(out[n], K3SM_MAX_NAME, "%s", name);
        n++;
    }
    return n;
}

/* True if name ends in "."suffix or equals suffix (a single trailing dot on
 * either side is ignored). Both are treated case-sensitively — DNS labels from
 * the config and the candidate list are already lowercased/normalized. */
static int k3sm_has_suffix_domain(const char *name, const char *suffix) {
    size_t nl = strlen(name);
    size_t sl = strlen(suffix);
    if (nl > 0 && name[nl - 1] == '.') {
        nl--;
    }
    if (sl > 0 && suffix[sl - 1] == '.') {
        sl--;
    }
    if (sl == 0 || nl < sl) {
        return 0;
    }
    if (nl == sl) {
        return strncmp(name, suffix, sl) == 0;
    }
    return name[nl - sl - 1] == '.' && strncmp(name + nl - sl, suffix, sl) == 0;
}

/*
 * Whether a TRANSIENT failure on this candidate must fail CLOSED (EAI_AGAIN, no
 * host fallthrough) rather than fall through to the host resolver. A candidate
 * is cluster-scoped — fail closed — when it is under the cluster domain or a
 * search domain, OR when it is a bare single-label name (which can never be a
 * real external FQDN, so it is a Service short name). Only a dotted candidate
 * that is NOT under any cluster/search domain (e.g. "github.com") is external:
 * during a resolver blip it may fall through to the host so external DNS stays
 * alive. Deliberate fail-closed-for-cluster / fall-through-for-external trade,
 * mirrored in the Go resolver's LookupHost walk.
 *
 * ACKNOWLEDGED CEILING of that trade: the k8s partial forms "svc.ns" /
 * "svc.ns.svc" are dotted and under no suffix, so they classify EXTERNAL —
 * during a cluster-resolver outage their search-expanded candidates fail
 * closed, but the absolute candidate falls through to the host, whose NXDOMAIN
 * turns a TRANSIENT outage into a definitive not-found for exactly those
 * forms. Suffix-based scoping cannot tell "db.prod" from "github.com"; the
 * bare-label and fully-qualified cluster forms keep the EAI_AGAIN guarantee.
 */
static int k3sm_candidate_fail_closed(const k3sm_cfg_t *c, const char *cand) {
    if (strchr(cand, '.') == NULL) {
        return 1; /* bare label: a cluster short name, never external */
    }
    if (c->domain[0] != '\0' && k3sm_has_suffix_domain(cand, c->domain)) {
        return 1;
    }
    for (int i = 0; i < c->nsearch; i++) {
        if (k3sm_has_suffix_domain(cand, c->search[i])) {
            return 1;
        }
    }
    return 0; /* dotted, not under any cluster/search domain: external */
}

/*
 * Resolve a getaddrinfo service string to a numeric port for the cluster path.
 * A NULL/empty service yields port 0. A purely-numeric service is used
 * verbatim; a numeric service outside the uint16 range is a hard EAI_SERVICE
 * (the system resolver rejects it identically). A non-numeric NAMED service
 * (e.g. "http") is legal getaddrinfo input that the cluster A-record path
 * cannot map to a port — no getservbyname here: Darwin's is not thread-safe
 * and this code runs interposed on arbitrary app threads. It is reported via
 * *named (with *port left 0) so the caller can DEFER the call to the system
 * resolver, which resolves named services natively; only a cluster HIT — where
 * this shim itself would have to fabricate the port — turns a named service
 * into EAI_SERVICE (never a silent port 0, the old atoi behavior). Returns 0
 * on success, an EAI_* code on error.
 */
static int k3sm_parse_port(const char *service, uint16_t *port, int *named) {
    *port = 0;
    *named = 0;
    if (service == NULL || service[0] == '\0') {
        return 0;
    }
    for (const char *p = service; *p != '\0'; p++) {
        if (*p < '0' || *p > '9') {
            *named = 1;
            return 0;
        }
    }
    long v = atol(service);
    if (v < 0 || v > 65535) {
        return EAI_SERVICE;
    }
    *port = (uint16_t)v;
    return 0;
}

/* -------- minimal DNS A query over UDP (TCP refetch on truncation) -------- */

/*
 * Per-candidate attempts on a TRANSIENT failure (timeout, network error,
 * SERVFAIL). Mirrors the Go reference resolver's queryAttempts and the
 * resolv.conf "attempts" default; a definitive NOERROR/NXDOMAIN never retries.
 */
#define K3SM_DNS_ATTEMPTS 2

/*
 * k3sm_query_a outcomes. MISS is definitive — the server answered and the name
 * has nothing (NXDOMAIN, or NOERROR with no A record) — so the caller moves to
 * the next search candidate. TEMPFAIL means the outcome is UNKNOWN (timeout,
 * network error, SERVFAIL, malformed response): the caller retries and, if it
 * keeps failing, must NOT treat the name as absent.
 */
#define K3SM_DNS_HIT 0
#define K3SM_DNS_MISS 1
#define K3SM_DNS_TEMPFAIL (-1)

/*
 * EDNS0 advertised UDP payload size (RFC 6891). The query carries an OPT RR
 * telling the server it may return datagrams up to this size before setting TC,
 * so a modestly large answer set (a Service with several endpoints) survives on
 * UDP instead of forcing a TCP refetch. It MUST NOT exceed the UDP receive
 * buffer (a recv() silently drops an oversized datagram) — a _Static_assert in
 * k3sm_query_a couples the two. This is the single C source of the value; the Go
 * reference exports it as dns.EDNSUDPPayloadSize and TestShimEDNSSizeMatchesC
 * binds the two so they cannot drift.
 */
#define K3SM_EDNS_UDP_SIZE 1232

/* Per-attempt wall-clock timeout (seconds) for a UDP/TCP exchange. */
#define K3SM_DNS_TIMEOUT_SEC 2

/*
 * Encode a dotted name into DNS wire label format. Returns bytes written or -1.
 *
 * INVARIANT: callers pass a name with NO trailing dot. k3sm_candidates strips
 * the one legitimate trailing dot in its absolute branch and k3sm_load_cfg
 * strips it from every search domain at config load, so any empty label reaching
 * the loop below is a defect in the requested name, not punctuation. (A trailing
 * dot would not actually reach the reject: the loop ends when the character
 * after the final dot is the NUL. The invariant is what makes that safe, and
 * k3sm_query_a is the single caller today — keep it if that changes.)
 *
 * That same trailing-dot strip is ALSO how a WHOLLY EMPTY name arrives: the
 * request "." leaves k3sm_candidates' absolute branch as "". The per-label loop
 * below never executes for it, so the zero-length-label reject cannot fire and
 * the function would fall through to emitting a BARE ROOT query — a query for
 * the root zone, not for anything the caller asked about. The explicit
 * empty-name guard at the top of the function is what closes that: it is the
 * degenerate member of the same unencodable class, and the Go reference reaches
 * the identical verdict (Message.Pack returns errNonCanonicalName for the empty
 * name, which queryA maps to a definitive miss with zero wire I/O). The wire
 * differential's unencodable_empty_name case pins both engines on it, verdict
 * AND zero queries.
 */
static int k3sm_encode_name(const char *name, uint8_t *buf, size_t cap) {
    size_t pos = 0;
    const char *p = name;
    /*
     * A WHOLLY EMPTY name is UNENCODABLE — reject before the loop, which would
     * never run for it (see the invariant above). Same -1 channel as the
     * zero-length-label reject: it flows through k3sm_build_query < 0 to
     * k3sm_query_a's K3SM_DNS_MISS boundary, so the empty name is a definitive
     * miss with zero wire I/O instead of a root query.
     */
    if (*p == '\0') {
        return -1;
    }
    while (*p != '\0') {
        const char *dot = strchr(p, '.');
        size_t label = dot ? (size_t)(dot - p) : strlen(p);
        if (label == 0) {
            /*
             * A ZERO-LENGTH label is UNENCODABLE — reject, never skip. The Go
             * reference reaches the same verdict (dnsmessage's pack returns
             * errZeroSegLen, which queryA maps to a definitive miss with zero
             * wire I/O). Skipping it silently collapsed "a..b" to "a.b", putting
             * a query for a DIFFERENT name than the caller asked for on the
             * wire, which can return a HIT belonging to another host. -1 flows
             * through k3sm_build_query < 0 to k3sm_query_a's existing
             * K3SM_DNS_MISS boundary; no new outcome channel is needed.
             */
            return -1;
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

/* Build a DNS A query for fqdn into qbuf. Returns the query length or -1. */
static int k3sm_build_query(const char *fqdn, uint8_t qbuf[512]) {
    /* DNS header: id, flags(RD), qd=1. The deterministic id matches the Go
     * reference resolver's stance (trusted VIP path; and a late duplicate from
     * a retried attempt still validates). */
    uint16_t id = 0x1234;
    memset(qbuf, 0, 12);
    qbuf[0] = (uint8_t)(id >> 8);
    qbuf[1] = (uint8_t)(id & 0xff);
    qbuf[2] = 0x01; /* RD */
    qbuf[5] = 0x01; /* QDCOUNT=1 */
    /* ARCOUNT=1 for the EDNS0 OPT appended below. WITHOUT bumping ARCOUNT the
     * server never parses the OPT and the advertised UDP payload size is a
     * silent no-op — the header count, not the trailing bytes, is what makes
     * EDNS take effect. */
    qbuf[11] = 0x01; /* ARCOUNT=1 */
    int npos = k3sm_encode_name(fqdn, qbuf + 12, 512 - 12);
    if (npos < 0) {
        return -1;
    }
    size_t pos = 12 + (size_t)npos;
    /* question QTYPE/QCLASS (4 bytes) + the OPT pseudo-RR (11 bytes) must fit. */
    if (pos + 4 + 11 > 512) {
        return -1;
    }
    qbuf[pos++] = 0x00;
    qbuf[pos++] = 0x01; /* QTYPE=A */
    qbuf[pos++] = 0x00;
    qbuf[pos++] = 0x01; /* QCLASS=IN */

    /*
     * EDNS0 OPT pseudo-RR in the Additional section (RFC 6891 §6.1.2):
     *   NAME  = 0x00                 (root)
     *   TYPE  = 0x00 0x29            (OPT = 41)
     *   CLASS = K3SM_EDNS_UDP_SIZE   (the requestor's UDP payload size, NOT IN)
     *   TTL   = 0x00000000           (ext-rcode 0, version 0, flags 0 — no DO bit)
     *   RDLEN = 0x0000               (no options)
     */
    qbuf[pos++] = 0x00; /* root NAME */
    qbuf[pos++] = 0x00;
    qbuf[pos++] = 0x29; /* TYPE = OPT (41) */
    qbuf[pos++] = (uint8_t)((K3SM_EDNS_UDP_SIZE >> 8) & 0xff);
    qbuf[pos++] = (uint8_t)(K3SM_EDNS_UDP_SIZE & 0xff); /* CLASS = UDP payload size */
    qbuf[pos++] = 0x00; /* TTL: extended RCODE */
    qbuf[pos++] = 0x00; /* TTL: version */
    qbuf[pos++] = 0x00;
    qbuf[pos++] = 0x00; /* TTL: flags (DO bit clear) */
    qbuf[pos++] = 0x00;
    qbuf[pos++] = 0x00; /* RDLEN = 0 */
    return (int)pos;
}

/* Fill sa from the configured server/port. Returns 0 or -1. */
static int k3sm_server_addr(const k3sm_cfg_t *c, struct sockaddr_in *sa) {
    memset(sa, 0, sizeof(*sa));
    sa->sin_family = AF_INET;
    sa->sin_port = htons((uint16_t)atoi(c->port));
    if (inet_pton(AF_INET, c->server, &sa->sin_addr) != 1) {
        return -1;
    }
    return 0;
}

/*
 * -------- EINTR-safe blocking I/O bounded by a monotonic deadline --------
 *
 * The shim is interposed into ARBITRARY app threads, including ones a profiler
 * (SIGPROF at ~100Hz/thread) or another signal source keeps interrupting. A
 * naive `do {...} while (n < 0 && errno == EINTR)` around recv() re-arms the
 * fixed 2s SO_RCVTIMEO timer on every pass, so under a steady signal the timer
 * is reset before it can fire and an UNREACHABLE resolver hangs the thread
 * FOREVER. Instead we fix an absolute CLOCK_MONOTONIC deadline once per exchange
 * and, on each EINTR retry, re-arm SO_{RCV,SND}TIMEO to only the time that
 * REMAINS — so the exchange is bounded by real wall-clock regardless of how
 * often it is interrupted.
 */

static void k3sm_deadline_from_now(struct timespec *deadline, int timeout_sec) {
    clock_gettime(CLOCK_MONOTONIC, deadline);
    deadline->tv_sec += timeout_sec;
}

/*
 * Arm optname (SO_RCVTIMEO / SO_SNDTIMEO) with the time remaining until
 * deadline. Returns 0 if time remains (socket armed), -1 if the deadline has
 * already passed (the caller treats this as a timeout). A strictly-positive but
 * sub-microsecond remainder is clamped to 1us: a {0,0} timeval means "block
 * forever" for SO_*TIMEO and must never be armed while time still remains.
 */
static int k3sm_arm_remaining(int fd, int optname, const struct timespec *deadline) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long sec = deadline->tv_sec - now.tv_sec;
    long nsec = deadline->tv_nsec - now.tv_nsec;
    if (nsec < 0) {
        sec -= 1;
        nsec += 1000000000L;
    }
    if (sec < 0) {
        return -1; /* deadline passed */
    }
    struct timeval tv;
    tv.tv_sec = sec;
    tv.tv_usec = nsec / 1000;
    if (tv.tv_sec == 0 && tv.tv_usec == 0) {
        tv.tv_usec = 1; /* never arm {0,0} (== block forever) while time remains */
    }
    setsockopt(fd, SOL_SOCKET, optname, &tv, sizeof(tv));
    return 0;
}

/* recv() retried across EINTR, bounded by deadline. Returns bytes, or -1. */
static ssize_t k3sm_recv_deadline(int fd, void *buf, size_t len,
                                  const struct timespec *deadline) {
    for (;;) {
        if (k3sm_arm_remaining(fd, SO_RCVTIMEO, deadline) < 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        ssize_t n = recv(fd, buf, len, 0);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        return n;
    }
}

/* send() retried across EINTR, bounded by deadline. Returns bytes, or -1. */
static ssize_t k3sm_send_deadline(int fd, const void *buf, size_t len,
                                  const struct timespec *deadline) {
    for (;;) {
        if (k3sm_arm_remaining(fd, SO_SNDTIMEO, deadline) < 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        ssize_t n = send(fd, buf, len, 0);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        return n;
    }
}

/* read() retried across EINTR, bounded by deadline. Returns bytes, or -1. */
static ssize_t k3sm_read_deadline(int fd, void *buf, size_t len,
                                  const struct timespec *deadline) {
    for (;;) {
        if (k3sm_arm_remaining(fd, SO_RCVTIMEO, deadline) < 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        ssize_t n = read(fd, buf, len);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        return n;
    }
}

/* write() retried across EINTR, bounded by deadline. Returns bytes, or -1. */
static ssize_t k3sm_write_deadline(int fd, const void *buf, size_t len,
                                   const struct timespec *deadline) {
    for (;;) {
        if (k3sm_arm_remaining(fd, SO_SNDTIMEO, deadline) < 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        ssize_t n = write(fd, buf, len);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        return n;
    }
}

/* One UDP round-trip. Returns response length into rbuf, or -1. */
static ssize_t k3sm_udp_exchange(const k3sm_cfg_t *c, const uint8_t *qbuf,
                                 size_t qlen, uint8_t *rbuf, size_t rcap) {
    struct sockaddr_in sa;
    if (k3sm_server_addr(c, &sa) != 0) {
        return -1;
    }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct timespec deadline;
    k3sm_deadline_from_now(&deadline, K3SM_DNS_TIMEOUT_SEC);

    /* CONNECT the UDP socket to the resolver, then send()/recv() — deliberately
     * NOT sendto()/recvfrom(). Under a pod's Seatbelt profile an UNCONNECTED
     * datagram socket's recvfrom() accepts from any peer and is classified
     * network-inbound, which (allow network-outbound) does NOT grant — the reply
     * is dropped with EPERM and every cluster lookup misses ("no such host"),
     * while the raw UDP query works fine outside the sandbox. A connected socket's
     * recv() belongs to the outbound flow the profile allows, and it hardens the
     * client to accept only the queried resolver's reply. PROBE-VERIFIED on macOS
     * 26.5.1 through the real execshim/Seatbelt path: unconnected recvfrom → EPERM,
     * connected recv → ok, under (allow network-outbound)(allow network-bind).
     *
     * connect() on a DATAGRAM socket only records the default peer in the kernel;
     * it does no handshake and cannot block, so it cannot return EINTR and needs
     * no retry wrapper (unlike the TCP connect() below). */
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    if (k3sm_send_deadline(fd, qbuf, qlen, &deadline) < 0) {
        close(fd);
        return -1;
    }
    ssize_t rn = k3sm_recv_deadline(fd, rbuf, rcap, &deadline);
    close(fd);
    return rn;
}

/*
 * One TCP round-trip with RFC 1035 §4.2.2 length framing — the refetch path
 * when a UDP response has TC set (the answer set did not fit a datagram).
 */
static ssize_t k3sm_tcp_exchange(const k3sm_cfg_t *c, const uint8_t *qbuf,
                                 size_t qlen, uint8_t *rbuf, size_t rcap) {
    struct sockaddr_in sa;
    if (k3sm_server_addr(c, &sa) != 0) {
        return -1;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct timespec deadline;
    k3sm_deadline_from_now(&deadline, K3SM_DNS_TIMEOUT_SEC);

    /* A blocking connect() on a STREAM socket CAN be interrupted by a signal and
     * return EINTR — and it must NOT be re-called: a second connect() on the same
     * fd returns EISCONN/EALREADY (the handshake is already in progress), not a
     * fresh attempt. So on ANY connect() error, EINTR included, we fail this
     * attempt; the caller's TEMPFAIL retry opens a brand-new socket. This is the
     * deliberate opposite of the UDP connect(), which cannot block at all. */
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    uint8_t framed[2 + 512];
    if (qlen > 512) {
        close(fd);
        return -1;
    }
    framed[0] = (uint8_t)(qlen >> 8);
    framed[1] = (uint8_t)(qlen & 0xff);
    memcpy(framed + 2, qbuf, qlen);
    if (k3sm_write_deadline(fd, framed, 2 + qlen, &deadline) != (ssize_t)(2 + qlen)) {
        close(fd);
        return -1;
    }
    uint8_t lb[2];
    size_t got = 0;
    while (got < 2) {
        ssize_t n = k3sm_read_deadline(fd, lb + got, 2 - got, &deadline);
        if (n <= 0) {
            close(fd);
            return -1;
        }
        got += (size_t)n;
    }
    size_t rlen = ((size_t)lb[0] << 8) | lb[1];
    if (rlen > rcap) {
        close(fd);
        return -1;
    }
    got = 0;
    while (got < rlen) {
        ssize_t n = k3sm_read_deadline(fd, rbuf + got, rlen - got, &deadline);
        if (n <= 0) {
            close(fd);
            return -1;
        }
        got += (size_t)n;
    }
    close(fd);
    return (ssize_t)rlen;
}

/*
 * Parse a DNS response for the first A record. Returns K3SM_DNS_HIT (addr4
 * filled), K3SM_DNS_MISS (definitive NXDOMAIN / no A record), or
 * K3SM_DNS_TEMPFAIL (malformed / SERVFAIL and friends). *truncated is set when
 * the response carries TC — the caller refetches over TCP.
 */
static int k3sm_parse_a(const uint8_t *rbuf, ssize_t rn, const uint8_t *qbuf,
                        uint8_t addr4[4], int *truncated) {
    *truncated = 0;
    if (rn < 12) {
        return K3SM_DNS_TEMPFAIL;
    }
    /* Verify id and that it actually is a response (QR bit). */
    if (rbuf[0] != qbuf[0] || rbuf[1] != qbuf[1]) {
        return K3SM_DNS_TEMPFAIL;
    }
    if ((rbuf[2] & 0x80) == 0) {
        return K3SM_DNS_TEMPFAIL;
    }
    if (rbuf[2] & 0x02) { /* TC: answer set did not fit — refetch over TCP */
        *truncated = 1;
        return K3SM_DNS_TEMPFAIL; /* overridden by the caller's TCP refetch */
    }
    /*
     * rcode: NOERROR and NXDOMAIN are DEFINITIVE (the server answered);
     * SERVFAIL and everything else is transient upstream trouble and must
     * never be treated as "no such host" (mirrors the Go lookupCandidate).
     */
    int rcode = rbuf[3] & 0x0f;
    if (rcode == 3) { /* NXDOMAIN */
        return K3SM_DNS_MISS;
    }
    if (rcode != 0) { /* SERVFAIL & friends */
        return K3SM_DNS_TEMPFAIL;
    }
    int qdcount = (rbuf[4] << 8) | rbuf[5];
    int ancount = (rbuf[6] << 8) | rbuf[7];
    if (ancount < 1) {
        return K3SM_DNS_MISS; /* NOERROR, no answers: NODATA */
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
        /* name (label sequence, possibly ending in a compression pointer) */
        while (off < (size_t)rn && rbuf[off] != 0) {
            if ((rbuf[off] & 0xc0) == 0xc0) {
                off += 1; /* second pointer byte consumed below */
                break;
            }
            off += rbuf[off] + 1;
        }
        off += 1;
        if (off + 10 > (size_t)rn) {
            return K3SM_DNS_TEMPFAIL;
        }
        int type = (rbuf[off] << 8) | rbuf[off + 1];
        int rdlen = (rbuf[off + 8] << 8) | rbuf[off + 9];
        off += 10;
        if (off + (size_t)rdlen > (size_t)rn) {
            return K3SM_DNS_TEMPFAIL;
        }
        if (type == 1 && rdlen == 4) { /* A */
            memcpy(addr4, rbuf + off, 4);
            return K3SM_DNS_HIT;
        }
        off += rdlen;
    }
    return K3SM_DNS_MISS;
}

/*
 * Query the configured DNS server for an A record of fqdn: one UDP round-trip,
 * refetched over TCP when the response is truncated. Returns K3SM_DNS_HIT
 * (addr4 filled), K3SM_DNS_MISS (definitive), or K3SM_DNS_TEMPFAIL.
 */
static int k3sm_query_a(const k3sm_cfg_t *c, const char *fqdn,
                        uint8_t addr4[4]) {
    uint8_t qbuf[512];
    int qlen = k3sm_build_query(fqdn, qbuf);
    if (qlen < 0) {
        return K3SM_DNS_MISS; /* unencodable name can never resolve: definitive */
    }

    uint8_t rbuf[1500];
    /* The advertised EDNS UDP payload size must fit this receive buffer: the
     * kernel silently DROPS a datagram larger than the buffer, so a too-small
     * rbuf under a larger K3SM_EDNS_UDP_SIZE would turn a fitting answer into a
     * phantom timeout. Couple the two at compile time. */
    _Static_assert(K3SM_EDNS_UDP_SIZE <= sizeof(rbuf),
                   "EDNS UDP payload size must fit the UDP receive buffer");
    ssize_t rn = k3sm_udp_exchange(c, qbuf, (size_t)qlen, rbuf, sizeof(rbuf));
    if (rn < 0) {
        return K3SM_DNS_TEMPFAIL;
    }
    int truncated = 0;
    int rc = k3sm_parse_a(rbuf, rn, qbuf, addr4, &truncated);
    if (!truncated) {
        return rc;
    }

    /*
     * Truncation refetch over TCP. The answer set did not fit UDP, so it can be
     * far larger than rbuf — up to the 65535-byte ceiling of the 2-byte TCP
     * length prefix (mirrors the Go reference, which sizes the TCP read from
     * that prefix). Allocate the 64 KiB receive buffer on the HEAP: a buffer
     * that large must never be a stack array in an interposed function running
     * on an arbitrary (possibly small-stacked) app thread. free() on EVERY
     * return path below.
     */
    uint8_t *tbuf = (uint8_t *)malloc(65535);
    if (tbuf == NULL) {
        return K3SM_DNS_TEMPFAIL;
    }
    rn = k3sm_tcp_exchange(c, qbuf, (size_t)qlen, tbuf, 65535);
    if (rn < 0) {
        free(tbuf);
        return K3SM_DNS_TEMPFAIL;
    }
    truncated = 0;
    rc = k3sm_parse_a(tbuf, rn, qbuf, addr4, &truncated);
    free(tbuf);
    if (truncated) {
        return K3SM_DNS_TEMPFAIL; /* TC over TCP is malformed */
    }
    return rc;
}

/* Build a one-entry struct addrinfo result for an IPv4 address and port. */
static int k3sm_make_result(const uint8_t addr4[4], uint16_t port,
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
    sin->sin_port = htons(port);

    ai->ai_family = AF_INET;
    /* Emit a CONCRETE socktype. A wildcard hints->ai_socktype of 0 would make
     * this single entry advertise "any" (real getaddrinfo returns one entry PER
     * socktype instead); default to SOCK_STREAM so callers that switch on
     * ai_socktype are not handed a 0. */
    ai->ai_socktype =
        (hints != NULL && hints->ai_socktype != 0) ? hints->ai_socktype : SOCK_STREAM;
    ai->ai_protocol = hints ? hints->ai_protocol : 0;
    ai->ai_addrlen = sizeof(struct sockaddr_in);
    ai->ai_addr = (struct sockaddr *)sin;
    ai->ai_next = NULL;
    *res = ai;
    return 0;
}

/*
 * Print the per-candidate K3SM_DNS_DEBUG verdict line. This is the SINGLE place
 * that wording lives: pkg/dns/differential_integration_test.go's traceRE parses
 * it to read the C engine's verdict, and asserts exactly ONE line per candidate.
 * Every path that finishes a candidate calls this exactly once (callers gate on
 * the debug flag). Note it prints cands[i] as STORED — for an over-long name
 * those are the truncated bytes, a storage fact, not a name anything queried.
 */
static void k3sm_trace_verdict(const k3sm_cfg_t *c, const char *cand, int rc) {
    fprintf(stderr, "k3sm-dns:   query %s @ %s:%s -> %s\n", cand, c->server, c->port,
            rc == K3SM_DNS_HIT    ? "HIT"
            : rc == K3SM_DNS_MISS ? "miss"
                                  : "TEMPFAIL");
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

    /* Diagnostic trace, gated on K3SM_DNS_DEBUG: report exactly what the shim sees
     * (whether K3SM_DNS_SERVER was inherited, the config, and each cluster-query
     * outcome) so an in-pod "no such host" localizes to env-not-seen vs query-miss.
     * Off by default (unset env) — zero overhead and no workload stderr noise. */
    int dbg = getenv("K3SM_DNS_DEBUG") != NULL;
    if (dbg) {
        fprintf(stderr, "k3sm-dns: getaddrinfo node=%s enabled=%d server=%s port=%s domain=%s nsearch=%d ndots=%d\n",
                node ? node : "(null)", cfg.enabled, cfg.server[0] ? cfg.server : "(unset)",
                cfg.port, cfg.domain[0] ? cfg.domain : "(unset)", cfg.nsearch, cfg.ndots);
    }

    /* Not configured, or no hostname to resolve: defer to the system. */
    if (!cfg.enabled || node == NULL || node[0] == '\0') {
        if (dbg) {
            fprintf(stderr, "k3sm-dns: DEFER node=%s (enabled=%d) — K3SM_DNS_SERVER not seen in-pod\n",
                    node ? node : "(null)", cfg.enabled);
        }
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

    /* Resolve the service to a numeric port up front. Only a numeric service
     * out of the uint16 range is a hard EAI_SERVICE here; a NAMED service
     * ("http") sets named_service and the walk below defers to the system
     * resolver wherever it would otherwise have to fabricate the port (see
     * k3sm_parse_port). */
    uint16_t port = 0;
    int named_service = 0;
    int serr = k3sm_parse_port(service, &port, &named_service);
    if (serr != 0) {
        return serr;
    }

    char cands[K3SM_MAX_SEARCH + 1][K3SM_MAX_NAME];
    /* bad[i] marks candidate i as over K3SM_DNS_MAX_NAME_LEN — unencodable, so
     * a definitive miss decided without any wire I/O (see the walk below). */
    int bad[K3SM_MAX_SEARCH + 1] = {0};
    int ncand = k3sm_candidates(&cfg, node, cands, bad, K3SM_MAX_SEARCH + 1);
    /*
     * cluster_tempfail records that a CLUSTER-scoped candidate failed
     * transiently. We keep walking past it (a later EXTERNAL absolute candidate
     * may still fall through to the host and keep external DNS alive across a
     * resolver bounce), and only fail closed with EAI_AGAIN at the end if no
     * external fall-through happened. A transient on an EXTERNAL candidate falls
     * through to the host immediately.
     */
    int cluster_tempfail = 0;
    for (int i = 0; i < ncand; i++) {
        /*
         * An UNENCODABLE candidate (would-be presentation length over
         * K3SM_DNS_MAX_NAME_LEN) is a DEFINITIVE miss with ZERO wire I/O, and it
         * is decided FIRST — before the cluster_tempfail skip, before the
         * named_service defer, and so before k3sm_candidate_fail_closed is ever
         * consulted for this slot. That ordering is the substance, not a style
         * choice: cands[i] holds only the TRUNCATED bytes, so letting them reach
         * either the suffix classification (which decides fail-closed vs
         * external from a name the caller never asked for) or the wire is the
         * same defect twice. The Go reference likewise refuses to encode the
         * name and never classifies it. Falling out of the walk as a miss
         * matches the Go resolver, which advances to the next candidate.
         */
        if (bad[i]) {
            if (dbg) {
                k3sm_trace_verdict(&cfg, cands[i], K3SM_DNS_MISS);
            }
            continue;
        }
        /*
         * Once a cluster-scoped candidate has failed transiently, do NOT try any
         * remaining cluster-scoped candidate: they ask the same unreachable
         * server, and a definitive HIT from a LATER search domain would be a
         * WRONG answer for the short name (the risk TestLookupHostServfail...
         * guards). We keep walking only to reach a still-pending EXTERNAL
         * candidate that may fall through to the host.
         */
        if (cluster_tempfail && k3sm_candidate_fail_closed(&cfg, cands[i])) {
            continue;
        }
        if (named_service && !k3sm_candidate_fail_closed(&cfg, cands[i])) {
            /*
             * EXTERNAL candidate + NAMED service: even a HIT would need a
             * fabricated port, and the system resolver handles both the name
             * and the service natively — defer the whole call without querying.
             * (An up-front EAI_SERVICE here once broke previously-working
             * external lookups like ("api.github.com", "https").)
             */
            if (dbg) {
                fprintf(stderr,
                        "k3sm-dns: DEFER node=%s service=%s — external candidate %s "
                        "with named service\n",
                        node, service, cands[i]);
            }
            return getaddrinfo(node, service, hints, res);
        }
        uint8_t addr4[4];
        int rc = K3SM_DNS_TEMPFAIL;
        for (int attempt = 0; attempt < K3SM_DNS_ATTEMPTS && rc == K3SM_DNS_TEMPFAIL;
             attempt++) {
            rc = k3sm_query_a(&cfg, cands[i], addr4);
        }
        if (dbg) {
            k3sm_trace_verdict(&cfg, cands[i], rc);
        }
        if (rc == K3SM_DNS_HIT) {
            if (named_service) {
                /*
                 * Only CLUSTER-scoped candidates are queried when the service
                 * is named (external ones deferred above), and the A-record
                 * path cannot map "http" to a port for the fabricated
                 * sockaddr — refuse honestly rather than return port 0. Use a
                 * numeric port for cluster names.
                 */
                return EAI_SERVICE;
            }
            return k3sm_make_result(addr4, port, hints, res);
        }
        if (rc == K3SM_DNS_TEMPFAIL) {
            if (k3sm_candidate_fail_closed(&cfg, cands[i])) {
                /*
                 * A CLUSTER-scoped candidate went transient. Deferring to the
                 * host resolver would let it give a confident WRONG answer
                 * (NXDOMAIN) for a cluster name, so we do NOT fall through for
                 * this candidate. Remember it and keep walking — a later
                 * external candidate may still fall through — then fail closed
                 * with EAI_AGAIN below if none does. Mirrors ErrTempFail.
                 */
                cluster_tempfail = 1;
                continue;
            }
            /*
             * An EXTERNAL candidate (dotted, not under the cluster domain) went
             * transient. The cluster resolver is not authoritative for it, so
             * fall through to the host resolver — this keeps github.com and
             * other external names resolving across a resolver blip.
             */
            if (dbg) {
                fprintf(stderr,
                        "k3sm-dns: DEFER node=%s — external candidate %s transient, "
                        "falling through to host\n",
                        node, cands[i]);
            }
            return getaddrinfo(node, service, hints, res);
        }
        /* K3SM_DNS_MISS: definitive — try the next search candidate. */
    }
    if (cluster_tempfail) {
        /*
         * A cluster-scoped candidate failed transiently and nothing resolved or
         * fell through. Report an honest temporary failure; callers retry
         * EAI_AGAIN. This is the fail-closed-for-cluster half of the trade.
         */
        if (dbg) {
            fprintf(stderr,
                    "k3sm-dns: EAI_AGAIN node=%s — cluster resolver unreachable "
                    "(%d candidate(s), %d attempts each)\n",
                    node, ncand, K3SM_DNS_ATTEMPTS);
        }
        return EAI_AGAIN;
    }
    /* Every candidate definitively missed: an external name — fall through so
     * the host resolver can answer it. */
    if (dbg) {
        fprintf(stderr, "k3sm-dns: DEFER node=%s — cluster resolver missed all %d candidate(s)\n", node, ncand);
    }
    return getaddrinfo(node, service, hints, res);
}

/* ==================================================================== */
/* ============ bind() interpose — the per-pod bind discipline ========= */
/* ==================================================================== */

/*
 * WHY THIS EXISTS. macOS has no network namespaces, so every same-node Pod
 * shares one port space: two Pods that both `bind(0.0.0.0:8080)` collide with
 * EADDRINUSE, and whichever binds second crash-loops. k3sm already gives each
 * Pod its own routable /32 (a lo0 alias, ../pkg/podnet), but nothing made a Pod
 * BIND that address — k3sm/docs/DESIGN.md §3/§5b calls this "source identity by
 * bind discipline" and it was never built. This interpose is that discipline:
 * a WILDCARD bind from a pod process is rewritten to the pod's own /32, so two
 * Pods can both hold :8080 and each receives only its own traffic.
 *
 * IT IS A CORRECTNESS DISCIPLINE, NOT A SECURITY BOUNDARY. A pod can still
 * bind another pod's /32 explicitly (a SPECIFIC bind is passed through
 * untouched, by design — see the AF_INET branch), and a pod that sets its own
 * DYLD_INSERT_LIBRARIES, or whose main executable is a platform/hardened binary,
 * never loads this dylib at all (the DYLD-strip ceiling documented at the top of
 * the file). Same-node Pods remain one OS trust domain; enforcement lives
 * elsewhere (a pf anchor, or the `vm` RuntimeClass for untrusted workloads).
 *
 * WHY bind() IS INTERPOSABLE AT ALL, INCLUDING FOR A GO SERVER — the mechanism's
 * whole premise, and the thing that is NOT obvious. Go on darwin does not issue
 * raw `syscall` instructions for socket calls the way it does on Linux: Apple's
 * only supported ABI is libSystem, so runtime/sys_darwin.go imports the libc
 * entry points dynamically —
 *
 *     //go:cgo_import_dynamic libc_bind bind "/usr/lib/libSystem.B.dylib"
 *
 * — and every net.Listen ultimately calls through that normal dynamic binding,
 * which dyld's __DATA,__interpose section can retarget exactly as it does for a
 * C program. This is measured, not assumed: the B215 probe wave observed a real
 * `net.Listen("tcp", ":18082")` land on the rewritten address (`lsof` showing
 * `TCP 100.64.99.7:18082 (LISTEN)` under the shim vs `TCP *:18082` without it).
 * If a future Go release ever emitted raw syscalls here, this interpose would go
 * silently inert for Go pods — the K3SM_BIND_DEBUG trace is how you would find
 * that out.
 *
 * THE DECISION ORDER BELOW IS LOAD-BEARING. Each step exists because a probe
 * cell or a persona critique demanded it, in this order:
 *   1. family + addrlen, BEFORE any sockaddr cast. bind(2) is domain-generic;
 *      an AF_UNIX sockaddr reinterpreted as a sockaddr_in reads a filesystem
 *      path as an address and a port.
 *   2. K3SM_POD_IP. Unset OR set-but-unparseable => full passthrough, the
 *      identical fail-safe polarity (pinned by the acceptance gate): a
 *      malformed value must never surface an error to the workload.
 *   3. wildcard only. A specific bind is the caller's explicit choice.
 *   4. IPV6_V6ONLY for in6addr_any. A socket whose owner asked for v6-only
 *      semantics must not be given a v4-mapped address (B215 P2-v6only).
 *   5. the low-port carve (see K3SM_BIND_MIN_PORT).
 *   6. SO_REUSEADDR before the rewritten bind, unconditionally (B215 P1a).
 */

/*
 * K3SM_BIND_MIN_PORT is the ONE boundary below which a wildcard bind is passed
 * through UNREWRITTEN. pkg/podnet's MinRewritablePort holds the Go-side copy and
 * TestShimMinRewritablePortMatchesC binds the two mechanically.
 *
 * Ports 1..1023 — Darwin INVERTS the rule Linux trains you to expect. A WILDCARD
 * bind needs no privilege at any port, while a SPECIFIC-address bind below 1024
 * returns EACCES for a non-root uid, and k3sm pods never run as root. So
 * rewriting `bind(0.0.0.0:80)` would convert a working nginx-shaped workload into
 * a permission error — a regression, not a discipline. B215 cell P1c measured
 * exactly this and pinned the cause to the uid (the same specific bind succeeds
 * as root and fails unconfined-unprivileged, which clears both Seatbelt and this
 * interposer). Low-port pods therefore keep today's shared wildcard behaviour;
 * that is a NAMED residual, not an oversight.
 *
 * Port 0 — ALSO passed through, and deliberately so. An ephemeral wildcard bind
 * is a CLIENT socket about to connect() somewhere this interpose cannot see;
 * pinning its source to the pod /32 would break an en0-routed external dial,
 * which is precisely the hazard the destination-scoped connect() rung (backlog
 * B218) exists to handle and which bind() alone cannot evaluate. The B215 probe
 * artifact rewrote port 0, but no probe cell measured that case, so the shipped
 * shim declines it rather than inherit an unmeasured behaviour.
 */
#define K3SM_BIND_MIN_PORT 1024

typedef struct {
    int enabled;                    /* K3SM_POD_IP parsed as an IPv4 literal */
    int debug;                      /* K3SM_BIND_DEBUG set and not "0"/"" */
    struct in_addr podip;           /* network byte order, ready to memcpy */
    char podip_s[INET_ADDRSTRLEN];  /* presentation form, for the trace only */
} k3sm_bind_cfg_t;

/*
 * The bind config is read ONCE per process, under pthread_once. bind() is
 * interposed onto arbitrary application threads (a Go program binds from
 * whichever goroutine's thread runs the listener), so a plain "initialized?"
 * flag would be a data race on first use; and unlike the DNS config there is
 * nothing per-call to vary, so caching costs nothing. getenv() is read only
 * inside the once-initializer, before any concurrent bind can observe the
 * result.
 */
static k3sm_bind_cfg_t k3sm_bind_cfg;
static pthread_once_t k3sm_bind_once = PTHREAD_ONCE_INIT;

static void k3sm_bind_trace(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/*
 * The K3SM_BIND_DEBUG stderr trace, mirroring K3SM_DNS_DEBUG. This is the ONLY
 * field diagnostic for the two silent-by-construction escapes (a v6-only socket
 * and a pod whose binary never loaded the dylib), so an unexplained EADDRINUSE
 * localizes to "the shim never ran" vs "the shim declined this bind".
 *
 * WORDING IS COUPLED: hack/acceptance/B216.sh parses these lines to read which
 * branch fired, the same private-log coupling the DNS differential carries.
 * Reword a line and update the gate in the same change.
 */
static void k3sm_bind_trace(const char *fmt, ...) {
    if (!k3sm_bind_cfg.debug) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "k3sm-bind: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    fflush(stderr);
}

static void k3sm_bind_cfg_init(void) {
    memset(&k3sm_bind_cfg, 0, sizeof k3sm_bind_cfg);

    const char *dbg = getenv("K3SM_BIND_DEBUG");
    k3sm_bind_cfg.debug = (dbg != NULL && dbg[0] != '\0' && strcmp(dbg, "0") != 0);

    const char *ip = getenv("K3SM_POD_IP");
    if (ip == NULL || ip[0] == '\0') {
        k3sm_bind_trace("disabled: K3SM_POD_IP unset (passthrough)");
        return;
    }
    if (inet_pton(AF_INET, ip, &k3sm_bind_cfg.podip) != 1) {
        /*
         * Set-but-unparseable behaves EXACTLY like unset: full passthrough, no
         * error surfaced to the workload. Failing the bind here would turn a
         * malformed env value into an unbootable pod, and the discipline is not
         * worth that; pkg/podnet's BindDisciplineEnv is the encoder that makes a
         * malformed value not happen in the first place.
         */
        k3sm_bind_trace("disabled: K3SM_POD_IP=%s unparseable (passthrough)", ip);
        return;
    }
    snprintf(k3sm_bind_cfg.podip_s, sizeof k3sm_bind_cfg.podip_s, "%s", ip);
    k3sm_bind_cfg.enabled = 1;
    k3sm_bind_trace("enabled: pod ip %s (wildcard binds >= %d rewritten)",
                    k3sm_bind_cfg.podip_s, K3SM_BIND_MIN_PORT);
}

/*
 * SO_REUSEADDR on every socket this shim rewrites — UNCONDITIONAL, and set
 * BEFORE the real bind. B215 cell P1a is the grounds and it is not a nicety:
 * without it the rewritten bind returns EADDRINUSE against a standing wildcard
 * listener (the node's svclb and the Service proxy both hold one) in every
 * shape and both orders, AND against the socket's own TIME_WAIT after serving a
 * single connection — an ordinary Pod restart. Go sets SO_REUSEADDR itself on
 * stream listeners, but that is a Go fact: a C, JVM, or Python pod sets none,
 * and Go's own net.ListenPacket (UDP) sets none either, where the omission is
 * sharper still (a pod-first UDP bind would otherwise BLOCK the node's wildcard
 * proxy listener). It is applied only on the rewrite path, so no passed-through
 * bind changes behaviour.
 *
 * A setsockopt failure is traced, not fatal: the subsequent bind is still the
 * caller's real bind and reports the real errno.
 */
static void k3sm_bind_set_reuseaddr(int fd) {
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0) {
        k3sm_bind_trace("fd=%d SO_REUSEADDR failed errno=%d — the rewritten bind may hit EADDRINUSE",
                        fd, errno);
        return;
    }
    k3sm_bind_trace("fd=%d SO_REUSEADDR set", fd);
}

/*
 * The interposed bind(). Every path returns the REAL bind()'s result, and no
 * libc call is made between that bind() and the return, so the caller sees the
 * kernel's errno untouched (a trace emitted after a failed bind would clobber
 * it — the traces below are therefore all emitted BEFORE the call).
 */
int k3sm_bind(int fd, const struct sockaddr *addr, socklen_t len) {
    pthread_once(&k3sm_bind_once, k3sm_bind_cfg_init);

    if (addr == NULL) {
        /* A NULL sockaddr is the kernel's EFAULT/EINVAL to report, not ours. */
        return bind(fd, addr, len);
    }

    /*
     * STEP 1 — family + addrlen, before any cast. bind(2) is domain-generic:
     * AF_UNIX, AF_SYSTEM, AF_NDRV and anything else must reach the kernel
     * byte-identical, and a short sockaddr for a family we DO handle is the
     * kernel's EINVAL to raise, not an invitation to read past the buffer.
     */
    int rewritable_shape =
        (addr->sa_family == AF_INET && len >= (socklen_t)sizeof(struct sockaddr_in)) ||
        (addr->sa_family == AF_INET6 && len >= (socklen_t)sizeof(struct sockaddr_in6));
    if (!rewritable_shape) {
        k3sm_bind_trace("fd=%d family=%d len=%u -> passthrough (not a rewritable shape)",
                        fd, (int)addr->sa_family, (unsigned)len);
        return bind(fd, addr, len);
    }

    /* STEP 2 — the pod identity. Unset or unparseable => transparent passthrough. */
    if (!k3sm_bind_cfg.enabled) {
        k3sm_bind_trace("fd=%d -> passthrough (shim disabled)", fd);
        return bind(fd, addr, len);
    }

    if (addr->sa_family == AF_INET) {
        struct sockaddr_in in;
        memcpy(&in, addr, sizeof in);

        /* STEP 3 — wildcard only. A specific bind is the caller's explicit
         * choice and is preserved untouched, INCLUDING another pod's /32: this
         * shim is a discipline, not an enforcement boundary. */
        if (in.sin_addr.s_addr != htonl(INADDR_ANY)) {
            char buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &in.sin_addr, buf, sizeof buf);
            k3sm_bind_trace("fd=%d AF_INET specific %s:%u -> passthrough", fd, buf,
                            (unsigned)ntohs(in.sin_port));
            return bind(fd, addr, len);
        }

        /* STEP 5 — the low-port carve (see K3SM_BIND_MIN_PORT). */
        unsigned port = (unsigned)ntohs(in.sin_port);
        if (port < K3SM_BIND_MIN_PORT) {
            k3sm_bind_trace("fd=%d AF_INET wildcard :%u -> PASSTHROUGH-LOWPORT", fd, port);
            return bind(fd, addr, len);
        }

        in.sin_addr = k3sm_bind_cfg.podip;
        /* STEP 6 — SO_REUSEADDR first, then the rewritten bind. */
        k3sm_bind_set_reuseaddr(fd);
        k3sm_bind_trace("fd=%d AF_INET wildcard :%u -> REWRITE %s:%u", fd, port,
                        k3sm_bind_cfg.podip_s, port);
        return bind(fd, (const struct sockaddr *)&in, (socklen_t)sizeof in);
    }

    /* AF_INET6. Go's net.Listen("tcp", ":8080") produces exactly this socket —
     * an in6addr_any dual-stack listener — so the v6 arm is the COMMON case for
     * a Go workload, not an exotic one. */
    struct sockaddr_in6 in6;
    memcpy(&in6, addr, sizeof in6);

    if (!IN6_IS_ADDR_UNSPECIFIED(&in6.sin6_addr)) {
        char buf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &in6.sin6_addr, buf, sizeof buf);
        k3sm_bind_trace("fd=%d AF_INET6 specific [%s]:%u -> passthrough", fd, buf,
                        (unsigned)ntohs(in6.sin6_port));
        return bind(fd, addr, len);
    }

    /*
     * STEP 4 — IPV6_V6ONLY. A v6-only socket is left ALONE: its owner asked for
     * v6-only semantics, a v4-mapped address is not even bindable on it, and
     * silently black-holing such a listener would be strictly worse than the
     * loud EADDRINUSE this shim exists to remove. Go's "tcp6" network sets
     * IPV6_V6ONLY=1, as may any C/JVM server (B215 P2-v6only). A getsockopt
     * failure is treated as "do not touch it" — the fail-safe direction.
     */
    int v6only = -1;
    socklen_t olen = (socklen_t)sizeof v6only;
    if (getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, &olen) != 0) {
        k3sm_bind_trace("fd=%d AF_INET6 getsockopt(IPV6_V6ONLY) errno=%d -> passthrough",
                        fd, errno);
        return bind(fd, addr, len);
    }
    if (v6only != 0) {
        k3sm_bind_trace("fd=%d AF_INET6 in6addr_any but IPV6_V6ONLY=1 -> PASSTHROUGH-V6ONLY", fd);
        return bind(fd, addr, len);
    }

    unsigned port6 = (unsigned)ntohs(in6.sin6_port);
    if (port6 < K3SM_BIND_MIN_PORT) {
        k3sm_bind_trace("fd=%d AF_INET6 wildcard :%u -> PASSTHROUGH-LOWPORT", fd, port6);
        return bind(fd, addr, len);
    }

    /*
     * Rewrite to the v4-mapped form ::ffff:<podip>. B215 P2 proved this binds on
     * a dual-stack socket and that v4 traffic to the alias arrives, while
     * 127.0.0.1 and [::1] are refused — the rewrite genuinely narrows the
     * socket rather than relabelling it — so the fallback path the plan held in
     * reserve (separate v4 handling) is not needed.
     */
    memset(&in6.sin6_addr, 0, sizeof in6.sin6_addr);
    in6.sin6_addr.s6_addr[10] = 0xff;
    in6.sin6_addr.s6_addr[11] = 0xff;
    memcpy(&in6.sin6_addr.s6_addr[12], &k3sm_bind_cfg.podip, sizeof k3sm_bind_cfg.podip);
    k3sm_bind_set_reuseaddr(fd);
    k3sm_bind_trace("fd=%d AF_INET6 wildcard :%u (v6only=0) -> REWRITE [::ffff:%s]:%u", fd, port6,
                    k3sm_bind_cfg.podip_s, port6);
    return bind(fd, (const struct sockaddr *)&in6, (socklen_t)sizeof in6);
}
