/*
 * probe.c — a plain getaddrinfo() caller used by the shim integration test.
 *
 * With the k3sm getaddrinfo DYLD shim injected via DYLD_INSERT_LIBRARIES (and
 * the K3SM_DNS_* environment set), this resolves cluster names through CoreDNS;
 * without it, the same call goes through the system resolver. It prints one
 * resolved address per line — "IP" with no service argument, "IP:port" with
 * one — so the test can assert both the shim path and the port the shim (or
 * the system resolver, for named services) filled in. On failure it prints the
 * symbolic EAI_* name for the codes the tests assert on, so assertions don't
 * depend on gai_strerror wording or numeric values.
 */
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

static const char *eai_name(int rc) {
    switch (rc) {
    case EAI_SERVICE:
        return "EAI_SERVICE";
    case EAI_AGAIN:
        return "EAI_AGAIN";
    case EAI_NONAME:
        return "EAI_NONAME";
    default:
        return "EAI_OTHER";
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: probe <name> [service]\n");
        return 2;
    }
    const char *service = argc > 2 ? argv[2] : NULL;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(argv[1], service, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo: %s %s\n", eai_name(rc), gai_strerror(rc));
        return 1;
    }
    char buf[64];
    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
        if (p->ai_family != AF_INET) {
            continue;
        }
        struct sockaddr_in *sin = (struct sockaddr_in *)p->ai_addr;
        inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
        if (service != NULL) {
            printf("%s:%d\n", buf, (int)ntohs(sin->sin_port));
        } else {
            printf("%s\n", buf);
        }
    }
    freeaddrinfo(res);
    return 0;
}
