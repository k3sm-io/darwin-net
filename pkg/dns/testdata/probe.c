/*
 * probe.c — a plain getaddrinfo() caller used by the shim integration test.
 *
 * With the k3sm getaddrinfo DYLD shim injected via DYLD_INSERT_LIBRARIES (and
 * the K3SM_DNS_* environment set), this resolves cluster names through CoreDNS;
 * without it, the same call goes through the system resolver. It prints one
 * resolved IPv4 address per line so the test can assert the shim path worked.
 */
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: probe <name>\n");
        return 2;
    }
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(argv[1], NULL, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
        return 1;
    }
    char buf[64];
    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
        if (p->ai_family != AF_INET) {
            continue;
        }
        struct sockaddr_in *sin = (struct sockaddr_in *)p->ai_addr;
        inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
        printf("%s\n", buf);
    }
    freeaddrinfo(res);
    return 0;
}
