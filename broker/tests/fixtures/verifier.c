/* Disposable static verifier: no real endpoint or credentials. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
int main(int argc, char **argv) {
    if (argc != 7 || strcmp(argv[1], "verify") || strcmp(argv[2], "--baseline") ||
        strcmp(argv[3], "/baseline.json") || strcmp(argv[4], "--format") || strcmp(argv[5], "json")) return 90;
    if (getenv("HOME") || getenv("PATH") || access("/etc/passwd", F_OK) == 0 ||
        access("/home/ubuntu", F_OK) == 0 || open("/baseline.json", O_WRONLY) >= 0 ||
        open("/verifier", O_WRONLY) >= 0) return 91;
    struct stat binary_stat, baseline_stat;
    if (stat("/verifier", &binary_stat) || stat("/baseline.json", &baseline_stat) ||
        (binary_stat.st_mode & 07777) != 0500 ||
        (baseline_stat.st_mode & 07777) != 0400 ||
        chmod("/verifier", 0700) == 0 || chmod("/baseline.json", 0600) == 0) return 94;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(8080)};
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) return 92;
    close(sock);
    FILE *f = fopen("/baseline.json", "r");
    if (!f) return 93;
    int mode = fgetc(f); fclose(f);
    if (mode == 't') { if (fork() == 0) { setsid(); for (;;) pause(); } for (;;) pause(); }
    if (mode == 'o' || mode == 'e') { for (int i=0;i<70000;i++) fputc('x', mode == 'o' ? stdout : stderr); return 0; }
    if (mode == 'x') { puts("failure"); return 7; }
    if (mode == 'b') { puts("invalid json"); return 0; }
    if (mode == 'd') { puts("{\"match\":false,\"risk\":\"LOW\",\"score\":5,\"changes\":[{}]}"); return 1; }
    puts("{\"match\":true,\"risk\":\"NONE\",\"score\":0,\"changes\":null}");
    return 0;
}
