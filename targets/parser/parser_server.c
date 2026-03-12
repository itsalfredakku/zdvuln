/*
 * Network Protocol Parser - Vulnerable TCP Server
 *
 * Bug: parses a length-prefixed protocol without validating the length field.
 * A malicious client can send a length larger than the buffer, causing overflow.
 *
 * Protocol format:
 *   [TYPE:1][LENGTH:2][DATA:LENGTH]
 *
 * Study:
 *   - How do real protocol parsers handle untrusted length fields?
 *   - What happens when LENGTH > buffer size?
 *   - How would you fuzz this server?
 *
 * Run: zig cc -o parser-server parser_server.c
 *      ./parser-server 9999
 *      echo -ne '\x01\xff\x00AAAA...' | nc localhost 9999
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PARSE_BUFFER_SIZE 128
#define MAX_PACKET_SIZE   1024

/* Packet types */
#define PKT_ECHO    0x01
#define PKT_AUTH    0x02
#define PKT_DATA    0x03

struct packet_header {
    uint8_t  type;
    uint16_t length;  /* claimed data length */
} __attribute__((packed));

void handle_packet(const char *raw, ssize_t raw_len) {
    char parse_buf[PARSE_BUFFER_SIZE];

    if (raw_len < (ssize_t)sizeof(struct packet_header)) {
        printf("[-] Packet too short\n");
        return;
    }

    struct packet_header hdr;
    memcpy(&hdr, raw, sizeof(hdr));

    printf("[*] Packet type:   0x%02x\n", hdr.type);
    printf("[*] Claimed length: %u\n", hdr.length);
    printf("[*] Actual data:    %zd bytes\n", raw_len - (ssize_t)sizeof(hdr));

    const char *data = raw + sizeof(hdr);

    /*
     * BUG: trusts the length field from the packet header.
     * If hdr.length > PARSE_BUFFER_SIZE, this overflows parse_buf.
     * A real parser must validate: hdr.length <= sizeof(parse_buf)
     *                          AND hdr.length <= (raw_len - sizeof(hdr))
     */
    memcpy(parse_buf, data, hdr.length);  /* VULNERABLE */
    parse_buf[hdr.length] = '\0';

    switch (hdr.type) {
        case PKT_ECHO:
            printf("[*] ECHO: %s\n", parse_buf);
            break;
        case PKT_AUTH:
            printf("[*] AUTH request: %s\n", parse_buf);
            break;
        case PKT_DATA:
            printf("[*] DATA: %zu bytes\n", strlen(parse_buf));
            break;
        default:
            printf("[-] Unknown packet type.\n");
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }

    int port = atoi(argv[1]);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Invalid port\n");
        return 1;
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK), /* localhost only */
        .sin_port = htons((uint16_t)port)
    };

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 1) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    printf("=== Vulnerable Parser Server ===\n");
    printf("[*] Listening on 127.0.0.1:%d\n", port);
    printf("[*] Protocol: [TYPE:1][LENGTH:2][DATA:LENGTH]\n\n");

    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) { perror("accept"); continue; }

        char recv_buf[MAX_PACKET_SIZE];
        ssize_t n = read(client_fd, recv_buf, sizeof(recv_buf));
        if (n > 0) {
            handle_packet(recv_buf, n);
        }

        close(client_fd);
    }

    close(server_fd);
    return 0;
}
