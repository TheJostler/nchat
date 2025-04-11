#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define SOCKS5_VERSION 0x05
#define SOCKS5_AUTH_NO_METHODS 0x00
#define SOCKS5_CONNECT_CMD 0x01
#define SOCKS5_ATYP_DOMAINNAME 0x03
#define SOCKS5_REPLY_SUCCESS 0x00

int socks5_connect(int sockfd, const char *hostname, uint16_t port) {
    unsigned char buf[512];

    // SOCKS5 handshake: version, number of methods, no-authentication method
    unsigned char handshake[] = {SOCKS5_VERSION, 1, SOCKS5_AUTH_NO_METHODS};
    if (write(sockfd, handshake, sizeof(handshake)) != (ssize_t)sizeof(handshake)) {
        perror("Error sending handshake");
        return -1;
    }

    // Expect: version, chosen method
    if (read(sockfd, buf, 2) != 2 || buf[1] != SOCKS5_AUTH_NO_METHODS) {
        fprintf(stderr, "SOCKS5 proxy does not support no-auth method\n");
        return -2;
    }

    // Build connect request
    size_t hostname_len = strlen(hostname);
    size_t req_len = 4 + 1 + hostname_len + 2;
    buf[0] = SOCKS5_VERSION;        // version
    buf[1] = SOCKS5_CONNECT_CMD;    // command: connect
    buf[2] = 0x00;                  // reserved
    buf[3] = SOCKS5_ATYP_DOMAINNAME; // address type: domain name
    buf[4] = (unsigned char)hostname_len;
    memcpy(&buf[5], hostname, hostname_len);
    buf[5 + hostname_len] = (port >> 8) & 0xFF;
    buf[6 + hostname_len] = port & 0xFF;

    if (write(sockfd, buf, req_len) != (ssize_t)req_len) {
        perror("Error sending connect request");
        return -3;
    }

    // Receive the SOCKS5 reply (at least 10 bytes expected)
    ssize_t r = read(sockfd, buf, sizeof(buf));
    if (r < 10) {
      perror("SOCKS5 reply too short\n");
      return -4;
    }
    if (r < 2 || buf[1] != SOCKS5_REPLY_SUCCESS) {
        fprintf(stderr, "SOCKS5 connect failed with code 0x%02X\n", buf[1]);
        return -4;
    }

    // Connection established
    printf("SOCKS5 connection established to %s:%d\n", hostname, port);
    return 0;
}