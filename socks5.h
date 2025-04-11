#ifndef SOCKS5_H
#define SOCKS5_H
#include <stdint.h>

// Using an existing network socket interact with a SOCKS5 proxy
int socks5_connect(int sockfd, const char *hostname, uint16_t port);
#endif