#ifndef NETWORK_H
#define NETWORK_H

#include <sodium.h>

int chat_listen(int port, int keep_listening);
int chat_connect(const char *peer_ip, int peer_port);
int chat_relay(int listen_left_port, const char *peer_right_ip, int peer_right_port);

#endif
