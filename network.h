#ifndef NETWORK_H
#define NETWORK_H

int chat_listen(int port, int keep_listening);
int chat_connect(const char *peer_ip, int peer_port);
int tor_chat_connect(const char *peer_addr, int peer_port, char *socks5_ip, int socks5_port);

#endif
