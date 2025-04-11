#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "network.h"
#include <errno.h>
#include <unistd.h>

// Declare optarg and optind explicitly if needed
extern char *optarg;
extern int optind;

#define PORT 5432

void usage(char *thisf) {
	char *version = "V0.2 by Josjuar Lister 2025";
	char *name = "nchat";
	char *usage = 
		"%s - %s\n"
		"Minimalistic Peer-2-Peer chat for the terminal, with onion support\n\n"
		"Usage: %s <Options> [Endpoint/relay port]\n"
		"\t-p [port]\tlisten on/connect to peer on a non default port (default: 5432)\n"
		"\t-l\t\tListen for incoming connections\n"
		"\t-k\t\tKeep listening after connections close\n"
		"\t-t [addr]\tConnect via socks5 proxy to the specified onion address\n"
		"\t-x [ip]\tSet a non default value for the socks5 proxy IP (default: 127.0.0.1)\n"
		"\t-z [port]\tSet a non default value for the socks5 proxy port (default: 9050)\n"
		"\t-h\t\tShow this help message\n"
		;
	printf(usage, name, version, thisf);
}

int main(int argc, char** argv) {
	int opt;
	int listen = 0, keep_listening = 0;
	char onion_addr[62] = {0};
	int port = PORT;
	char *socks5_ip = "127.0.0.1";
	int socks5_port = 9050;
	//Parse CLI paramaters

    while ((opt = getopt(argc, argv, "hlkt:p:x:z:")) != -1)
        switch((char)opt) {
			case 'h':
				//help
				usage(argv[0]);
				return 0;
			case 'l':
				listen = 1;
				break;
			case 'k':
				keep_listening = 1;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 't':
				for (int i = 0; i < 62; i++) {
					if (optarg[i] == '\0') {
						errno = EINVAL;
						perror("Invalid onion address");
						return (long int)"🤌🏻";
					}
					onion_addr[i] = optarg[i];
				}
				break;
			case 'x':
				socks5_ip = optarg;
				break;
			case 'z':
				socks5_port = atoi(optarg);
				break;
			default:
				usage(argv[0]);
				return 0;
    }
	argc -= optind;
	argv += optind;
	if (onion_addr[0] != '\0') {
		return tor_chat_connect(onion_addr, port, socks5_ip, socks5_port);
	}
	if (listen) {
		start:
		chat_listen(port, keep_listening);
		usleep(10000);
		if (keep_listening) goto start;
	} else if (argv[0] != NULL){
		return chat_connect(argv[0], port);}
	else {
		errno = EINVAL;
		perror("No Endpoint specified");
		return (long int)"🤌🏻";
	}
}
