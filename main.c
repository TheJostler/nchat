#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "network.h"
#include "crypto.h"

#define PORT 4322

void usage(char *thisf) {
	char *version = "V0.1 by Josjuar Lister 2023";
	char *name = "nchat";
	char *usage = 
		"%s - %s\n"
		"Minimalistic Encrypted Peer-2-Peer chat for the terminal\n\n"
		"Usage: %s <Options> [Endpoint/relay port]\n"
		"\t-p [port]\tlisten on/connect to port\n"
		"\t-r [addr]\tStart as a relay and forward all traffic to the specified address\n"
		"\t-l\t\tListen on defailt port\n"
		"\t-k\t\tKeep listening after connections close\n"
		;
	printf(usage, name, version, thisf);
}

int main(int argc, char** argv) {
	int opt;
	int listen = 0, keep_listening = 0;
	int port = PORT;
	int relay= 0;
	char *relay_addr;
	//Parse CLI paramaters

    while ((opt = getopt(argc, argv, "hltkr:p:")) != -1)
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
			case 't':
				return test_kx();
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'r':
				relay = 1;
				relay_addr = optarg;
				break;
			default:
				usage(argv[0]);
				return 0;
    }
	argc -= optind;
	argv += optind;

	if (listen) {
		for (int p = 0; ;p++) {
			chat_listen(port+p, keep_listening);
			usleep(10000);
			if (!keep_listening)
				break;
		}
	} else if(relay) {
		int relay_port;
		if (argv[0] == NULL) {
			relay_port = PORT;
		} else {
			relay_port = atoi(argv[0]);
		}
		return chat_relay(port, relay_addr, relay_port);
	} else if (argv[0] != NULL){
		return chat_connect(argv[0], port);}
	else {
		perror("No Endpoint specified.");
		return (long int)"🤌🏻";
	}
}
