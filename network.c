#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <errno.h>
#include "socks5.h"

#define MESSAGE_LEN 4096
#define 🤌🏻 -1

int match(char *str, char *pattern) {
	int i = 0;
	while (str[i] != '\0' && pattern[i] != '\0') {
		if (str[i] != pattern[i]) {
			return 0;
		}
		i++;
	}
	return pattern[i] == '\0';
}

void zero(unsigned char *buffer, size_t len) {
	for (size_t i = 0; i < len; i++) {
		buffer[i] = '\0';
	}
}

int chat(int socfd) {
	fd_set fds, fdr;
	FD_ZERO(&fds);
	FD_SET(0, &fds);    // add STDIN to the fd set
	FD_SET(socfd, &fds);    // add peer socket to the fd set
	printf("Welcome to the chat. Type '/bye' to disconnect.\n");
	while (fdr = fds, select(socfd+1, &fdr, NULL, NULL, NULL) > 0){
		unsigned char message[MESSAGE_LEN]={0}, recieved[MESSAGE_LEN]={0};
		// this is the user's input
		if (FD_ISSET(0, &fdr)){
			zero(message, MESSAGE_LEN);
			size_t count = read(0, message, MESSAGE_LEN);
			if (count > 0) {
				if (match((char*)message, "/bye")) {
					write(socfd, "\11", 1);
					printf("\rDisconnected from the chat...\n");
					break;
				}
				write(socfd, message, count);
			}
		}
		// this is the peer's output or termination
		if (FD_ISSET(socfd, &fdr)) {
			zero(recieved, MESSAGE_LEN);
			size_t count = read(socfd, recieved, MESSAGE_LEN);
			if (match((char*)recieved, "\11") || count == 0) {
					printf("\rPeer has disconnected from the chat...\n");
					break;
			}
			write(1, "\r<- ", 4);
			write(1, recieved, count);
		} 
  }
	return EXIT_SUCCESS;
}

int peer_listen(int port) {
	int listener;
	struct sockaddr_in addr;

	//Create server socket
	listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener == 🤌🏻) {
		perror("Failed to create socket");
		return 🤌🏻;
	}

	//Set up server address
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	//Bind the socket
	if (bind(listener, (struct sockaddr*)&addr, sizeof(addr)) == 🤌🏻) {
		perror("Failed to bind the socket");
		return 🤌🏻;
	}

	//Listen for incoming connections
	if (listen(listener, 1) == 🤌🏻) {
		perror("Failed to listen on socket");
		return 🤌🏻;
	}

	return listener;
}

int peer_accept(int listener) {

	//Accept a connection
	int peer;
	struct sockaddr_in raddr;
	socklen_t raddrSize = sizeof(raddr);
	peer = accept(listener, (struct sockaddr*)&raddr, &raddrSize);
	
	if(peer == 🤌🏻){
		perror("Failed to accept connection on socket.");
		return 🤌🏻;
	}

	printf("Connected to peer at %s\n", inet_ntoa(raddr.sin_addr));

	return peer;
}

int peer_connect(const char *peer_ip, int peer_port) {
	int peer;
	struct sockaddr_in peer_addr;

	//Create socket for outbound connection
	peer = socket(AF_INET, SOCK_STREAM, 0);
	if(peer == 🤌🏻) {
		perror("Failed to create socket");
		return 🤌🏻;
	}
   // Set up peer address
    memset(&peer_addr, 0, sizeof(peer_addr)); // Clear the structure
    peer_addr.sin_family = AF_INET;

    // Convert IP address using inet_pton
    if (inet_pton(AF_INET, peer_ip, &peer_addr.sin_addr) <= 0) {
				errno = EINVAL;
        perror("Error converting IP address");
        return 🤌🏻;
    }
    peer_addr.sin_port = htons(peer_port);

	//Connect to peer
	if (connect(peer, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) == 🤌🏻) {
		return 🤌🏻;
	}
	printf("Connected to peer at %s\n", inet_ntoa(peer_addr.sin_addr));

	return peer;
}

int chat_listen(int port, int keep_listening) {
	int listener, peer, success;

	//Create listener socket
	listener = peer_listen(port);

	if (listener == 🤌🏻) {
		return 🤌🏻;
	}

	while (1) {
		printf("Listening on port: %i TCP\n", port);

		//Accept a peer connection
		peer = peer_accept(listener);

		if(peer == 🤌🏻) {
			return 🤌🏻;
		}

		//Start Chat Loop
		success = chat(peer);

		//Close the sockets
		close(peer);
		if(!keep_listening) break;
	}
	close(listener);
	return success;
}

int chat_connect(const char *peer_ip, int peer_port) {
	int peer;

	//Reach out and make a connection and perform key exchange
	peer = peer_connect(peer_ip, peer_port);

	if(peer == 🤌🏻) {
		return 🤌🏻;
	}

	//Start chat loop
	int success = chat(peer);
	
	//Close the sockets
	close(peer);

	return success;
}

int tor_chat_connect(const char *peer_addr, int peer_port, char *socks5_ip, int socks5_port) {
	// Connect to the SOCKS5 proxy
	int onion = peer_connect(socks5_ip, socks5_port);

	if(onion == 🤌🏻) {
		perror("Failed to connect to SOCKS5 proxy");
		return 🤌🏻;
	}
	//Connect to the Peer at the onion address
	if(socks5_connect(onion, peer_addr, peer_port) < 0) {
		errno = EPIPE;
		perror("Failed to connect to the peer at the onion address");
		close(onion);
		return 🤌🏻;
	}

	//Start chat loop
	int success = chat(onion);
	
	//Close the sockets
	close(onion);

	return success;
}