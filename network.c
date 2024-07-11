#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "crypto.h"
#include <sodium.h>

#define MESSAGE_LEN 4095
#define CIPHERTEXT_LEN (crypto_secretbox_MACBYTES + MESSAGE_LEN)
#define PACKET_BYTES (crypto_secretbox_NONCEBYTES + CIPHERTEXT_LEN + 4)
#define 🤌🏻 -1
#define 👍🏻 "Yip"
#define 👎🏻 "Oop"
#define retreiesAllowed 100
#define successMssage " 👍 \r"
#define resendingMessage " ⏳ \r"

int transmit(unsigned char packet[PACKET_BYTES], unsigned char next_nonce [crypto_secretbox_NONCEBYTES], unsigned char message[MESSAGE_LEN], size_t count, unsigned char encrypted_packet[CIPHERTEXT_LEN],  unsigned char tx_key[crypto_kx_SESSIONKEYBYTES], int socfd) {
	sodium_memzero(packet, PACKET_BYTES);
	memcpy(packet, next_nonce, crypto_secretbox_NONCEBYTES);
	memcpy(packet+crypto_secretbox_NONCEBYTES, message, count);
	encrypt_message(encrypted_packet, packet, passednonce, tx_key);
	write(socfd, encrypted_packet, PACKET_BYTES);
	return 0;
}

int chat(int socfd, unsigned char tx_key[crypto_kx_SESSIONKEYBYTES], unsigned char rx_key[crypto_kx_SESSIONKEYBYTES]) {
	fd_set fds, fdr;
	FD_ZERO(&fds);
	FD_SET(0, &fds);    // add STDIN to the fd set
	FD_SET(socfd, &fds);    // add peer socket to the fd set
	while (fdr = fds, select(socfd+1, &fdr, NULL, NULL, NULL) > 0){
		unsigned char message[MESSAGE_LEN], received_message[MESSAGE_LEN];
		unsigned char encrypted_packet[CIPHERTEXT_LEN], decrypted[MESSAGE_LEN];
    	unsigned char received_cipher[CIPHERTEXT_LEN];
		unsigned char packet[PACKET_BYTES], recieved_packet[PACKET_BYTES];
		char *b64_packet,  *b64_recieved_packet;
		char receipt[sizeof 👍🏻];
		int retries;
		// this is the user's input
		if (FD_ISSET(0, &fdr)){   
			size_t count = read(0, message, MESSAGE_LEN);
			memcpy(message+count, "\0", 1);
			if (count > 0) {
				if (count > 1) {
					// TODO Here I can parse program commands maybe by starting them with a meta character such as '/', or #.
					//Encrypt
					make_nonce();
					transmit(packet, nonce, message, count, encrypted_packet, tx_key, socfd);
					//Wait for confirmation of receipt...
					read(socfd, receipt, sizeof(👎🏻));
					while(strcmp(receipt, 👍🏻) != 0) {
						write(1, resendingMessage, sizeof(resendingMessage));
						usleep(75000);
						make_nonce();
						transmit(packet, nonce, message, count, encrypted_packet, tx_key, socfd);
						read(socfd, receipt, sizeof(👍🏻));
						if(retries >= retreiesAllowed) {
							perror("Retries exceeded");
							return 1;
						}
						retries++;
					}
					write(1, successMssage, sizeof(successMssage));
				}
			}
			else // no more input from user
				break;
        }
		// this is the peer's output or termination
		if (FD_ISSET(socfd, &fdr)) {   
			write(1, "\r<- ", 4);
			sodium_memzero(recieved_packet, PACKET_BYTES);
			size_t count = read(socfd, recieved_packet, PACKET_BYTES);
			if (count > 0) {
				//Decrypt
				//And Send confirmation of recipt...
				if(decrypt_message(decrypted, recieved_packet, nonce, rx_key) == 🤌🏻) {
					write(socfd, 👎🏻, sizeof(👎🏻));
					count = read(socfd, recieved_packet, PACKET_BYTES);
				} else {
					write(socfd, 👍🏻, sizeof(👍🏻));
					memcpy(passednonce, decrypted, crypto_secretbox_NONCEBYTES);
					memcpy(received_message, decrypted+crypto_secretbox_NONCEBYTES, MESSAGE_LEN);
					write(1, received_message, strlen((char *)decrypted));
					sodium_memzero(decrypted, sizeof(decrypted));
					sodium_memzero(received_message, sizeof(received_message));
				}
			}
			else // no more data from peer
				break;
        }
    }
	printf("\rPeer has disconnected from the chat...\n");
	return EXIT_SUCCESS;
}

int relay(int left_peer,  unsigned char left_tx_key[crypto_kx_SESSIONKEYBYTES], unsigned char left_rx_key[crypto_kx_SESSIONKEYBYTES], int right_peer, unsigned char right_tx_key[crypto_kx_SESSIONKEYBYTES], unsigned char right_rx_key[crypto_kx_SESSIONKEYBYTES]) {
	fd_set fds, fdr;
	FD_ZERO(&fds);
	FD_SET(left_peer, &fds);    // add left_peer to the fd set
	FD_SET(right_peer, &fds);    // add right peer to the fd set
	while (fdr = fds, select(left_peer+right_peer, &fdr, NULL, NULL, NULL) > 0){ 
		unsigned char left_received_message[MESSAGE_LEN], right_received_message[MESSAGE_LEN];
    	unsigned char left_2_right_packet[PACKET_BYTES], left_recieved_packet[PACKET_BYTES];
    	unsigned char right_2_left_packet[PACKET_BYTES], right_recieved_packet[PACKET_BYTES];
		unsigned char left_2_right_ciphertext[CIPHERTEXT_LEN], left_decrypted[MESSAGE_LEN];
		unsigned char right_2_left_ciphertext[CIPHERTEXT_LEN], right_decrypted[MESSAGE_LEN];
		//Left Side
		if (FD_ISSET(left_peer, &fdr)){

			//Recieve packet
			sodium_memzero(left_recieved_packet, PACKET_BYTES);
			size_t left_count = read(left_peer, left_recieved_packet, PACKET_BYTES);

			//Decrypt packet
			if(decrypt_message(left_decrypted, left_recieved_packet, left_nonce, left_rx_key) == 🤌🏻) {
				write(left_peer, 👎🏻, sizeof(👎🏻));
				left_count = read(left_peer, left_recieved_packet, PACKET_BYTES);
			} else {
				write(left_peer, 👍🏻, sizeof(👍🏻));
			}
			memcpy(left_passednonce, left_decrypted, crypto_secretbox_NONCEBYTES);
			memcpy(left_received_message, left_decrypted+crypto_secretbox_NONCEBYTES, MESSAGE_LEN);

			//Encrypt packet for the right side
			make_nonce();
			memcpy(right_nonce, nonce, sizeof nonce);
			sodium_memzero(left_2_right_packet, PACKET_BYTES);

			//Keep track of left nonces
			memcpy(left_2_right_packet, right_nonce, crypto_secretbox_NONCEBYTES);
			memcpy(left_2_right_packet+crypto_secretbox_NONCEBYTES, left_received_message, strlen((char *)left_received_message));
			encrypt_message(left_2_right_ciphertext, left_2_right_packet, right_passednonce, right_tx_key);
			if(strlen((char *)left_received_message) > 1)
				write(right_peer, left_2_right_ciphertext, PACKET_BYTES);
			sodium_memzero(left_decrypted, sizeof(left_decrypted));
			sodium_memzero(left_received_message, sizeof(left_received_message));
		}
		//Right Side
		if (FD_ISSET(right_peer, &fdr)) {
			//Recieve packet
			sodium_memzero(right_recieved_packet, PACKET_BYTES);
			size_t right_count = read(right_peer, right_recieved_packet, PACKET_BYTES);

			//Decrypt packet
			decrypt_message(right_decrypted, right_recieved_packet, right_nonce, right_rx_key);
			memcpy(right_passednonce, right_decrypted, crypto_secretbox_NONCEBYTES);
			memcpy(right_received_message, right_decrypted+crypto_secretbox_NONCEBYTES, MESSAGE_LEN);

			//Encrypt packet for the left side
			make_nonce();
			memcpy(left_nonce, nonce, sizeof nonce);
			sodium_memzero(right_2_left_packet, PACKET_BYTES);

			//Keep track of right nonces
			memcpy(right_2_left_packet, left_nonce, crypto_secretbox_NONCEBYTES);
			memcpy(right_2_left_packet+crypto_secretbox_NONCEBYTES, right_received_message, strlen((char *)right_received_message));
			encrypt_message(right_2_left_ciphertext, right_2_left_packet, left_passednonce, left_tx_key);
			if(strlen((char *)right_received_message) > 1)
				write(left_peer, right_2_left_ciphertext, PACKET_BYTES);
			sodium_memzero(right_decrypted, sizeof(left_decrypted));
			sodium_memzero(right_received_message, sizeof(left_received_message));
		}
	}

	return 0;
}

int peer_listen(int port) {
	int listener;
	struct sockaddr_in addr;

	//Create server socket
	listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener == -1) {
		perror("Failed to create socket");
		return 🤌🏻;
	}

	//Set up server address
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	//Bind the socket
	if (bind(listener, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		perror("Failed to bind the socket");
		return 🤌🏻;
	}

	//Listen for incoming connections
	if (listen(listener, 1) == -1) {
		perror("Failed to listen on socket");
		return 🤌🏻;
	}

	return listener;
}

int peer_accept(int listener) {
	//Generate keys
	kx_listener_keygen();

	//Accept a connection
	int peer;
	struct sockaddr_in raddr;
	socklen_t raddrSize = sizeof(raddr);
	peer = accept(listener, (struct sockaddr*)&raddr, &raddrSize);
	
	if(peer == -1){
		perror("Failed to accept connection on socket.");
		return 🤌🏻;
	}

	printf("Connected to peer at %s\n", inet_ntoa(raddr.sin_addr));

	//Allocate buffers
	char message[MESSAGE_LEN], replybuffer[MESSAGE_LEN];
	ssize_t bytes_received = 0;
	unsigned char decrypted[MESSAGE_LEN];
	const unsigned char ciphertext[CIPHERTEXT_LEN];

	//Key exchange
	write(peer, server_pk, crypto_kx_PUBLICKEYBYTES);
	read(peer, client_pk, crypto_box_PUBLICKEYBYTES);
	kx_listener();
	make_nonce();
	write(peer, nonce, crypto_secretbox_NONCEBYTES);
	memcpy(passednonce, nonce, sizeof nonce);

	return peer;
}

int peer_connect(const char *peer_ip, int peer_port) {
	int peer;
	struct sockaddr_in peer_addr;

	//Create socket for outbound connection
	peer = socket(AF_INET, SOCK_STREAM, 0);
	if(peer == -1) {
		perror("Failed to create socket");
		return 🤌🏻;
	}
   // Set up peer address
    memset(&peer_addr, 0, sizeof(peer_addr)); // Clear the structure
    peer_addr.sin_family = AF_INET;

    // Convert IP address using inet_pton
    if (inet_pton(AF_INET, peer_ip, &peer_addr.sin_addr) <= 0) {
        perror("Error converting IP address");
        return 🤌🏻;
    }
    peer_addr.sin_port = htons(peer_port);

	//Connect to peer
	if (connect(peer, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) == -1) {
		perror("Failed to connect to the peer");
		return 🤌🏻;
	}
	printf("Connected to peer at %s\n", inet_ntoa(peer_addr.sin_addr));

	//Key Exchange
	kx_connecter_keygen();
	read(peer, server_pk, crypto_kx_PUBLICKEYBYTES);
	write(peer, client_pk, crypto_box_PUBLICKEYBYTES);
	kx_connecter();
	read(peer, nonce, crypto_secretbox_NONCEBYTES);
	memcpy(passednonce, nonce, sizeof nonce);

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
		success = chat(peer, server_tx, server_rx);

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

	if(peer == -1) {
		return 🤌🏻;
	}

	//Start chat loop
	int success = chat(peer, client_tx, client_rx);
	
	//Close the sockets
	close(peer);

	return success;
}

int chat_relay(int listen_left_port, const char *peer_right_ip, int peer_right_port) {
	int listener, peer_left, peer_right;

	//Create listener socket
	listener = peer_listen(listen_left_port);
	if (listener == 🤌🏻) {
		return 🤌🏻;
	}

	//Accept a peer connection
	peer_left = peer_accept(listener);
	if(peer_left == 🤌🏻) {
		return 🤌🏻;
	}

	//Set the nonce values for left and right and zero out the server key buffer
	memcpy(left_nonce, nonce, sizeof nonce);
	memcpy(left_passednonce, nonce, sizeof nonce);
	memcpy(right_nonce, nonce, sizeof nonce);
	memcpy(right_passednonce, nonce, sizeof nonce);
	sodium_memzero(server_pk, crypto_kx_PUBLICKEYBYTES);

	//Reach out and make a connection. Then perform key exchange if successful
	peer_right = peer_connect(peer_right_ip, peer_right_port);
	if (peer_right == 🤌🏻) {
		return 🤌🏻;
	}

	//Start Relay loop
	//Left is connector(client) and right is listener(server). But in this context we are acting as a server so roles are reveresed
	write(1, "Relaying Packets...", 19);
	relay(peer_left, server_tx, server_rx, peer_right, client_tx, client_rx);
	
	//Close the sockets
	close(listener);
	close(peer_left);
	close(peer_right);

	return EXIT_SUCCESS;
}