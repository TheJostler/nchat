#include "crypto.h"
#include <sodium.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define MESSAGE_LEN 4095
#define CIPHERTEXT_LEN (crypto_secretbox_MACBYTES + MESSAGE_LEN)
#define PACKET_BYTES (crypto_secretbox_NONCEBYTES + CIPHERTEXT_LEN + 4)
#define 🤌🏻 -1

unsigned char nonce[crypto_secretbox_NONCEBYTES], passednonce[crypto_secretbox_NONCEBYTES];
unsigned char left_nonce[crypto_secretbox_NONCEBYTES], left_passednonce[crypto_secretbox_NONCEBYTES];
unsigned char right_nonce[crypto_secretbox_NONCEBYTES], right_passednonce[crypto_secretbox_NONCEBYTES];
//Server keys
unsigned char server_pk[crypto_kx_PUBLICKEYBYTES], server_sk[crypto_kx_SECRETKEYBYTES];
unsigned char server_rx[crypto_kx_SESSIONKEYBYTES], server_tx[crypto_kx_SESSIONKEYBYTES];
//Client keys
unsigned char client_pk[crypto_kx_PUBLICKEYBYTES], client_sk[crypto_kx_SECRETKEYBYTES];
unsigned char client_rx[crypto_kx_SESSIONKEYBYTES], client_tx[crypto_kx_SESSIONKEYBYTES];

int sodium_init_or_fail() {
    int si = sodium_init();
    if (si == -1) {
        perror("Could not initialize libsodium");
        exit(🤌🏻);
    }
    return EXIT_SUCCESS;
}

void make_nonce() {
    randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);
}

void kx_listener_keygen() {
    sodium_init_or_fail();

    /* Generate the server's key pair */
    crypto_kx_keypair(server_pk, server_sk);
}

int kx_listener() {

    /* Prerequisite after this point: the client's public key must be known by the server */

    /* Compute two shared keys using the client's public key and the server's secret key.
    server_rx will be used by the server to receive data from the client,
    server_tx will be used by the server to send data to the client. */
    if (crypto_kx_server_session_keys(server_rx, server_tx, server_pk, server_sk, client_pk) != 0) {
        /* Suspicious client public key, bail out */

        perror("Suspicious client public key, exiting");
        return 🤌🏻;
    }
    return EXIT_SUCCESS;
}

void kx_connecter_keygen() {
    sodium_init_or_fail();

    /* Generate the client's key pair */
    crypto_kx_keypair(client_pk, client_sk);
}

int kx_connecter() {
    /* Prerequisite after this point: the server's public key must be known by the client */

    /* Compute two shared keys using the server's public key and the client's secret key.
    client_rx will be used by the client to receive data from the server,
    client_tx will be used by the client to send data to the server. */
    if (crypto_kx_client_session_keys(client_rx, client_tx, client_pk, client_sk, server_pk) != 0) {
        /* Suspicious server public key, bail out */

        perror("Suspicious server public key, exiting");
        return 🤌🏻;
    }
    return EXIT_SUCCESS;
}

int encrypt_message(unsigned char ciphertext_[CIPHERTEXT_LEN], const unsigned char *message_, const unsigned char nonce_[24], const unsigned char shared_x[32]) {
    if (crypto_secretbox_easy(ciphertext_, message_, MESSAGE_LEN, nonce_, shared_x) != 0) {
        perror("There was an error encrypting the message");
        return 🤌🏻;
    }
    return EXIT_SUCCESS;
}

int decrypt_message(unsigned char decrypted_[MESSAGE_LEN], const unsigned char ciphertext_[CIPHERTEXT_LEN], const unsigned char nonce_[24],const unsigned char shared_x[32]) {
    if (crypto_secretbox_open_easy(decrypted_, ciphertext_, CIPHERTEXT_LEN, nonce_, shared_x) != 0) {
    	return 🤌🏻;
    }
    return EXIT_SUCCESS;
}

int test_kx() {
    sodium_init_or_fail();
    const unsigned char *message = (unsigned char *)"This message was encrypted and decrypted using shared keys that were generated with a diffie helman key exchange";
    unsigned char ciphertext[CIPHERTEXT_LEN], decrypted[MESSAGE_LEN];
    unsigned char received_cipher[CIPHERTEXT_LEN];
    unsigned char packet[PACKET_BYTES], recieved_packet[PACKET_BYTES];

    make_nonce();
    kx_listener_keygen();
    kx_connecter_keygen();
    kx_listener();
    kx_connecter();

    //Encrypt
    encrypt_message(ciphertext, message, nonce, client_tx);
    memcpy(packet, nonce, crypto_secretbox_NONCEBYTES);
    memcpy(packet+crypto_secretbox_NONCEBYTES, ciphertext, sizeof(ciphertext));
    //PACKET PASSED OVER THE NETWORK
    memcpy(recieved_packet, packet, PACKET_BYTES);
    memcpy(passednonce, recieved_packet, crypto_secretbox_NONCEBYTES);
    memcpy(received_cipher, recieved_packet+crypto_secretbox_NONCEBYTES, CIPHERTEXT_LEN);
    //Decrypt
    decrypt_message(decrypted, received_cipher, passednonce, server_rx);

    if (sodium_memcmp(message, decrypted, MESSAGE_LEN) == -1) {
        perror("Test failed");
        fwrite(decrypted, 1, MESSAGE_LEN, stdout);
        return 🤌🏻;
    } else {
        printf("Test succeeded\n");
        printf("Decrypted Message: %s\n", decrypted);
        return 0;
    }
}
