#ifndef CRYPTO_H
#define CRYPTO_H

#include <sodium.h>

#define MESSAGE_LEN 4095
#define CIPHERTEXT_LEN (crypto_secretbox_MACBYTES + MESSAGE_LEN)
#define PACKET_BYTES (crypto_secretbox_NONCEBYTES + CIPHERTEXT_LEN + 4)

extern unsigned char nonce[crypto_secretbox_NONCEBYTES], passednonce[crypto_secretbox_NONCEBYTES];
extern unsigned char left_nonce[crypto_secretbox_NONCEBYTES], left_passednonce[crypto_secretbox_NONCEBYTES];
extern unsigned char right_nonce[crypto_secretbox_NONCEBYTES], right_passednonce[crypto_secretbox_NONCEBYTES];
//Server keys
extern unsigned char server_pk[crypto_kx_PUBLICKEYBYTES], server_sk[crypto_kx_SECRETKEYBYTES];
extern unsigned char server_rx[crypto_kx_SESSIONKEYBYTES], server_tx[crypto_kx_SESSIONKEYBYTES];
//Client keys
extern unsigned char client_pk[crypto_kx_PUBLICKEYBYTES], client_sk[crypto_kx_SECRETKEYBYTES];
extern unsigned char client_rx[crypto_kx_SESSIONKEYBYTES], client_tx[crypto_kx_SESSIONKEYBYTES];

int sodium_init_or_fail();
void make_nonce();
void kx_listener_keygen();
int kx_listener();
void kx_connecter_keygen();
int kx_connecter();
int encrypt_message(unsigned char ciphertext[CIPHERTEXT_LEN], const unsigned char *message, const unsigned char *nonce,const unsigned char shared_x[32]);
int decrypt_message(unsigned char decrypted[MESSAGE_LEN], const unsigned char ciphertext[CIPHERTEXT_LEN], const unsigned char *nonce,const unsigned char shared_x[32]);
int test_kx();

#endif
