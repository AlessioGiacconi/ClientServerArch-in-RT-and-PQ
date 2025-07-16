#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sched.h>
#include <pthread.h>
#include <time.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>

#define PORT 12345
#define BUFFER_SIZE 8192

int server_sock = -1;

void log_ts(const char *msg) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    printf("[%s] %.6f\n", msg, ts.tv_sec + ts.tv_nsec / 1e9);
}

void handle_sigint(int sig) {
    printf("\n[!] Interruzione, chiusura server.\n");
    if (server_sock >= 0) close(server_sock);
    exit(0);
}

void set_rt_sched(void) {
    struct sched_param param = { .sched_priority = 80 };
    if (sched_setscheduler(0, SCHED_FIFO, &param) == -1) {
        perror("sched_setscheduler");
    } else {
        printf("[*] Scheduling SCHED_FIFO, prio=80\n");
    }
}

void *client_handler(void *arg) {
    int client_sock = *(int *)arg;
    free(arg);
    log_ts("Connessione accettata");

    // === OQS provider ===
    OSSL_PROVIDER *oqs = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if (!oqs) {
        fprintf(stderr, "[!] Errore: impossibile caricare oqsprovider\n");
        ERR_print_errors_fp(stderr);
        close(client_sock);
        return NULL;
    }

    EVP_PKEY_CTX *kex_ctx = EVP_PKEY_CTX_new_from_name(NULL, "mlkem512", NULL);
    EVP_PKEY *kem_key = NULL;
    EVP_PKEY_keygen_init(kex_ctx);
    EVP_PKEY_generate(kex_ctx, &kem_key);

    unsigned char pubkey[2048];
    size_t pubkey_len = sizeof(pubkey);
    EVP_PKEY_get_raw_public_key(kem_key, pubkey, &pubkey_len);
    send(client_sock, &pubkey_len, sizeof(pubkey_len), 0);
    send(client_sock, pubkey, pubkey_len, 0);

    size_t ct_len;
    recv(client_sock, &ct_len, sizeof(ct_len), 0);
    unsigned char ct[2048];
    recv(client_sock, ct, ct_len, 0);

    unsigned char shared_secret[64];
    size_t ss_len = sizeof(shared_secret);
    EVP_PKEY_CTX *decaps_ctx = EVP_PKEY_CTX_new(kem_key, NULL);
    EVP_PKEY_decapsulate_init(decaps_ctx, NULL);
    if (EVP_PKEY_decapsulate(decaps_ctx, shared_secret, &ss_len, ct, ct_len) <= 0) {
        fprintf(stderr, "Errore: EVP_PKEY_decapsulate fallito\n");
        ERR_print_errors_fp(stderr);
    }
    log_ts("Shared secret decapsulata (mlkem512)");

    unsigned char nonce[12];
    recv(client_sock, nonce, sizeof(nonce), 0);
    uint32_t msg_len;
    recv(client_sock, &msg_len, sizeof(msg_len), 0);
    msg_len = ntohl(msg_len);

    unsigned char ciphertext[msg_len];
    recv(client_sock, ciphertext, msg_len, 0);
    unsigned char tag[16];
    recv(client_sock, tag, sizeof(tag), 0);

    unsigned char plaintext[BUFFER_SIZE];
    int outlen = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(nonce), NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, shared_secret, nonce);
    EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, msg_len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, sizeof(tag), tag);
    int final_ok = EVP_DecryptFinal_ex(ctx, plaintext + outlen, &outlen);
    EVP_CIPHER_CTX_free(ctx);

    if (final_ok > 0) {
        plaintext[msg_len] = '\0';
        log_ts("Messaggio decrittato");
        printf("\033[1;34m[MSG] %s\033[0m\n", plaintext);
    } else {
        printf("[!] Errore nella decrittazione!\n");
    }

    EVP_PKEY_free(kem_key);
    EVP_PKEY_CTX_free(kex_ctx);
    EVP_PKEY_CTX_free(decaps_ctx);
    OSSL_PROVIDER_unload(oqs);
    close(client_sock);
    return NULL;
}

int main() {
	
	setenv("OPENSSL_CONF", "/home/alessio/openssl-pq/openssl.cnf", 1);
	setenv("OPENSSL_MODULES", "/usr/lib/x86_64-linux-gnu/ossl-modules", 1);
	
    signal(SIGINT, handle_sigint);
    set_rt_sched();

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(server_sock, (struct sockaddr *)&addr, sizeof(addr));
    listen(server_sock, 10);
    printf("[*] Server PQ-RT avviato su porta %d\n", PORT);

    while (1) {
        int *client_sock = malloc(sizeof(int));
        *client_sock = accept(server_sock, NULL, NULL);
        if (*client_sock < 0) {
            free(client_sock);
            continue;
        }
        pthread_t tid;
        pthread_create(&tid, NULL, client_handler, client_sock);
        pthread_detach(tid);
    }

    close(server_sock);
    return 0;
}
