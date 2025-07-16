#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <execinfo.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

#define PORT 12345
#define BUFFER_SIZE 8192

int sock = -1;
OSSL_PROVIDER *oqs = NULL;
OSSL_LIB_CTX *libctx = NULL;

void log_ts(const char *msg) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    printf("[%s] t=%.6f s\n", msg, ts.tv_sec + ts.tv_nsec / 1e9);
}

void handle_sigsegv(int sig) {
    void *array[10];
    size_t size;
    fprintf(stderr, "\n[!] SIGSEGV ricevuto\n");
    size = backtrace(array, 10);
    backtrace_symbols_fd(array, size, STDERR_FILENO);
    exit(1);
}

void handle_sigint(int sig) {
    printf("\n[!] Interruzione: cleanup...\n");
    if (sock >= 0) close(sock);
    if (oqs) OSSL_PROVIDER_unload(oqs);
    if (libctx) OSSL_LIB_CTX_free(libctx);
    exit(0);
}

void set_rt_sched(void) {
    struct sched_param param = { .sched_priority = 70 };
    if (sched_setscheduler(0, SCHED_FIFO, &param) == -1)
        perror("sched_setscheduler");
    else
        printf("[*] Scheduling SCHED_FIFO, prio=70\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Uso: %s \"messaggio\"\n", argv[0]);
        return 1;
    }
	
	setenv("OPENSSL_CONF", "/home/alessio/openssl-pq/openssl.cnf", 1);
	setenv("OPENSSL_MODULES", "/usr/lib/x86_64-linux-gnu/ossl-modules", 1);

    signal(SIGINT, handle_sigint);
    signal(SIGSEGV, handle_sigsegv);
    set_rt_sched();

    libctx = OSSL_LIB_CTX_new();
    oqs = OSSL_PROVIDER_load(libctx, "oqsprovider");
    if (!oqs) {
        fprintf(stderr, "Errore: impossibile caricare il provider oqsprovider\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // === Connessione TCP ===
    sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &server.sin_addr);
    connect(sock, (struct sockaddr *)&server, sizeof(server));
    log_ts("Connessione al server");

    // === Ricezione chiave pubblica ===
    size_t pubkey_len = 0;
    recv(sock, &pubkey_len, sizeof(pubkey_len), 0);
    unsigned char pubkey[2048];
    ssize_t recvd = recv(sock, pubkey, pubkey_len, 0);
    if (recvd != (ssize_t)pubkey_len) {
        fprintf(stderr, "Errore: chiave pubblica incompleta (%zd/%zu byte)\n", recvd, pubkey_len);
        exit(1);
    }

    // === Conversione in EVP_PKEY ===
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, "mlkem512", NULL);
    if (!ctx) {
        fprintf(stderr, "Errore: EVP_PKEY_CTX_new_from_name fallito\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (EVP_PKEY_fromdata_init(ctx) <= 0) {
        fprintf(stderr, "Errore: EVP_PKEY_fromdata_init fallito\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    EVP_PKEY *server_key = NULL;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string("pub", pubkey, pubkey_len),
        OSSL_PARAM_construct_end()
    };

    if (EVP_PKEY_fromdata(ctx, &server_key, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        fprintf(stderr, "Errore: EVP_PKEY_fromdata fallito\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    EVP_PKEY_CTX_free(ctx);

    // === Encapsulazione ===
    EVP_PKEY_CTX *encaps_ctx = EVP_PKEY_CTX_new_from_pkey(libctx, server_key, NULL);
    if (!encaps_ctx || EVP_PKEY_encapsulate_init(encaps_ctx, NULL) <= 0) {
        fprintf(stderr, "Errore: EVP_PKEY_encapsulate_init fallito\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    unsigned char ciphertext[2048];
    size_t ct_len = sizeof(ciphertext);
    unsigned char shared_secret[64];
    size_t ss_len = sizeof(shared_secret);

    if (EVP_PKEY_encapsulate(encaps_ctx, ciphertext, &ct_len, shared_secret, &ss_len) <= 0) {
        fprintf(stderr, "Errore: EVP_PKEY_encapsulate fallito\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    log_ts("Chiave condivisa generata (mlkem512)");

    // === Invia ciphertext ===
    send(sock, &ct_len, sizeof(ct_len), 0);
    send(sock, ciphertext, ct_len, 0);
    EVP_PKEY_CTX_free(encaps_ctx);
    EVP_PKEY_free(server_key);

    // === ChaCha20-Poly1305 ===
    unsigned char nonce[12];
    RAND_bytes(nonce, sizeof(nonce));

    // Prepara messaggio con timestamp + payload
    unsigned char plaintext[BUFFER_SIZE];
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    double timestamp = ts.tv_sec + ts.tv_nsec / 1e9;
    snprintf((char *)plaintext, sizeof(plaintext), "%.9f|%s", timestamp, argv[1]);

    unsigned char ciphertext_enc[BUFFER_SIZE + 32];
    unsigned char tag[16];
    int len = 0, len_final = 0;

    EVP_CIPHER_CTX *ctx_enc = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx_enc, EVP_chacha20_poly1305(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx_enc, EVP_CTRL_AEAD_SET_IVLEN, sizeof(nonce), NULL);
    EVP_EncryptInit_ex(ctx_enc, NULL, NULL, shared_secret, nonce);

    EVP_EncryptUpdate(ctx_enc, ciphertext_enc, &len, plaintext, strlen((char *)plaintext));
    EVP_EncryptFinal_ex(ctx_enc, ciphertext_enc + len, &len_final);
    EVP_CIPHER_CTX_ctrl(ctx_enc, EVP_CTRL_AEAD_GET_TAG, sizeof(tag), tag);
    EVP_CIPHER_CTX_free(ctx_enc);

    int total_len = len + len_final;
    uint32_t net_len = htonl(total_len);

    send(sock, nonce, sizeof(nonce), 0);
    send(sock, &net_len, sizeof(net_len), 0);
    send(sock, ciphertext_enc, total_len, 0);
    send(sock, tag, sizeof(tag), 0);
    log_ts("Messaggio cifrato inviato");

    close(sock);
    OSSL_PROVIDER_unload(oqs);
    OSSL_LIB_CTX_free(libctx);
    return 0;
}
