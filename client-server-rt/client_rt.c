/* Comando corretto per compilare il file
 * gcc -Wall -Wno-deprecated-declarations -o client_rt client_rt.c -lssl -lcrypto
 * 
 * -Wno-deprecated-declarations --> se si vuole silenziare i warning sulle funzioni deprecate
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sched.h>
#include <time.h>
#include <execinfo.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define PORT 12345
#define TIMEOUT_SEC 5
#define MAX_MSG_LEN 8192

int sock = -1;
RSA *rsa_pub = NULL;

void log_ts(const char *stage) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    printf("[%s] t=%.6f s\n", stage, ts.tv_sec + ts.tv_nsec / 1e9);
}

void set_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void handle_sigsegv(int sig){
		void *array[10];
		size_t size;
		
		fprintf(stderr, "\n[!] Error: ricevuto SIGSEGV (segmentation fault)\n");
		
		size = backtrace(array, 10);
		fprintf(stderr, "[!] Backtrace (%zd stack frames):\n", size);
		backtrace_symbols_fd(array, size, STDERR_FILENO);
		
		exit(1);
}

void handle_sigint(int sig) {
    printf("\n[!] SIGINT ricevuto: cleanup...\n");
    if (sock >= 0) close(sock);
    if (rsa_pub) RSA_free(rsa_pub);
    exit(0);
}

void set_rt_sched(void) {
    struct sched_param param = { .sched_priority = 70 };
    if (sched_setscheduler(0, SCHED_FIFO, &param) == -1) {
        perror("sched_setscheduler");
    } else printf("[*] Scheduling SCHED_FIFO, prio=80\n");
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		fprintf(stderr, "Uso: %s \"messaggio da inviare\"\n", argv[0]);
		return 1;
	}
	
    signal(SIGINT, handle_sigint);
    signal(SIGSEGV, handle_sigsegv);
    set_rt_sched();

    struct sockaddr_in serv_addr = {0};
    fd_set read_fds;
    struct timeval timeout;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    set_non_blocking(sock);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
    connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    printf("[*] Connessione in corso...\n");
    log_ts("connect called");

    // Aspetta chiave pubblica
    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);
    timeout.tv_sec = TIMEOUT_SEC;

    unsigned char pubkey_buf[2048] = {0};
    if (select(sock + 1, &read_fds, NULL, NULL, &timeout) > 0) {
        int len = recv(sock, pubkey_buf, sizeof(pubkey_buf), 0);
        BIO *bio = BIO_new_mem_buf(pubkey_buf, len);
        rsa_pub = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);
        log_ts("RSA pubkey received");
    } else {
        fprintf(stderr, "[!] Timeout ricezione chiave pubblica\n");
        close(sock);
        return 1;
    }

    // AES key + IV
    unsigned char aes_key[32], iv[16];
    RAND_bytes(aes_key, sizeof(aes_key));
    RAND_bytes(iv, sizeof(iv));

    // Invia chiave AES cifrata con RSA
    unsigned char enc_key[256];
    int enc_len = RSA_public_encrypt(sizeof(aes_key), aes_key, enc_key, rsa_pub, RSA_PKCS1_OAEP_PADDING);
    send(sock, enc_key, enc_len, 0);
    log_ts("AES key sent");

    // Invia IV al server per decifrare
    send(sock, iv, sizeof(iv), 0);
    log_ts("IV sent");

    // Prepara AES-CBC con EVP
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv);

    // Costruisce messaggio con timestamp + payload massivo
    unsigned char msg[MAX_MSG_LEN];
    memset(msg, 0, sizeof(msg));
    
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    double timestamp = ts.tv_sec + ts.tv_nsec / 1e9;
    int written = snprintf((char *)msg, MAX_MSG_LEN, "%.9f|%s", timestamp, argv[1]);
    if (written < 0 || written >= MAX_MSG_LEN - 1) {
        fprintf(stderr, "Errore nella creazione del messaggio\n");
        exit(1);
    }

    // Cifra
    unsigned char cipher[MAX_MSG_LEN + 32];
    int clen1 = 0, clen2 = 0;
    EVP_EncryptUpdate(ctx, cipher, &clen1, msg, written);
    EVP_EncryptFinal_ex(ctx, cipher + clen1, &clen2);
    int total_len = clen1 + clen2;

    uint32_t net_len = htonl(total_len);
    send(sock, &net_len, sizeof(net_len), 0);
    send(sock, cipher, total_len, 0);
    log_ts("Encrypted message sent");
    printf("[*] Messaggio inviato (%d byte cifrati)\n", total_len);

    EVP_CIPHER_CTX_free(ctx);
    RSA_free(rsa_pub);
    close(sock);
    log_ts("client done");
    return 0;
}
