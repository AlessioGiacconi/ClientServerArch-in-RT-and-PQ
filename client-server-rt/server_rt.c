/* Comando corretto per compilare il file
 * gcc -Wall -Wno-deprecated-declarations -o server_rt server_rt.c -lssl -lcrypto -lrt
 * 
 * sudo ./server_rt --> dato che lo scheduler SCHED_FIFO richiede privilegi di root
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
#include <pthread.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define PORT 12345
#define TIMEOUT_SEC 5

int sockfd;

void log_ts(const char *stage) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    printf("[%s] t=%.6f s\n", stage, ts.tv_sec + ts.tv_nsec / 1e9);
}

void handle_sigint(int sig) {
    printf("\n[!] Interruzione rilevata, chiusura server...\n");
    if (sockfd > 0) close(sockfd);
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

void handle_sigsegv(int sig){
		void *array[10];
		size_t size;
		
		fprintf(stderr, "\n[!] Error: ricevuto SIGSEGV (segmentation fault)\n");
		
		size = backtrace(array, 10);
		fprintf(stderr, "[!] Backtrace (%zd stack frames):\n", size);
		backtrace_symbols_fd(array, size, STDERR_FILENO);
		
		exit(1);
}

void set_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void *client_handler(void *arg) {
	int clientfd = *(int *)arg;
	free(arg);
	
	log_ts("start RSA");
	RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(bio, rsa);
    size_t pub_len = BIO_pending(bio);
    unsigned char pub_key[2048] = {0};
    BIO_read(bio, pub_key, pub_len);
    send(clientfd, pub_key, pub_len, 0);
    BIO_free(bio);
    
    unsigned char enc_key[256] = {0};
    recv(clientfd, enc_key, sizeof(enc_key), 0);
    
    unsigned char aes_key[32] = {0};
    RSA_private_decrypt(256, enc_key, aes_key, rsa, RSA_PKCS1_OAEP_PADDING);
    log_ts("AES key decrypted");
    
    unsigned char iv[16] = {0};
    recv(clientfd, iv, sizeof(iv), 0);
    log_ts("IV received");
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv);
    
    uint32_t net_len = 0;
    recv(clientfd, &net_len, sizeof(net_len), 0);
    uint32_t cipher_len = ntohl(net_len);

    unsigned char *buf = malloc(cipher_len);
    size_t received = 0;
    while(received < cipher_len) {
        int chunk = recv(clientfd, buf + received, cipher_len - received, 0);
        if (chunk <= 0) break;
        received += chunk;
    }
    log_ts("cipher received");
    
    unsigned char *pt = malloc(cipher_len + EVP_MAX_BLOCK_LENGTH);
    int len1 = 0, len2 = 0;
    EVP_DecryptUpdate(ctx, pt, &len1, buf, cipher_len);
    EVP_DecryptFinal_ex(ctx, pt + len1, &len2);
    pt[len1 + len2] = '\0';
    log_ts("message decrypted");

    char *sep = strchr((char *)pt, '|');
    if(sep) {
        *sep = '\0';
        double t_sent = atof((char *)pt);
        char *real_msg = sep + 1;

        struct timespec t_now;
        clock_gettime(CLOCK_MONOTONIC, &t_now);
        double t_recv = t_now.tv_sec + t_now.tv_nsec / 1e9;

        printf("\033[1;32m[MSG] %s\033[0m\n", real_msg);
        printf("[*] RTT (send->decrypt): %.6f s \n", t_recv - t_sent);
    }

    EVP_CIPHER_CTX_free(ctx);
    free(buf);
    free(pt);
    close(clientfd);
    RSA_free(rsa);
    log_ts("client done");
    return NULL;
		
}

int main() {
	signal(SIGSEGV, handle_sigsegv);
    signal(SIGINT, handle_sigint);
    set_rt_sched();

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr = {0};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(PORT);
    bind(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    listen(sockfd, 10);
    printf("[*] Server multithread avviato su porta %d\n", PORT);

    while (1) {
        int *clientfd = malloc(sizeof(int));
        *clientfd = accept(sockfd, NULL, NULL);
        if (*clientfd >= 0) {
			log_ts("accepted");
            pthread_t tid;
            pthread_create(&tid, NULL, client_handler, clientfd);
            pthread_detach(tid);
        }
    }

    close(sockfd);
    return 0;
}
