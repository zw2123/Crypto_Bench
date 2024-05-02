// Include necessary headers...
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <time.h>
#include <sys/resource.h>
#include <pthread.h>
#include <unistd.h>

#define DATA_SIZE 64  // This needs to be less than key size minus padding overhead
#define ITERATIONS 10
#define PADDING RSA_PKCS1_OAEP_PADDING

struct benchmark_stats {
    double enc_time;
    double dec_time;
    double total_time;
    double throughput;
    char *integrity_check;
    double cpu_user_time;
    double cpu_system_time;
    int thread_id;
};

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

void *rsa_encryption_decryption(void *arg) {
    struct benchmark_stats *stats = (struct benchmark_stats *)arg;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, stats->thread_id) <= 0)
        handleErrors();

    EVP_PKEY_keygen(pctx, &pkey);
    unsigned char *plaintext = malloc(DATA_SIZE);
    size_t ciphertext_len = EVP_PKEY_size(pkey);
    unsigned char *ciphertext = malloc(ciphertext_len);
    unsigned char *decryptedtext = malloc(DATA_SIZE);
    size_t decryptedlen = DATA_SIZE;

    RAND_bytes(plaintext, DATA_SIZE);
    EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_encrypt_init(ectx);
    EVP_PKEY_CTX_set_rsa_padding(ectx, PADDING);
    EVP_PKEY_decrypt_init(dctx);
    EVP_PKEY_CTX_set_rsa_padding(dctx, PADDING);

    struct timespec start, end;
    double enc_time = 0, dec_time = 0;

    for (int i = 0; i < ITERATIONS; i++) {
        size_t outlen = ciphertext_len;
        EVP_PKEY_encrypt(ectx, ciphertext, &outlen, plaintext, DATA_SIZE);
        EVP_PKEY_decrypt(dctx, decryptedtext, &decryptedlen, ciphertext, outlen);
        clock_gettime(CLOCK_MONOTONIC, &end);
        enc_time += (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1e6;
    }

    stats->enc_time = enc_time / ITERATIONS;
    stats->dec_time = dec_time / ITERATIONS;
    stats->total_time = stats->enc_time + stats->dec_time;
    stats->throughput = ((double)DATA_SIZE * ITERATIONS / (1024.0 * 1024.0)) / (stats->total_time / 1000.0);
    stats->integrity_check = (memcmp(plaintext, decryptedtext, DATA_SIZE) == 0) ? "Pass" : "Fail";

    free(plaintext);
    free(ciphertext);
    free(decryptedtext);
    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);

    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <2048|4096>\n", argv[0]);
        return 1;
    }

    int key_size = atoi(argv[1]);
    int num_threads = sysconf(_SC_NPROCESSORS_ONLN);
    pthread_t threads[num_threads];
    struct benchmark_stats stats[num_threads];

    for (int i = 0; i < num_threads; i++) {
        stats[i].thread_id = key_size;
        pthread_create(&threads[i], NULL, rsa_encryption_decryption, &stats[i]);
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
        printf("Thread %d: Encryption Time: %.2f ms, Decryption Time: %.2f ms, Total Time: %.2f ms, Throughput: %.2f MB/s, Data Integrity: %s\n",
               i, stats[i].enc_time, stats[i].dec_time, stats[i].total_time, stats[i].throughput, stats[i].integrity_check);
    }

    return 0;
}
