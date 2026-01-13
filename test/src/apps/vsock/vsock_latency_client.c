// SPDX-License-Identifier: MPL-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <time.h>
#include <errno.h>

#define VSOCK_PORT 9002
#define NUM_ITERATIONS 10000
#define MSG_SIZE 64
#define WARMUP_ITERATIONS 100

static int compare_long(const void *a, const void *b) {
    long long diff = *(const long long*)a - *(const long long*)b;
    return (diff > 0) - (diff < 0);
}

static long long get_time_us() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000LL + ts.tv_nsec / 1000LL;
}

static double calculate_percentile(long long *sorted_data, int count, double percentile) {
    double index = (percentile / 100.0) * (count - 1);
    int lower = (int)index;
    int upper = lower + 1;
    
    if (upper >= count) {
        return (double)sorted_data[count - 1];
    }
    
    double weight = index - lower;
    return sorted_data[lower] * (1.0 - weight) + sorted_data[upper] * weight;
}

int main(int argc, char *argv[]) {
    unsigned int guest_cid = 3; // Default guest CID
    int sock;
    struct sockaddr_vm sa;
    char send_buf[MSG_SIZE];
    char recv_buf[MSG_SIZE];
    long long *rtt_times;
    long long start_time, end_time;
    int i;
    
    if (argc > 1) {
        guest_cid = atoi(argv[1]);
    }
    
    // Allocate array for storing RTT times
    rtt_times = malloc(NUM_ITERATIONS * sizeof(long long));
    if (!rtt_times) {
        fprintf(stderr, "Failed to allocate memory for RTT times\n");
        return 1;
    }
    
    // Fill send buffer
    memset(send_buf, 'A', MSG_SIZE);
    
    // Create socket
    sock = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        free(rtt_times);
        return 1;
    }
    
    // Connect to guest
    memset(&sa, 0, sizeof(sa));
    sa.svm_family = AF_VSOCK;
    sa.svm_cid = guest_cid;
    sa.svm_port = VSOCK_PORT;
    
    if (connect(sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("connect");
        close(sock);
        free(rtt_times);
        return 1;
    }
    
    printf("# Vsock Latency Test\n");
    printf("# Guest CID: %u\n", guest_cid);
    printf("# Warmup...\n");
    fflush(stdout);
    
    // Warmup
    for (i = 0; i < WARMUP_ITERATIONS; i++) {
        if (write(sock, send_buf, MSG_SIZE) != MSG_SIZE) {
            fprintf(stderr, "Warmup write failed\n");
            goto cleanup;
        }
        
        size_t total_read = 0;
        while (total_read < MSG_SIZE) {
            ssize_t n = read(sock, recv_buf + total_read, MSG_SIZE - total_read);
            if (n <= 0) {
                fprintf(stderr, "Warmup read failed\n");
                goto cleanup;
            }
            total_read += n;
        }
    }
    
    printf("# Running %d iterations...\n", NUM_ITERATIONS);
    fflush(stdout);
    
    // Run test
    for (i = 0; i < NUM_ITERATIONS; i++) {
        start_time = get_time_us();
        
        if (write(sock, send_buf, MSG_SIZE) != MSG_SIZE) {
            fprintf(stderr, "Write failed at iteration %d\n", i);
            goto cleanup;
        }
        
        size_t total_read = 0;
        while (total_read < MSG_SIZE) {
            ssize_t n = read(sock, recv_buf + total_read, MSG_SIZE - total_read);
            if (n <= 0) {
                fprintf(stderr, "Read failed at iteration %d\n", i);
                goto cleanup;
            }
            total_read += n;
        }
        
        end_time = get_time_us();
        rtt_times[i] = end_time - start_time;
        
        // Progress indicator
        if ((i + 1) % 1000 == 0) {
            printf("# Completed %d iterations...\n", i + 1);
            fflush(stdout);
        }
    }
    
    // Sort RTT times for percentile calculation
    qsort(rtt_times, NUM_ITERATIONS, sizeof(long long), compare_long);
    
    // Calculate percentiles
    double p50 = calculate_percentile(rtt_times, NUM_ITERATIONS, 50.0);
    double p95 = calculate_percentile(rtt_times, NUM_ITERATIONS, 95.0);
    double p99 = calculate_percentile(rtt_times, NUM_ITERATIONS, 99.0);
    
    // Calculate average
    long long total = 0;
    for (i = 0; i < NUM_ITERATIONS; i++) {
        total += rtt_times[i];
    }
    double avg = (double)total / NUM_ITERATIONS;
    
    printf("\n# Results\n");
    printf("p50_us,p95_us,p99_us,avg_us,min_us,max_us\n");
    printf("%.2f,%.2f,%.2f,%.2f,%lld,%lld\n", 
           p50, p95, p99, avg, rtt_times[0], rtt_times[NUM_ITERATIONS - 1]);
    fflush(stdout);
    
cleanup:
    close(sock);
    free(rtt_times);
    return 0;
}
