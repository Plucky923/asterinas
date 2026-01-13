/*
 * syscalls.h - Minimal Freestanding C Syscall wrappers for x86_64
 *
 * This header allows writing C code that compiles to pure assembly-like
 * binaries without any C Runtime (CRT) dependencies.
 */

#ifndef _SYSCALLS_H
#define _SYSCALLS_H

// Basic types
typedef unsigned long size_t;
typedef long ssize_t;
typedef unsigned long uint64_t;
typedef long int64_t;
typedef unsigned int uint32_t;
typedef int int32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;

#define NULL ((void*)0)

// Constants
#define AF_FRAMEVSOCK   46
#define SOCK_STREAM     1
#define SOCK_NONBLOCK   0x800

#define VMADDR_CID_ANY  ((uint64_t)-1)
#define VMADDR_CID_HOST 2

#define CLOCK_MONOTONIC 1

// Syscall Numbers (x86_64)
#define SYS_READ            0
#define SYS_WRITE           1
#define SYS_CLOSE           3
#define SYS_NMAMP           9  // Defined but we try to avoid it
#define SYS_SOCKET          41
#define SYS_CONNECT         42
#define SYS_ACCEPT          43
#define SYS_SENDTO          44
#define SYS_RECVFROM        45
#define SYS_BIND            49
#define SYS_LISTEN          50
#define SYS_EXIT            60
#define SYS_CLOCK_GETTIME   228
#define SYS_NANOSLEEP       35

// Structures
// Note: svm_cid must be uint64_t to match kernel's CSocketAddrFrameVsock
struct sockaddr_vm {
    uint16_t svm_family;
    uint16_t svm_reserved1;
    uint32_t svm_port;
    uint64_t svm_cid;  // 64-bit CID to match kernel definition
};

struct timespec {
    int64_t tv_sec;
    int64_t tv_nsec;
};

// Syscall wrappers using inline assembly
static inline long syscall1(long n, long a1) {
    long ret;
    asm volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall2(long n, long a1, long a2) {
    long ret;
    asm volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2) : "rcx", "r11", "memory");
    return ret;
}

static inline long syscall3(long n, long a1, long a2, long a3) {
    long ret;
    asm volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory");
    return ret;
}

// Used for sendto/recvfrom which take 6 arguments
static inline long syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
    long ret;
    register long r10 asm("r10") = a4;
    register long r8 asm("r8") = a5;
    register long r9 asm("r9") = a6;
    asm volatile ("syscall" 
        : "=a"(ret) 
        : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9) 
        : "rcx", "r11", "memory");
    return ret;
}

// Helper functions wrappers
static inline void sys_exit(int status) {
    syscall1(SYS_EXIT, status);
    __builtin_unreachable();
}

static inline ssize_t sys_write(int fd, const void *buf, size_t count) {
    return syscall3(SYS_WRITE, fd, (long)buf, count);
}

static inline ssize_t sys_read(int fd, void *buf, size_t count) {
    return syscall3(SYS_READ, fd, (long)buf, count);
}

static inline int sys_close(int fd) {
    return (int)syscall1(SYS_CLOSE, fd);
}

static inline int sys_socket(int domain, int type, int protocol) {
    return (int)syscall3(SYS_SOCKET, domain, type, protocol);
}

static inline int sys_connect(int sockfd, const struct sockaddr_vm *addr, int addrlen) {
    return (int)syscall3(SYS_CONNECT, sockfd, (long)addr, addrlen);
}

static inline int sys_bind(int sockfd, const struct sockaddr_vm *addr, int addrlen) {
    return (int)syscall3(SYS_BIND, sockfd, (long)addr, addrlen);
}

static inline int sys_listen(int sockfd, int backlog) {
    return (int)syscall2(SYS_LISTEN, sockfd, backlog);
}

static inline int sys_accept(int sockfd, struct sockaddr_vm *addr, int *addrlen) {
    return (int)syscall3(SYS_ACCEPT, sockfd, (long)addr, (long)addrlen);
}

static inline ssize_t sys_sendto(int sockfd, const void *buf, size_t len, int flags) {
    // dest_addr and addrlen are NULL/0
    return syscall6(SYS_SENDTO, sockfd, (long)buf, len, flags, 0, 0);
}

static inline ssize_t sys_recvfrom(int sockfd, void *buf, size_t len, int flags) {
    // src_addr and addrlen are NULL/0
    return syscall6(SYS_RECVFROM, sockfd, (long)buf, len, flags, 0, 0);
}

static inline int sys_clock_gettime(int clk_id, struct timespec *tp) {
    return (int)syscall2(SYS_CLOCK_GETTIME, clk_id, (long)tp);
}

static inline int sys_nanosleep(const struct timespec *req, struct timespec *rem) {
    return (int)syscall2(SYS_NANOSLEEP, (long)req, (long)rem);
}

// Minimal utility functions
static inline size_t strlen(const char *s) {
    const char *p = s;
    while (*p) p++;
    return p - s;
}

static inline void print(const char *s) {
    sys_write(1, s, strlen(s));
}

static inline void reverse(char *s, int len) {
    for (int i = 0; i < len / 2; i++) {
        char temp = s[i];
        s[i] = s[len - 1 - i];
        s[len - 1 - i] = temp;
    }
}

static inline void itoa(uint64_t n, char *buf) {
    int i = 0;
    if (n == 0) {
        buf[i++] = '0';
    } else {
        uint64_t temp = n;
        while (temp > 0) {
            buf[i++] = (temp % 10) + '0';
            temp /= 10;
        }
    }
    buf[i] = '\0';
    reverse(buf, i);
}

static inline void print_number(uint64_t n) {
    char buf[32];
    itoa(n, buf);
    print(buf);
}

static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    sys_clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static inline void sleep_ms(uint64_t ms) {
    struct timespec req;
    req.tv_sec = ms / 1000;
    req.tv_nsec = (ms % 1000) * 1000000;
    sys_nanosleep(&req, NULL);
}

#endif // _SYSCALLS_H
