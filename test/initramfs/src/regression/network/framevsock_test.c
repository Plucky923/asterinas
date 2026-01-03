#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

#define AF_FRAMEVSOCK 46
#define VMADDR_CID_ANY UINT64_MAX
#define VMADDR_PORT_ANY UINT32_MAX

struct sockaddr_framevsock {
    unsigned short sa_family;
    unsigned short svm_reserved1;
    unsigned int svm_port;
    uint64_t svm_cid;
    unsigned char svm_zero[sizeof(struct sockaddr) -
                           sizeof(unsigned short) * 2 -
                           sizeof(unsigned int) -
                           sizeof(uint64_t)];
};

int main() {
    printf("[FrameVsock Test] Starting...\n");

    int fd = socket(AF_FRAMEVSOCK, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("[FrameVsock Test] socket failed");
        return 1;
    }
    printf("[FrameVsock Test] Socket created successfully, fd = %d\n", fd);

    struct sockaddr_framevsock addr;
    memset(&addr, 0, sizeof(addr));
    addr.sa_family = AF_FRAMEVSOCK;
    addr.svm_cid = VMADDR_CID_ANY;
    addr.svm_port = 12345;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[FrameVsock Test] bind failed");
        close(fd);
        return 1;
    }
    printf("[FrameVsock Test] Bind successful\n");

    if (listen(fd, 5) < 0) {
        perror("[FrameVsock Test] listen failed");
        close(fd);
        return 1;
    }
    printf("[FrameVsock Test] Listen successful\n");

    close(fd);
    printf("[FrameVsock Test] Finished successfully\n");
    return 0;
}

