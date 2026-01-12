// SPDX-License-Identifier: MPL-2.0
/*
 * FrameVsock Client (Host side)
 *
 * This program connects to FrameVM (Guest) and exchanges data.
 * It acts as a client connecting to the vsock_echo_server running in Guest.
 *
 * Guest CID: 3 (VMADDR_CID_GUEST)
 * Guest Port: 12345
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>

#include <stdint.h>
#include <inttypes.h>

// Definition for AF_FRAMEVSOCK if not in system headers
#ifndef AF_FRAMEVSOCK
#define AF_FRAMEVSOCK 46
#endif

// Definition for sockaddr_vm if not in system headers
#ifndef VMADDR_CID_GUEST
#define VMADDR_CID_GUEST 3
#endif

struct sockaddr_framevsock {
    unsigned short svm_family;
    unsigned short svm_reserved1;
    unsigned int svm_port;
    uint64_t svm_cid;
    unsigned char svm_zero[sizeof(struct sockaddr) -
                           sizeof(unsigned short) * 2 -
                           sizeof(unsigned int) -
                           sizeof(uint64_t)];
};

#define TEST_PORT 12345
#define TEST_MSG "Hello from Host User Space!"

int main() {
    int fd;
    struct sockaddr_framevsock addr;
    char buffer[256];
    int ret;

    printf("[Host Client] Creating socket...\n");
    fd = socket(AF_FRAMEVSOCK, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("[Host Client] socket failed");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.svm_family = AF_FRAMEVSOCK;
    addr.svm_cid = VMADDR_CID_GUEST;
    addr.svm_port = TEST_PORT;

    printf("[Host Client] Connecting to Guest (CID=%" PRIu64 ", Port=%u)...\n", 
           addr.svm_cid, addr.svm_port);
    
    // Connect to Guest
    ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        perror("[Host Client] connect failed");
        close(fd);
        return 1;
    }
    printf("[Host Client] Connected!\n");

    // Send data
    printf("[Host Client] Sending: %s\n", TEST_MSG);
    ret = send(fd, TEST_MSG, strlen(TEST_MSG), 0);
    if (ret < 0) {
        perror("[Host Client] send failed");
        close(fd);
        return 1;
    }
    printf("[Host Client] Sent %d bytes\n", ret);

    // Receive echo
    printf("[Host Client] Waiting for echo...\n");
    memset(buffer, 0, sizeof(buffer));
    ret = recv(fd, buffer, sizeof(buffer) - 1, 0);
    if (ret < 0) {
        perror("[Host Client] recv failed");
        close(fd);
        return 1;
    }
    printf("[Host Client] Received %d bytes: %s\n", ret, buffer);

    if (strcmp(buffer, TEST_MSG) == 0) {
        printf("[Host Client] SUCCESS: Echo matches sent data!\n");
    } else {
        printf("[Host Client] FAILURE: Echo mismatch!\n");
    }

    close(fd);
    return 0;
}

