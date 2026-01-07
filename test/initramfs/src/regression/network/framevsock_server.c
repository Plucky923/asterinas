// SPDX-License-Identifier: MPL-2.0
/*
 * FrameVsock Server (Host side)
 *
 * This program listens for connections from FrameVM (Guest).
 * It acts as a server waiting for connection from vsock_client running in Guest.
 *
 * Host CID: 2 (VMADDR_CID_HOST)
 * Host Port: 8080
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>

#ifndef AF_FRAMEVSOCK
#define AF_FRAMEVSOCK 46
#endif

#ifndef VMADDR_CID_HOST
#define VMADDR_CID_HOST 2
#endif

#ifndef VMADDR_CID_ANY
#define VMADDR_CID_ANY -1U
#endif

struct sockaddr_framevsock {
    unsigned short svm_family;
    unsigned short svm_reserved1;
    unsigned int svm_port;
    unsigned int svm_cid;
    unsigned char svm_zero[sizeof(struct sockaddr) -
                           sizeof(unsigned short) * 2 -
                           sizeof(unsigned int) * 2];
};

#define SERVER_PORT 8080

int main() {
    int listen_fd, client_fd;
    struct sockaddr_framevsock addr, client_addr;
    socklen_t client_len;
    char buffer[256];
    int ret;

    printf("[Host Server] Creating socket...\n");
    listen_fd = socket(AF_FRAMEVSOCK, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("[Host Server] socket failed");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.svm_family = AF_FRAMEVSOCK;
    addr.svm_cid = VMADDR_CID_HOST; // Bind to Host CID
    addr.svm_port = SERVER_PORT;

    printf("[Host Server] Binding to CID=%u, Port=%u...\n", addr.svm_cid, addr.svm_port);
    ret = bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        perror("[Host Server] bind failed");
        close(listen_fd);
        return 1;
    }

    printf("[Host Server] Listening...\n");
    ret = listen(listen_fd, 5);
    if (ret < 0) {
        perror("[Host Server] listen failed");
        close(listen_fd);
        return 1;
    }

    printf("[Host Server] Waiting for connection...\n");
    client_len = sizeof(client_addr);
    client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0) {
        perror("[Host Server] accept failed");
        close(listen_fd);
        return 1;
    }

    printf("[Host Server] Accepted connection from CID=%u, Port=%u\n",
           client_addr.svm_cid, client_addr.svm_port);

    // Echo loop
    while (1) {
        memset(buffer, 0, sizeof(buffer));
        ret = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
        if (ret < 0) {
            perror("[Host Server] recv failed");
            break;
        } else if (ret == 0) {
            printf("[Host Server] Client disconnected\n");
            break;
        }

        printf("[Host Server] Received %d bytes: %s\n", ret, buffer);

        printf("[Host Server] Echoing back...\n");
        ret = send(client_fd, buffer, ret, 0);
        if (ret < 0) {
            perror("[Host Server] send failed");
            break;
        }
    }

    close(client_fd);
    close(listen_fd);
    return 0;
}

