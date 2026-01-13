// SPDX-License-Identifier: MPL-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <errno.h>

#define VSOCK_PORT 9002
#define BUFFER_SIZE 4096

int main() {
    int listen_fd, conn_fd;
    struct sockaddr_vm sa_listen, sa_client;
    socklen_t client_len = sizeof(sa_client);
    char buffer[BUFFER_SIZE];

    // Create vsock socket
    listen_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }

    // Bind to any CID on port 9002
    memset(&sa_listen, 0, sizeof(sa_listen));
    sa_listen.svm_family = AF_VSOCK;
    sa_listen.svm_cid = VMADDR_CID_ANY;
    sa_listen.svm_port = VSOCK_PORT;

    if (bind(listen_fd, (struct sockaddr*)&sa_listen, sizeof(sa_listen)) != 0) {
        perror("bind");
        close(listen_fd);
        return 1;
    }

    if (listen(listen_fd, 1) != 0) {
        perror("listen");
        close(listen_fd);
        return 1;
    }

    printf("VSOCK Latency Server listening on port %d...\n", VSOCK_PORT);
    fflush(stdout);

    while(1) {
        conn_fd = accept(listen_fd, (struct sockaddr*)&sa_client, &client_len);
        if (conn_fd < 0) {
            perror("accept");
            continue;
        }
        
        printf("Client connected from CID %u\n", sa_client.svm_cid);
        fflush(stdout);

        // Echo small messages back immediately
        ssize_t n;
        while ((n = read(conn_fd, buffer, BUFFER_SIZE)) > 0) {
            ssize_t total_written = 0;
            while (total_written < n) {
                ssize_t written = write(conn_fd, buffer + total_written, n - total_written);
                if (written < 0) {
                    if (errno == EINTR) continue;
                    perror("write");
                    goto close_conn;
                }
                total_written += written;
            }
        }
        
        if (n < 0) {
            perror("read");
        }

close_conn:
        close(conn_fd);
        printf("Client disconnected\n");
        fflush(stdout);
    }

    close(listen_fd);
    return 0;
}
