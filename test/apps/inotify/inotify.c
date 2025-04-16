#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/inotify.h>
#include <string.h>
#include <sys/ioctl.h>

#define BUFFER_SIZE 1024
#define MAX_WATCHES 5

int main() {
    // Initialize inotify
    int inotify_fd = inotify_init();
    if (inotify_fd < 0) {
        perror("inotify_init failed");
        return 1;
    }
    printf("Created inotify instance with fd: %d\n", inotify_fd);

    // Create test files
    for (int i = 0; i < MAX_WATCHES; i++) {
        char filename[32];
        snprintf(filename, sizeof(filename), "test%d.txt", i);
        FILE *fp = fopen(filename, "w");
        if (fp) {
            fclose(fp);
        }
    }

    // Add watches for each test file
    int wds[MAX_WATCHES];
    for (int i = 0; i < MAX_WATCHES; i++) {
        char filename[32];
        snprintf(filename, sizeof(filename), "test%d.txt", i);
        wds[i] = inotify_add_watch(inotify_fd, filename, IN_ALL_EVENTS);
        if (wds[i] < 0) {
            perror("inotify_add_watch failed");
            close(inotify_fd);
            return 1;
        }
        printf("Watch descriptor for %s: %d\n", filename, wds[i]);
    }

    // Test adding watch to the same file
    printf("\nTesting adding watch to the same file:\n");
    char filename[32];
    snprintf(filename, sizeof(filename), "test0.txt");
    int wd = inotify_add_watch(inotify_fd, filename, IN_ALL_EVENTS);
    if (wd < 0) {
        perror("inotify_add_watch failed for same file");
    } else {
        printf("Watch descriptor for same file %s: %d\n", filename, wd);
        // Remove the duplicate watch
        if (inotify_rm_watch(inotify_fd, wd) < 0) {
            perror("inotify_rm_watch failed for duplicate watch");
        }
    }

    // Generate some events by modifying files
    printf("\nGenerating events by modifying files:\n");
    for (int i = 0; i < MAX_WATCHES; i++) {
        char filename[32];
        snprintf(filename, sizeof(filename), "test%d.txt", i);
        
        // Write to file
        FILE *fp = fopen(filename, "w");
        if (fp) {
            fprintf(fp, "Test content %d\n", i);
            fclose(fp);
        }
        
        // Read from file
        fp = fopen(filename, "r");
        if (fp) {
            char buf[100];
            fgets(buf, sizeof(buf), fp);
            fclose(fp);
        }
    }

    // Check available data size using ioctl
    int available_bytes;
    if (ioctl(inotify_fd, FIONREAD, &available_bytes) < 0) {
        perror("ioctl FIONREAD failed");
    } else {
        printf("\nAvailable bytes to read: %d\n", available_bytes);
    }

    // Read and print events from inotify file descriptor
    printf("\nReading events from inotify fd %d:\n", inotify_fd);
    char buffer[BUFFER_SIZE];
    int length = read(inotify_fd, buffer, BUFFER_SIZE);
    if (length < 0) {
        perror("read failed");
    } else {
        printf("Read %d bytes from inotify fd\n", length);
        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *) &buffer[i];
            
            printf("Event detected:\n");
            printf("  Watch descriptor: %d\n", event->wd);
            printf("  Mask: 0x%x\n", event->mask);
            printf("  Cookie: %u\n", event->cookie);
            printf("  Length: %u\n", event->len);
            if (event->len > 0) {
                printf("  Name: %s\n", event->name);
            }
            
            // Move to next event
            i += sizeof(struct inotify_event) + event->len;
        }
    }

    // Remove all watches
    for (int i = 0; i < MAX_WATCHES; i++) {
        if (inotify_rm_watch(inotify_fd, wds[i]) < 0) {
            perror("inotify_rm_watch failed");
        }
    }

    // Clean up
    close(inotify_fd);
    for (int i = 0; i < MAX_WATCHES; i++) {
        char filename[32];
        snprintf(filename, sizeof(filename), "test%d.txt", i);
        unlink(filename);
    }
    return 0;
}
