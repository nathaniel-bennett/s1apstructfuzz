#include <stdio.h>
#include <dirent.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "s1apstructured.h"

#define MAX_FUZZ_LENGTH 100000
#define NET_PORT 36412
#define NET_IP "10.140.96.10"

#define GENERAL_TIMEOUT_MS 4000

int test_one(char *filename);


int main (int argc, char *argv[]) {
    struct dirent *p_dirent;
    DIR *p_dir;
    int ret;

    char *directory;

    time_t raw_time;
    struct tm* time_info;
    char str_time[32];

    if (argc != 2) {
        printf("Usage: test_crashes <directory containing crashing seeds>\n");
        return 1;
    }

	sigset_t block_signals, old_set;
	sigemptyset(&block_signals);
	sigaddset(&block_signals, SIGPIPE); // Set SIGPIPE as the only blocked signal
	pthread_sigmask(SIG_BLOCK, &block_signals, &old_set);

    directory = argv[1];
    p_dir = opendir (argv[1]);
    if (p_dir == NULL) {
        printf("Cannot open directory '%s'\n", argv[1]);
        return 1;
    }


    int crashes_fd = open("crashes.txt", O_WRONLY | O_CREAT, S_IRWXU);
     if (crashes_fd < 0) {
        printf("Failed to open \"crashes.txt\" to write to: error %i, %s\n", errno, strerror(errno));
        exit(1);
    }

    struct sockaddr_in serv_addr;

    memset(&serv_addr, '0', sizeof(struct sockaddr_in));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(NET_PORT);
    serv_addr.sin_addr.s_addr = inet_addr(NET_IP);

    while ((p_dirent = readdir(p_dir)) != NULL) {
        char *filename = p_dirent->d_name;
        if (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0) {
            continue;
        }

        printf("Testing file: [%s]\n", filename);
        
        char filepath[1000];
        snprintf(filepath, 999, "%s/%s", directory, filename);
        int file_fd = open(filepath, O_RDONLY);
         if (file_fd < 0) {
            printf("Failed to open file: error %i, %s\n", errno, strerror(errno));
            close(crashes_fd);
            exit(1);
        }
        
        char unstructured_buf[MAX_FUZZ_LENGTH];
        int unstructured_len = 0;

        do {
            ret = read(file_fd, &unstructured_buf[unstructured_len], MAX_FUZZ_LENGTH - unstructured_len);
            if (ret < 0) {
                printf("Failed to read file: error %i, %s\n", errno, strerror(errno));
                close(crashes_fd);
                exit(1);
            } else if (ret == 0) {
                break;
            } else {
                unstructured_len += ret;
            }
        } while (unstructured_len < MAX_FUZZ_LENGTH);
    
        char fuzzing_buf[MAX_FUZZ_LENGTH];
        long fuzzing_len;

        fuzzing_len = s1ap_arbitrary_to_structured(unstructured_buf, unstructured_len, fuzzing_buf, MAX_FUZZ_LENGTH);
        if (fuzzing_len < 0) {
            printf("WARNING: input failed to correctly convert to structured output. Skipping...\n");
            continue;
        }

retry_connection:

        int canary_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_SCTP);
        if (canary_fd < 0) {
            printf("Failed to open first SCTP socket: error %i, %s\n", errno, strerror(errno));
            close(crashes_fd);
            exit(1);
        }
        
        ret = connect(canary_fd, (struct sockaddr*) &serv_addr, sizeof(serv_addr));
        if (ret < 0 && (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINPROGRESS)) {
            struct pollfd pfd[1];
            pfd[0].fd = canary_fd;
            pfd[0].events = POLLOUT;
            int rv = poll(pfd, 1, GENERAL_TIMEOUT_MS);
            if (rv <= 0) {
                printf("Failed to connect first (canary) SCTP socket after timeout: error %i, %s\n", errno, strerror(errno));
                printf("Sleeping 15 seconds and retrying...\n");
                close(canary_fd);
                sleep(15);
                goto retry_connection;
            } else {
                ret = connect(canary_fd, (struct sockaddr*) &serv_addr, sizeof(serv_addr));
            }
        }
        else if (ret < 0) {
            printf("Failed to connect first (canary) SCTP socket: error %i, %s\n", errno, strerror(errno));
            printf("Sleeping 15 seconds and retrying...\n");
            close(canary_fd);
            sleep(15);
            goto retry_connection;
        }

        int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
        if (fd < 0) {
            printf("Failed to open first SCTP socket: error %i, %s\n", errno, strerror(errno));
            close(crashes_fd);
            exit(1);
        }
        
        ret = connect(fd, (struct sockaddr*) &serv_addr, sizeof(serv_addr));
        if (ret < 0 && (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINPROGRESS)) {
            struct pollfd pfd[1];
            pfd[0].fd = fd;
            pfd[0].events = POLLOUT;
            int rv = poll(pfd, 1, GENERAL_TIMEOUT_MS);
            if (rv <= 0) {
                printf("Failed to connect second (fuzzing) SCTP socket after timeout: error %i, %s\n", errno, strerror(errno));
                printf("Sleeping 15 seconds and retrying...\n");
                close(canary_fd);
                close(fd);
                sleep(15);
                goto retry_connection;
            } else {
                ret = connect(fd, (struct sockaddr*) &serv_addr, sizeof(serv_addr));
            }
        }
        if (ret < 0) {
            printf("Failed to connect second (fuzzing) SCTP socket: error %i, %s\n", errno, strerror(errno));
            printf("Sleeping 15 seconds and retrying...\n");
            close(canary_fd);
            close(fd);
            sleep(15);
            goto retry_connection;
        }

        // TAMU eNB-ID/PLMN
        unsigned char s1_setup_request_bytes[] = "\x00\x11\x00\x2d\x00\x00\x04\x00\x3b\x00\x08\x00\x13\x05\x01\x00" \
                                                 "\x00\x19\xb0\x00\x3c\x40\x0a\x03\x80\x73\x72\x73\x65\x6e\x62\x30" \
                                                 "\x31\x00\x40\x00\x07\x00\x00\x01\xc0\x13\x05\x01\x00\x89\x40\x01\x40";
        
        ret = write(fd, s1_setup_request_bytes, sizeof(s1_setup_request_bytes));
        if (ret < 0) {
            printf("Failed to write S1Setup request: error %i, %s\n", errno, strerror(errno));
            printf("Sleeping 15 seconds and retrying...\n");
            close(canary_fd);
            close(fd);
            sleep(15);
            goto retry_connection;
        }


        struct pollfd pfd[1];
        pfd[0].fd = fd;
        pfd[0].events = POLLIN;
        int rv = poll(pfd, 1, GENERAL_TIMEOUT_MS);
        if (rv <= 0) {
            printf("Failed to read S1Setup response after timeout: error %i, %s\n", errno, strerror(errno));
            printf("Sleeping 15 seconds and retrying...\n");
            close(canary_fd);
            close(fd);
            sleep(15);
            goto retry_connection;
        }
        
        char resp[4096];
        ret = read(fd, resp, 4096);
        if (ret < 0) {
            printf("Failed to read S1Setup response: error %i, %s\n", errno, strerror(errno));
            printf("Sleeping 15 seconds and retrying...\n");
            close(canary_fd);
            close(fd);
            sleep(15);
            goto retry_connection;
        }

        ret = write(fd, fuzzing_buf, fuzzing_len);
        if (ret < 0) {
            printf("Failed to write fuzzing data: error %i, %s\n", errno, strerror(errno));
            printf("Sleeping 15 seconds and retrying...\n");
            close(canary_fd);
            close(fd);
            sleep(15);
            goto retry_connection;
        } else if (ret == 0) {
	    printf("Write unexpectedly encountered closed connection\n");
            printf("Sleeping 15 seconds and retrying...\n");
	    close(canary_fd);
	    close(fd);
	    sleep(15);
	    goto retry_connection;
	}

        pfd[0].fd = fd;
        pfd[0].events = POLLIN;
        rv = poll(pfd, 1, GENERAL_TIMEOUT_MS);
        if (rv < 0) {
            printf("Warning: polling failed: error %i, %s\n", errno, strerror(errno));
            close(crashes_fd);
            exit(1);
        } else if (rv == 0) {
            printf("Fuzzing response timed out--could indicate crash...\n");   
        } else {
            ret = recv(fd, resp, 4096, MSG_DONTWAIT);
            if (ret < 0) {
                printf("Failed to read fuzzing response: error %i, %s\n", errno, strerror(errno));
                close(canary_fd);
                close(fd);
            } else if (ret == 0) {
                printf("Socket unexpectedly closed after writing fuzzing data\n");
            }
        }
        
        close(fd);
        
        ret = write(canary_fd, s1_setup_request_bytes, sizeof(s1_setup_request_bytes));
        if (ret < 0) {
            printf("Failed to write canary S1Setup request: error %i, %s\n", errno, strerror(errno));
            close(canary_fd);
            goto record_crash;
        } else if (ret == 0) {
	    printf("Canary unexpectedly closed connection before S1Setup could be written\n");
	}
 

        pfd[0].fd = canary_fd;
        pfd[0].events = POLLIN;
        rv = poll(pfd, 1, GENERAL_TIMEOUT_MS);
        if (rv < 0) {
            printf("Warning: canary polling failed: error %i, %s\n", errno, strerror(errno));
            close(crashes_fd);
            exit(1);
        } else if (rv == 0) {
            printf("Canary response timed out--assuming crash\n");
            goto record_crash;
        } else {
            ret = recv(canary_fd, resp, 4096, MSG_DONTWAIT);
            if (ret < 0) {
                printf("Failed to read canary response: error %i, %s\n", errno, strerror(errno));
                close(canary_fd);
		goto record_crash;
            } else if (ret == 0) {
                printf("Socket unexpectedly closed after writing fuzzing data\n");
		close(canary_fd);
		goto record_crash;
            }
        }

	printf("Canary indicated no crash--continuing on.\n");

        close(canary_fd);
        continue;
record_crash:
        time(&raw_time);
        time_info = localtime(&raw_time);
        strftime(str_time,32,"%G-%m-%d_%H:%M:%S",time_info);
        
        printf("Recording crash...\n");
        write(crashes_fd, str_time, strlen(str_time));
        write(crashes_fd, ",", 1);
        write(crashes_fd, filename, strlen(filename));
        write(crashes_fd, "\n", 1);

        sleep(20);
    }

    // Close directory and exit.
    
    closedir (p_dir);
    close(crashes_fd);
    return 0;
}
