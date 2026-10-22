#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3 || argv[1][0] != '/' || argv[2][0] == '\0') {
        fprintf(stderr, "usage: veyra-qemu-tty-inject TTY TEXT\n");
        return 2;
    }
    const int tty_fd = open(argv[1], O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (tty_fd < 0) {
        perror("veyra-qemu-tty-inject: open TTY");
        return 1;
    }
    for (const unsigned char *cursor = (const unsigned char *)argv[2];
         *cursor != '\0'; cursor++) {
        char byte = (char)*cursor;
        if (ioctl(tty_fd, TIOCSTI, &byte) < 0) {
            perror("veyra-qemu-tty-inject: inject input");
            close(tty_fd);
            return 1;
        }
    }
    char newline = '\n';
    if (ioctl(tty_fd, TIOCSTI, &newline) < 0) {
        perror("veyra-qemu-tty-inject: inject newline");
        close(tty_fd);
        return 1;
    }
    close(tty_fd);
    return 0;
}
