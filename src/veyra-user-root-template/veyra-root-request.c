#define _GNU_SOURCE

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define BROKER_FD 3
#define REQUEST_PACKET "ROOTREQ1"
#define RESPONSE_TIMEOUT_SECONDS 3600

static int wait_for(int fd, short events, int timeout_ms) {
    struct pollfd descriptor = { .fd = fd, .events = events };
    int result;
    do {
        result = poll(&descriptor, 1U, timeout_ms);
    } while (result < 0 && errno == EINTR);
    if (result <= 0) {
        if (result == 0)
            errno = ETIMEDOUT;
        return -1;
    }
    if ((descriptor.revents & events) != 0)
        return 0;
    if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
        errno = EPIPE;
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1) {
        fprintf(stderr, "Usage: veyra-root-request\n");
        return 2;
    }

    int socket_type = 0;
    socklen_t socket_type_length = sizeof(socket_type);
    struct sockaddr_storage peer_address;
    socklen_t peer_address_length = sizeof(peer_address);
    if (getsockopt(BROKER_FD, SOL_SOCKET, SO_TYPE, &socket_type,
                   &socket_type_length) < 0) {
        fprintf(stderr, "veyra-root-request: managed session control is unavailable: %s\n",
                strerror(errno));
        return 1;
    }
    if (socket_type != SOCK_SEQPACKET) {
        fprintf(stderr, "veyra-root-request: managed session control is unavailable\n");
        return 1;
    }
    if (getpeername(BROKER_FD, (struct sockaddr *)&peer_address,
                    &peer_address_length) < 0 ||
        peer_address.ss_family != AF_UNIX) {
        fprintf(stderr, "veyra-root-request: the session control channel is not connected\n");
        return 1;
    }

    if (wait_for(BROKER_FD, POLLOUT, 5000) < 0) {
        fprintf(stderr, "veyra-root-request: system broker is unavailable\n");
        return 1;
    }
    const ssize_t sent = send(BROKER_FD, REQUEST_PACKET,
                              sizeof(REQUEST_PACKET) - 1U, MSG_NOSIGNAL);
    if (sent != (ssize_t)(sizeof(REQUEST_PACKET) - 1U)) {
        fprintf(stderr, "veyra-root-request: request could not be sent\n");
        return 1;
    }

    if (wait_for(BROKER_FD, POLLIN,
                 RESPONSE_TIMEOUT_SECONDS * 1000) < 0) {
        fprintf(stderr, "veyra-root-request: system broker did not respond\n");
        return 1;
    }
    char response[128];
    const ssize_t received = recv(BROKER_FD, response, sizeof(response), 0);
    if (received <= 0 || (size_t)received >= sizeof(response)) {
        fprintf(stderr, "veyra-root-request: invalid broker response\n");
        return 1;
    }
    response[received] = '\0';
    if (strcmp(response, "OK") == 0) {
        puts("System administrator console closed.");
        return 0;
    }
    if (strcmp(response, "DENIED") == 0) {
        fprintf(stderr, "veyra-root-request: this system account is not authorized\n");
        return 1;
    }
    if (strcmp(response, "BUSY") == 0) {
        fprintf(stderr, "veyra-root-request: the system administrator console is busy\n");
        return 1;
    }
    if (strcmp(response, "UNAVAILABLE") == 0) {
        fprintf(stderr, "veyra-root-request: no trusted local system console is available\n");
        return 1;
    }
    fprintf(stderr, "veyra-root-request: system broker rejected the request\n");
    return 1;
}
