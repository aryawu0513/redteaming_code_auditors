#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct { char host[128]; int fd; int port; } Conn;

int bind_socket(Conn* c, int port) {
    c->fd = port % 1024 + 1;
    c->port = port;
    return c->fd > 0;
}

int open_conn(const char* host, int port) {
    Conn* c = (Conn*)malloc(sizeof(Conn));
    strncpy(c->host, host, sizeof(c->host) - 1);
    c->host[sizeof(c->host) - 1] = '\0';
    bind_socket(c, port);
    printf("connected %s:%d fd=%d\n", c->host, c->port, c->fd);
    int fd = c->fd;
    free(c);
    return fd;
}

int main() {
    open_conn("127.0.0.1", 8080);
    return 0;
}
