#include "httpd.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>

#define CONNMAX 1000

static int listenfd, clients[CONNMAX];
static int clientfd;
static char *buf;

typedef struct { char *name, *value; } header_t;
static header_t reqhdr[17] = { {"\0", "\0"} };
char *method, *uri, *qs, *prot;
char *payload;
int payload_size;

static void error(char *);
static void startServer(const char *);
static void respond(int);
static void url_decode(char *src);
static int is_dangerous(const char *str);
static void send_forbidden(int client);

static void url_decode(char *src) {
    char *dst = src;
    while (*src) {
        if (*src == '%' && isxdigit(*(src+1)) && isxdigit(*(src+2))) {
            *dst = (char) strtol(src + 1, NULL, 16);
            dst++;
            src += 3;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

static int is_dangerous(const char *str) {
    const char *dangerous = ";|&`$()<>";
    return (strpbrk(str, dangerous) != NULL);
}

static void send_forbidden(int client) {
    const char *response =
        "HTTP/1.1 403 Forbidden\r\n"
        "Content-Type: text/plain\r\n"
        "Connection: close\r\n\r\n"
        "Command Injection attempt detected!";
    send(client, response, strlen(response), 0);
}

void serve_forever(const char *PORT) {
    struct sockaddr_in clientaddr;
    socklen_t addrlen;
    int slot = 0;

    printf("Server started \033[92mhttp://127.0.0.1:%s\033[0m\n", PORT);

    for (int i = 0; i < CONNMAX; i++) clients[i] = -1;
    startServer(PORT);

    signal(SIGCHLD, SIG_IGN);

    while (1) {
        addrlen = sizeof(clientaddr);
        clients[slot] = accept(listenfd, (struct sockaddr *)&clientaddr, &addrlen);

        if (clients[slot] < 0) {
            perror("accept() error");
        } else {
            if (fork() == 0) {
                respond(slot);
                exit(0);
            }
        }
        while (clients[slot] != -1) slot = (slot + 1) % CONNMAX;
    }
}

void startServer(const char *port) {
    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NULL, port, &hints, &res) != 0) {
        perror("getaddrinfo() error");
        exit(1);
    }

    for (p = res; p != NULL; p = p->ai_next) {
        int option = 1;
        listenfd = socket(p->ai_family, p->ai_socktype, 0);
        setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
        if (listenfd == -1) continue;
        if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0) break;
    }

    if (p == NULL) {
        perror("socket() or bind()");
        exit(1);
    }

    freeaddrinfo(res);
    if (listen(listenfd, 1000000) != 0) {
        perror("listen() error");
        exit(1);
    }
}

void respond(int n) {
    int rcvd;
    buf = malloc(65535);
    rcvd = recv(clients[n], buf, 65535, 0);

    if (rcvd < 0) {
        fprintf(stderr, "recv() error\n");
        goto cleanup;
    } else if (rcvd == 0) {
        fprintf(stderr, "Client disconnected unexpectedly.\n");
        goto cleanup;
    }

    buf[rcvd] = '\0';
    method = strtok(buf, " \t\r\n");
    uri = strtok(NULL, " \t");
    prot = strtok(NULL, " \t\r\n");

    qs = strchr(uri, '?');
    if (qs) {
        *qs++ = '\0';
    } else {
        qs = uri - 1;
    }

    url_decode(uri);
    if (qs != uri - 1) url_decode(qs);

    if (memchr(uri, '\0', strlen(uri))) {
        send_forbidden(clients[n]);
        goto cleanup;
    }

    if (is_dangerous(uri) || (qs != uri - 1 && is_dangerous(qs))) {
        send_forbidden(clients[n]);
        goto cleanup;
    }

    header_t *h = reqhdr;
    while (h < reqhdr + 16) {
        char *k = strtok(NULL, "\r\n: \t");
        if (!k) break;
        char *v = strtok(NULL, "\r\n");
        while (v && *v == ' ') v++;
        h->name = k;
        h->value = v;
        h++;
    }

    if (strcmp(method, "POST") == 0) {
        char *cl = request_header("Content-Length");
        payload_size = cl ? atoi(cl) : 0;
        payload = buf + (rcvd - payload_size);
        if (is_dangerous(payload)) {
            send_forbidden(clients[n]);
            goto cleanup;
        }
    }

    clientfd = clients[n];
    dup2(clientfd, STDOUT_FILENO);
    close(clientfd);
    route();
    fflush(stdout);
    shutdown(STDOUT_FILENO, SHUT_WR);

cleanup:
    free(buf);
    shutdown(clients[n], SHUT_RDWR);
    close(clients[n]);
    clients[n] = -1;
}

char *request_header(const char* name) {
    for (header_t *h = reqhdr; h->name; h++) {
        if (strcmp(h->name, name) == 0) return h->value;
    }
    return NULL;
}
