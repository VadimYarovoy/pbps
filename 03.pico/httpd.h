#ifndef _HTTPD_H___
#define _HTTPD_H___

#include <string.h>
#include <stdio.h>

// Server control
void serve_forever(const char *PORT);

// Client request
extern char *method, *uri, *qs, *prot;
extern char *payload;
extern int payload_size;

char *request_header(const char* name);
void route();

// Macros
#define ROUTE_START()       if (0) {
#define ROUTE(METHOD,URI)   } else if (strcmp(URI,uri)==0&&strcmp(METHOD,method)==0) {
#define ROUTE_GET(URI)      ROUTE("GET", URI)
#define ROUTE_POST(URI)     ROUTE("POST", URI)
#define ROUTE_END()         } else printf("HTTP/1.1 500 Not Handled\r\n\r\n");

#endif
