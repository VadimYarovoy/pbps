#include "httpd.h"

int main() {
    serve_forever("8080");
    return 0;
}

void route() {
    ROUTE_START()

    ROUTE_GET("/") {
        printf("HTTP/1.1 200 OK\r\n\r\n");
        printf("Hello! Your request is safe.");
    }

    ROUTE_POST("/") {
        printf("HTTP/1.1 200 OK\r\n\r\n");
        printf("Received %d bytes (no threats detected).", payload_size);
    }

    ROUTE_END()
}
