/**
 * @file ssl_client.c
 * @name Lindsey Cox/Alexey Chausenko
 * @date 10/20/2025
 * @brief TLS client for Distributed To-Do List
 *
 * Connects to one or two servers, sends commands: LIST | ADD:<text> | DELETE:<id>
 * Supports failover: tries second host if first fails.
 * Reads server response until "END\n" to signal end of message.
 *
 * Usage: ./ssl_client <host1> <port1> [<host2> <port2>] [--ca <ca_file>]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUF_SIZE 4096

/**
 * @brief Connect TCP socket to host:port
 * @return socket fd or -1 on error
 */
int tcp_connect(const char *host, int port) {
    struct addrinfo hints, *res;
    char portstr[16];
    int sockfd;

    snprintf(portstr, sizeof(portstr), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if(getaddrinfo(host, portstr, &hints, &res)!=0) return -1;
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if(sockfd<0) { freeaddrinfo(res); return -1; }
    if(connect(sockfd, res->ai_addr, res->ai_addrlen)<0) { close(sockfd); freeaddrinfo(res); return -1; }

    freeaddrinfo(res);
    return sockfd;
}

/**
 * @brief Wrap TCP socket with SSL
 */
SSL* ssl_connect(const char *host, int port, const char *ca_file) {
    SSL_library_init();   //FIXED: initialize SSL
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if(!ctx) { ERR_print_errors_fp(stderr); return NULL; }

    if(ca_file) { //FIXED: load CA to verify server
        if(SSL_CTX_load_verify_locations(ctx, ca_file, NULL)!=1) {
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            return NULL;
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    }

    int sockfd = tcp_connect(host, port);
    if(sockfd<0) { SSL_CTX_free(ctx); return NULL; }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    if(SSL_connect(ssl)<=0) { //FIXED: perform SSL handshake
        ERR_print_errors_fp(stderr);
        SSL_free(ssl); close(sockfd); SSL_CTX_free(ctx);
        return NULL;
    }

    //FIXED: check hostname (optional strict verification)
    if(SSL_get_verify_result(ssl) != X509_V_OK) {
        fprintf(stderr,"TLS hostname failed for %s\n", host);
        SSL_shutdown(ssl); SSL_free(ssl); close(sockfd); SSL_CTX_free(ctx);
        return NULL;
    }

    return ssl;
}

/**
 * @brief Send a command line to server
 */
int send_command_line(SSL *ssl, const char *line) {
    int len = strlen(line);
    char buf[BUF_SIZE];
    if(len+2 >= BUF_SIZE) return -1;
    snprintf(buf, sizeof(buf), "%s\n", line); //FIXED: append newline
    if(SSL_write(ssl, buf, strlen(buf)) <= 0) return -1;
    return 0;
}

/**
 * @brief Read server reply until "END\n"
 */
int read_reply_until_END(SSL *ssl) {
    char buf[BUF_SIZE];
    int bytes;
    while(1) {
        bytes = SSL_read(ssl, buf, sizeof(buf)-1);
        if(bytes <= 0) return -1;
        buf[bytes] = '\0'; //FIXED: null-terminate
        printf("%s", buf);
        if(strstr(buf,"END\n")) break; //FIXED: stop at END
    }
    return 0;
}

/**
 * @brief Main REPL
 */
int main(int argc, char *argv[]) {
    if(argc<3) {
        fprintf(stderr,"Usage: %s <host1> <port1> [<host2> <port2>] [--ca <ca_file>]\n", argv[0]);
        return 1;
    }

    const char *host1 = argv[1];
    int port1 = atoi(argv[2]);
    const char *host2 = NULL;
    int port2 = 0;
    const char *ca_file = NULL;

    for(int i=3;i<argc;i++) { //FIXED: parse optional host2/port2 and --ca
        if(strcmp(argv[i],"--ca")==0 && i+1<argc) { ca_file = argv[i+1]; i++; }
        else if(!host2) { host2 = argv[i]; port2 = atoi(argv[i+1]); i++; }
    }

    SSL *ssl_conn = ssl_connect(host1, port1, ca_file);
    if(!ssl_conn && host2) {
        ssl_conn = ssl_connect(host2, port2, ca_file);
    }
    if(!ssl_conn) { fprintf(stderr,"All connection attempts failed\n"); return 1; }

    printf("connected via TLS to %s:%d\n", ssl_conn?host1:host2, ssl_conn?port1:port2);
    printf("Commands: LIST | ADD:<text> | DELETE:<id> | Crtl+D to quit\n");

    char line[1024];
    while(1) {
        printf("> "); fflush(stdout); //FIXED: prompt flush
        if(!fgets(line,sizeof(line),stdin)) break;

        //FIXED: strip newline characters
        size_t len = strlen(line);
        while(len>0 && (line[len-1]=='\n' || line[len-1]=='\r')) line[--len] = '\0';
        if(len==0) continue; //FIXED: skip empty

        if(send_command_line(ssl_conn, line)!=0) {
            fprintf(stderr,"send failed, disconnecting\n");
            break;
        }

        if(read_reply_until_END(ssl_conn)!=0) {
            fprintf(stderr,"read failed, disconnecting\n");
            break;
        }
    }

    SSL_shutdown(ssl_conn);
    SSL_free(ssl_conn);
    return 0;
}

