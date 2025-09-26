/**
 * @file ssl_server.c
 * @name Lindsey Cox/Alexey Chausenko
 * @date 10/20/2025
 * @brief Distributed To-Do List Server with TLS, MySQL, and concurrent threads
 *
 * Listens on a configurable TCP port, accepts TLS connections from clients,
 * processes LIST, ADD, DELETE commands with MySQL backend.
 * Each client runs in a separate thread with its own database connection.
 * Responses are terminated with "END\n" to signal end of message.
 *
 * Supports multiple instances on different ports for failover (useful in Docker).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <mysql/mysql.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BACKLOG 10       ///max pending connections
#define BUF_SIZE 4096    ///buffer for client messages

//TLS certificate/key/CA paths
#define SERVER_CERT "server.crt"
#define SERVER_KEY  "server.key"
#define CA_CERT     "ca.crt"

//MySQL credentials (adjust to your Docker setup)
#define DB_HOST "todo_mysql"  ///use Docker service name if in same network
#define DB_USER "dbuser"
#define DB_PASS "dbpass"
#define DB_NAME "todo_db"

/**
 * @brief Holds context for each client thread
 * Includes SSL connection and MySQL connection
 */
typedef struct {
    SSL *ssl;       //TLS connection
    MYSQL *db_conn; //MySQL connection
} conn_ctx_t;

/**
 * @brief Send a string to client over TLS
 * @param ssl TLS connection
 * @param s Null-terminated string
 */
void send_str(SSL *ssl, const char *s) {
    SSL_write(ssl, s, strlen(s));
}

/**
 * @brief Thread to handle a single client connection
 * @param arg Pointer to conn_ctx_t
 *
 * Handles LIST, ADD:<task>, DELETE:<id> commands. Each response is terminated with "END\n".
 */
void *connection_thread(void *arg) {
    conn_ctx_t *ctx = (conn_ctx_t*)arg;
    SSL *ssl = ctx->ssl;
    MYSQL *db = ctx->db_conn;
    char buf[BUF_SIZE];
    int r;

    while(1) {
        memset(buf, 0, sizeof(buf));
        r = SSL_read(ssl, buf, sizeof(buf)-1);
        if(r <= 0) break;      //connection closed
        if(buf[r-1]=='\n') buf[r-1]=0; //remove newline

        //LIST command
        if(strncmp(buf,"LIST",4)==0) {
            if(db && mysql_query(db,"SELECT id, task FROM todo ORDER BY id;")==0) {
                MYSQL_RES *res = mysql_store_result(db);
                if(res) {
                    MYSQL_ROW row;
                    while((row=mysql_fetch_row(res))!=NULL) {
                        char line[1024];
                        snprintf(line,sizeof(line),"%s:%s\n", row[0], row[1]?row[1]:"");
                        send_str(ssl,line);
                    }
                    mysql_free_result(res);
                }
            }
            send_str(ssl,"END\n");
        }
        //ADD command with SQL escaping
        else if(strncmp(buf,"ADD:",4)==0) {
            char task[1024];
            unsigned long len = strlen(buf+4);
            mysql_real_escape_string(db, task, buf+4, len); //escape input for SQL safety

            char query[2048];
            snprintf(query,sizeof(query),"INSERT INTO todo (task) VALUES ('%s');", task);

            if(db && mysql_query(db,query)==0)
                send_str(ssl,"OK: added\nEND\n");
            else {
                char errbuf[512];
                snprintf(errbuf,sizeof(errbuf),"ERR: add failed: %s\nEND\n", mysql_error(db));
                send_str(ssl, errbuf);
            }
        }
        //DELETE command with basic validation
        else if(strncmp(buf,"DELETE:",7)==0) {
            char id[64];
            unsigned long len = strlen(buf+7);
            mysql_real_escape_string(db, id, buf+7, len); //escape input
            char query[256];
            snprintf(query,sizeof(query),"DELETE FROM todo WHERE id=%s;", id);

            if(db && mysql_query(db,query)==0)
                send_str(ssl,"OK: deleted\nEND\n");
            else {
                char errbuf[512];
                snprintf(errbuf,sizeof(errbuf),"ERR: delete failed: %s\nEND\n", mysql_error(db));
                send_str(ssl, errbuf);
            }
        }
        else {
            send_str(ssl,"ERR: unknown command\nEND\n");
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    if(db) mysql_close(db);
    free(ctx);
    pthread_exit(NULL);
}

/**
 * @brief Initialize SSL context for server
 * @param cert_file Server certificate
 * @param key_file Server private key
 * @param ca_file CA certificate for client verification
 * @return SSL_CTX pointer or NULL on failure
 */
SSL_CTX *create_server_ssl_ctx(const char *cert_file, const char *key_file, const char *ca_file) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if(!ctx) { ERR_print_errors_fp(stderr); return NULL; }

    if(SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM)<=0 ||
       SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM)<=0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if(ca_file) {
        if(SSL_CTX_load_verify_locations(ctx, ca_file, NULL)!=1) {
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            return NULL;
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); //server does not verify clients
    }
    return ctx;
}

/**
 * @brief Wrap TCP socket with TLS
 * @param ctx SSL context
 * @param sockfd TCP socket fd
 * @return SSL* object or NULL
 */
SSL *ssl_wrap_server(SSL_CTX *ctx, int sockfd) {
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    if(SSL_accept(ssl)<=0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }
    return ssl;
}

/**
 * @brief Create, bind, and listen on TCP socket
 * @param port Port number
 * @return socket fd or -1
 */
int create_bind_socket(int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM,0);
    if(sockfd<0){ perror("socket"); return -1; }

    int opt=1; setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr,0,sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if(bind(sockfd,(struct sockaddr*)&addr,sizeof(addr))<0) { perror("bind"); close(sockfd); return -1; }
    if(listen(sockfd,BACKLOG)<0) { perror("listen"); close(sockfd); return -1; }

    return sockfd;
}

/**
 * @brief Main server entry point
 * Usage: ./ssl_server [port]
 * Default port 8443. Can run multiple instances on different ports (for Docker failover).
 */
int main(int argc, char *argv[]) {
    int port = 8443; //default
    if(argc>1) port = atoi(argv[1]);

    SSL_CTX *ctx = create_server_ssl_ctx(SERVER_CERT,SERVER_KEY,CA_CERT);
    if(!ctx){ fprintf(stderr,"SSL context failed\n"); return 1; }

    int listenfd = create_bind_socket(port);
    if(listenfd<0) return 1;
    printf("Server listening on port %d\n", port);

    while(1) {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int clientfd = accept(listenfd,(struct sockaddr*)&client_addr,&len);
        if(clientfd<0){ perror("accept"); continue; }

        SSL *ssl = ssl_wrap_server(ctx,clientfd);
        if(!ssl){ close(clientfd); continue; }

        MYSQL *db_conn = mysql_init(NULL);
        if(mysql_real_connect(db_conn,DB_HOST,DB_USER,DB_PASS,DB_NAME,0,NULL,0)==NULL) {
            fprintf(stderr,"DB connect failed: %s\n", mysql_error(db_conn));
            mysql_close(db_conn); db_conn=NULL;
        }

        conn_ctx_t *ctxdata = malloc(sizeof(conn_ctx_t));
        ctxdata->ssl = ssl;
        ctxdata->db_conn = db_conn;

        pthread_t tid;
        if(pthread_create(&tid,NULL,connection_thread,ctxdata)!=0){
            perror("pthread_create");
            SSL_shutdown(ssl); SSL_free(ssl);
            if(db_conn) mysql_close(db_conn);
            free(ctxdata);
            continue;
        }
        pthread_detach(tid);
    }

    close(listenfd);
    SSL_CTX_free(ctx);
    return 0;
}

