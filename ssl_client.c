/**
 * @file ssl_client.c
 * @name Lindsey Cox/Alexey Chausenko
 * @date 10/20/2025
 * @brief Distributed To-Do List Client with 
 *
 * The big picture is the Client opens a TCP socket, does the TCP handshake + cert verification,
 * sends one command per line, and reads until END. If the connection breaks, it can fail over
 * to a second host and retry
 */

#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/tls1.h>

#define RECV_BUFSZ 4096

/*************helpers for printing errors and exiting  *******************/
/**
 * @param format
 * @param ...
 * print a formatted message to stderr, add a newline, and terminate the process with exit code 1
 */

static void die(const char *format, ...)
{
    va_list varargs; //iterator object to walk through the "..." params
    va_start(varargs, format);
    vfprintf(stderr, format, varargs);
    fputc('\n', stderr);
    va_end(varargs);
    exit(1); //if we want the caller to decide what to do, can change to return -1;
}

/** 
 * @param prefix_message 
 * prints our message for the most recent OpenSSL failures, exits with 1
*/
static void openssl_die(const char *prefix_message)
{
    fprintf(stderr, "%s\n", prefix_message); //own context
    ERR_print_errors_fp(stderr); //dump OpenSSL's error queue
    exit(1);
}

/************ endpoint info for optional failover ************** */

typedef struct {
    const char *host;  // DNS name or IP
    const char *port;  // decimal string, e.g., "8443"
} endpoint_t;


/************* POSIX TCP connect (DNS -> socket -> connect)  *******************/
/**
 * @param host name of the host : 127.0.0.1 or myserver.com, etc
 * @param port connection port for the host : ex: 8443 
 * we have to parse through a linked list of addresses, because of failover strats
 * the list if a list of nodes, each desrcibing one possible socket address
 * 
 * Usage: int fd = tctp_connect("localhost", "8443"); -> on success fd is a valid TCP connection, -1 otherwise
 * 
 * @return socket_fd 
 */
static int tcp_connect(const char *host, const char *port)
{
    //addrinfo describes network endpoints
    struct addrinfo hints; //what kind of addresses we want
    struct addrinfo *addr_results = NULL; //list of all results, IPv4, IPv6, etc
    struct addrinfo *addr_iter = NULL; //loop pointer for trying each result
    int socket_fd = -1;
    int resolve_status; //will be a return code from getaddrinfo

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; //allow IPv4, IPv6, note ai stands for "address info"
    hints.ai_socktype = SOCK_STREAM; //TCP
    hints.ai_protocol = IPPROTO_TCP; //even more explicitly TCP

    //DNS resolution
    //take the host, port, apply the hints, and give back a linked list of possible network addresses
    resolve_status = getaddrinfo(host, port, &hints, &addr_results);
    if (resolve_status != 0)
    {
        fprintf(stderr, "getaddrinfo(%s:%s): %s\n",
            host, port, gai_strerror(resolve_status));
        return -1;
    }

    //loop through candidates
    for (addr_iter = addr_results; addr_iter != NULL;  addr_iter = addr_iter->ai_next) 
    {
        socket_fd = socket(addr_iter->ai_family, addr_iter->ai_socktype, addr_iter->ai_protocol);
        if (socket_fd == 1) continue; //couldn't create socket, try next
        if (connect(socket_fd, addr_iter->ai_addr, addr_iter-.ai_addrlen) == 0)
        {
            break; //success!
        }
        close(socket_fd); //failed connect, clean up
        socket_fd = -1;
    }

    freeaddrinfo(addr_results);
    return socket_fd; //-1 if nothing worked

}

/************* OpenSSL client context (CA verification enabled!)  *******************/
/**
 * @param ca_file_path the filename of our CA certificate to verify the server's cert chain
 * @return ssl_ctx pointer to an SSL_CTX
 * 
 * creates and configures the SSL_CTX object all the client-side TLS connections will share
 * kind of like a template; all teh rules, algs, and trust anchors the connections will inherit
 * 
 * Usage: SSL *ssl = SSL_new(ssl_ctx); --> holds a context for rules for every TLS connection
 */
static SSL_CTX* create_tls_client_context(const char *ca_file_path)
{
    //initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    //pick the TLS method
    const SSL_METHOD *tls_method = TLS_client_method(); //returns a method object that supports TLS 1.0 - 1.3
    SSL_CTX *ssl_ctx = SSL_CTX_new(tls_method); //allocate the context with that ^ method
    if (!ssl_ctx) openssl_die("SSL_CTX_new failed");

    //require certificate verification
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL); //tell OpenSSL we want to verify 
    SSL_CTX_set_verify_depth(ssl_ctx, 4); //control how deep our chains go

    //load the CA certificates
    if (ca_file_path) //user specified CA file -> load the trusted root from like a PEM file
    {
        if (SSL_CTX_load_verify_locations(ssl_ctx, ca_file_path, NULL) != 1)
        {
            openssl_die("Failed to load CA file(SSL_CTX_load_verify_locations)");
        } 
        else //fallback to sys defaults
        { //use the OS' built in trust store (/etc/ssl/certs on Linux I think)
            if (SSL_CTX_set_default_verify_paths(ssl_ctx) != 1)
            {
                openssl_die("No CA provided and no default verify paths");
            }
        }
    }

    return ssl_ctx;

}

/************* Hostname Verification helper *******************/
/**
 * @param ssl_conn  the live TLS connection obj created after handshake
 * @param expected_hostname the hostname we think we are connected to (but is it them????)
 * @return 1 (true) if the certificate matches the hostname, 0 if not
 * 
 * this ensures that the certificate isn't just validly signed, but also for this exact host
 */
static int verify_peer_hostname(SSL *ssl_conn, const char *expected_hostname)
{
    //get the peer certificate
    X509 *peer_cert = SSL_get_peer_certificate(ssl_conn);
    if (!peer_cert) return 0;
    int matches = (X509_check_host(peer_cert, expected_hostname, 0, 0, NULL) == 1);
    X509_free(peer_cert);
    return matches;
}

/************* TCP to TLS handshake step *******************/
/**
 * @param ssl_ctx a ssl context object
 * @param host hostname we want to connect to
 * @param port port num as string
 * @param out_socket_fd an optional return val where we can store the raw TCP socket fd if we so care
 * @return a pointer to a live TLS connection obj on success, NULL on failure
 * 
 * takes a plain TCP connection and upgrades it to the full TLS session
 * calls the tcp_connect, verify_peer_hostname
 */
static SSL* connect_tls(SSL_CTX *ssl_ctx, const char *host, const char *port, int *out_socket_fd)
{
    //establish TCP in the raw
    int socket_fd = tcp_connect(host, port);
    if (socket_fd < 0) return NULL;

    //create SSL object
    SSL *ssl = SSL_new(ssl_ctx);
    if (!ssl) 
    { 
        close(socket_fd); 
        openssl_die("SSL_new failed"); 
    }

    //set SNI so the server can present the correct cert for host
    //one port can host multiple TLS certs, this helps ensure the server does not present the wrong one
    if (SSL_set_tlsext_host_name(ssl, host) != 1)
    {
        fprintf(stderr, "warning: failed to set SNI for host '%s'\n", host);
    }

    //bind socket and perform handshake
    SSL_set_fd(ssl, socket_fd); //link the TCP socket to ssl obj
    if (SSL_connect(ssl) != 1)
    {
        SSL_free(ssl);
        close(socket_fd);
        return NULL;
    }

    //verify cert chain
    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK)
    {
        fprintf(stderr, "TLS verify failed: %s\n", X509_verify_cert_error_string(verify_result));
        SSL_free(ssl);
        close(socket_fd);
        return NULL;
    }

    //verify hostname
    if (!verify_peer_hostname(ssl, host))
    {
        fprintf(stderr, "TLS hostname failed for %s\n", host);
        SSL_free(ssl);
        close(socket_fd);
        return NULL;
    }

    //save socket fd and return
    //if caller passed a pointer for out_socket_fd, store it
    if (out_socket_fd) *out_socket_fd = socket_fd;

    return ssl;
}

/************* Simple line protocol helpers *******************/
/**
 * @param ssl ssl connection obj
 * @param line single line of text holding the server command
 * send a single-line command as a line of text to the server, (append '\n' so server's line reader triggers)
 * the ssl_server.c expects each command on its own line like LIST, 'ADD':task, 'DELETE':id
 */
static int send_command_line(SSL *ssl, const char *line)
{
    size_t line_len = strlen(line);
    if (SSL_write(ssl, line, (int)line_len) <= 0) return -1;
    if (SSL_write(ssl, "\n", 1) <= 0) return -1;
    return 0;
}

 /**
  * @param ssl ssl connection object
  * read and print server lines until a line equal to END appears
  * @return 0 on success, -1 if connection breaks 
  */
 static int read_reply_until_END(SSL *ssl)
 {
    char buffer[RECV_BUFSZ];
    size_t bytes_in_buffer = 0;

    //keep reading server output line by line until server sends END
    //print everything else along the way
    for (;;)
    {
        //read more bytes
        int bytes_read = SSL_read(ssl, buffer + bytes_in_buffer,
                            (int)(sizeof(buffer) - 1 - bytes_in_buffer));
        if (bytes_read <= 0) return -1;
        bytes_in_buffer += (size_t)bytes_read;
        buffer[bytes_in_buffer] = '\0';

        //process complete lines
        //loops if more new lines exist
        char *line_start = buffer;
        for (;;) 
        {
            char *newline_pos = strchr(line_start, '\n'); //look for '\n' to find a complete line
            if (!newline_pos) break;
            *newline_pos = '\0'; //replace '\n' with '\0' so line_start is null terminated string

            if (strcmp(line_start, "END") == 0) //if line = END, we reached the end of the server reply
            {
                //shift down any leftover bytes after END'\n' with memmove (rare case, but still good to include for security)
                size_t remaining = bytes_in_buffer - ((newline_pos +1) - buffer);
                memmove(buffer, newline_pos + 1, remaining);
                bytes_in_buffer = remaining;
                return 0;
            }
            else
            {
                puts(line_start); //print the line: ex: "Buy Milk"
            }
            line_start = newline_pos + 1;
        }

        //keep any partial line at start of buffer for the next read
        // if the last read ended mid-line (no '\n'), save them for start of buffer at next loop iteration
        if (line_start != buffer) 
        {
            size_t remaining = bytes_in_buffer - (size_t)(line_start - buffer);
            memmove(buffer, line_start, remaining);
            bytes_in_buffer = remaining;
        }

        //if we somehow accumulate a giant line, flush it
        //this is overflow safety
        if (bytes_in_buffer > sizeof(buffer) - 128)
        {
            fwrite(buffer, 1, bytes_in_buffer, stdout);
            bytes_in_buffer = 0;
        }
    }
 }

 /************* Failover Method: try multiple endpoints *******************/
 /**
  * @param ssl TLS context
  * @param endpoints array of endpoint_t structs
  * @param endpoint_count how many entries in endpoints to try
  * @param out_socket_fd optional out-param, if a connection succeeds we place the raw TCP socket fd here, 
  * so caller can close it later
  * @param out_index_connected optional out-param, if we succeed it tells you which index worked
  * @return valid TLS connection
  */
 static SSL* connect_with_failover(SSL_CTX *ssl, endpoint_t *endpoints, int endpoint_count, 
                                    int *out_socket_fd, int *out_index_connected)
 {
    for (int endpoint_index = 0; endpoint_index < endpoint_count; endpoint_index++) //loop over candidates in order, try app1 b4 app2
    {
        //log which we are dealing with
        fprintf(stderr, "Connecting to %s:%s ... \n", 
                endpoints[endpoint_index].host, endpoints[endpoint_index].port);

        //attempt connection
        SSL *ssl_conn = connect_tls(ssl, 
                                    endpoints[endpoint_index].host, endpoints[endpoint_index].port, out_socket_fd);
        if (ssl_conn)
        {
            if (out_index_connected) *out_index_connected = endpoint_index;
            return ssl_conn;
        }

        fprintf(stderr, "Connection to %s:%s failed, trying next.\n",
                endpoints[endpoint_index].host, endpoints[endpoint_index].port);
    }
    return NULL; //nothing worked
 }

 /************* Main REPL that sends command and handles failovers *******************/
 /**
  * @param argc
  * @param argv
  * note REPL stands for read, eval, print, loop
  */
 int main(int argc, char **argv) 
 {
    //this requires at least one endpoint <host1> <port1>
    //optional second endpoint for failover [<host2> <port2>]
    //--ca lets us pick a CA file, else default
    if (argc < 3)
    {
        fprintf(stderr, "Usage: %s <host1> <port1> [<host2> <port2>] [--ca <ca_file>]\n", argv[0]);
        return 2;
    }

    const char *ca_file_path = "ca.crt"; //default dev CA path
    endpoint_t endpoints[2] = {{0}}; //up to 2 endpoints for failover
    int endpoint_count = 0;

    int arg_index = 1;
    while (arg_index < argc)
    {
        //parse optional --ca path
        if (strcmp(argv[arg_index], "--ca") == 0 && arg_index + 1 , argc)
        {
            ca_file_path = argv[arg_index + 1];
            arg_index += 2;
            continue;
        }
        //parse endpoints adn get the info
        if (endpoint_count < 2 && arg_index + 1 < argc && argv[arg_index][0] != '-')
        {
            endpoints[endpoint_count].host = argv[arg_index];
            endpoints[endpoint_count].port = argv[arg_index + 1];
            endpoint_count++;
            arg_index += 2;
            continue;
        }
        break; //ignore anything extra
    }
    //if no endpoints were parsed
    if (endpoint_count == 0) die("Provide at least <host> <port>");

    //create a single TLS object for the whole process
    SSL_CTX *ssl_ctx = create_tls_client_context(ca_file_path);

    //initial connect with failover
    int socket_fd = -1;
    int connected_endpoint_index = -1;
    //try endpoints in order, app1, app2
    //on success we have ssl_conn = live connection
    //socket_fd =  TCP fd ofc
    //connected_endpoint_index = which endpoint worked, 0 or 1

    SSL *ssl_conn = connect_with_failover(ssl_ctx, endpoints, endpoint_count, 
                                        &socket_fd, &connected_endpoint_index);
    if (!ssl_conn) die("All connection attempts failed");

    //remind user what to type
    fprintf(stderr, "connected via TLS to %s:%s\n",
            endpoints[connected_endpoint_index].host,
            endpoints[connected_endpoint_index].port);
    fprintf(stderr, "Commands: LIST | ADD:<text> | DELETE:<id> | Crtl+D to quit\n");

    //REPL
    char *input_line = NULL;
    size_t input_capacity = 0;

    for(;;)
    {
        fprintf(stdout, "> ");
        fflush(stdout);

        //read a full user line
        ssize_t read_len = getline(&input_line, &input_capacity, stdin);
        if (read_len == -1) break; //EOF (Ctrl+D)

        //strip trailing newline
        if (read_len > 0 && input_line[read_len - 1] == '\n')
        {
            input_line[read_len - 1] = '\0';
        }

        //send the command with newline
        if (send_command_line(ssl_conn, input_line) != 0)
        {
            /**
             * if we are in here, the write failed, likely teh server died or reset connection
             * time to try the backup endpoint
             * strategy: close old conection, reconnect using failover, resend the command
             * do we have a check for ensuring duplicate commands aren't sent?
             * like say the reply got lost when a command was successfully sent
             */
            SSL_free(ssl_conn);
            close(socket_fd);

            ssl_conn = connect_with_failover(ssl_ctx, endpoints, endpoint_count,
                        &socket_fd, &connected_endpoint_index);
            if (!ssl_conn) die("Failover failed: n0 servers reachable");

            //resend the command on the new connection
            if (send_command_line(ssl_conn, input_line) != 0)
                die("Send after reconnect failed");

            //read multi-line reply until "END"
            if (read_reply_until_END(ssl_conn) != 0)
            {
                //fprintf(stderr, "Send failed: attempting failover"); here in case we want it for testing purposes
                SSL_free(ssl_conn);
                close(socket_fd);
                ssl_conn = connect_with_failover(ssl_ctx, endpoints, endpoint_count,
                        &socket_fd, &connected_endpoint_index);
                if (!ssl_conn) die("Failover failed: n0 servers reachable");
            }

        }
    }

    //cleanup
    free(input_line);
    SSL_shutdown(ssl_conn);
    SSL_free(ssl_conn);
    close(socket_fd);
    SSL_CTX_free(ssl_ctx);
    return 0;

 }
