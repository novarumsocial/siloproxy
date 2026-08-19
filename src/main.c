#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define BUFSZ             (64 * 1024)
#define CHUNK_LINE_MAX    (8 * 1024)
#define IDLE_TIMEOUT_MS   30000
#define CONNECT_TIMEOUT_MS 5000

static int g_debug;
static SSL_CTX *g_ssl_ctx;

typedef struct {
    int cfd;
    int ufd;
    SSL *ssl;
    int use_tls;
    char *upstream;
    char *up_host;
    int up_port;
    const char *bucket;
    char cbuf[BUFSZ];
    size_t cbuf_len;
    char ubuf[BUFSZ];
    size_t ubuf_len;
    char out[BUFSZ];
    size_t out_len;
} Conn;

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static int wait_fd(int fd, short ev) {
    struct pollfd p = { .fd = fd, .events = ev };
    int r;
    do { r = poll(&p, 1, -1); } while (r < 0 && errno == EINTR);
    return r > 0;
}

static ssize_t cl_read(Conn *c, void *buf, size_t n) {
    ssize_t r;
    do { r = read(c->cfd, buf, n); } while (r < 0 && errno == EINTR);
    return r;
}

static int cl_write_all(Conn *c, const void *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(c->cfd, (const char *)buf + off, n - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

static ssize_t up_read(Conn *c, void *buf, size_t n) {
    if (!c->use_tls) {
        ssize_t r;
        do { r = read(c->ufd, buf, n); } while (r < 0 && errno == EINTR);
        return r;
    }
    for (;;) {
        int r = SSL_read(c->ssl, buf, (int)n);
        if (r > 0) return r;
        if (r == 0) return 0;
        int e = SSL_get_error(c->ssl, r);
        if (e == SSL_ERROR_WANT_READ && wait_fd(c->ufd, POLLIN)) continue;
        if (e == SSL_ERROR_WANT_WRITE && wait_fd(c->ufd, POLLOUT)) continue;
        return -1;
    }
}

static int up_write_all(Conn *c, const void *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w;
        if (!c->use_tls) {
            do { w = write(c->ufd, (const char *)buf + off, n - off); } while (w < 0 && errno == EINTR);
            if (w < 0) return -1;
        } else {
            w = SSL_write(c->ssl, (const char *)buf + off, (int)(n - off));
            if (w <= 0) {
                int e = SSL_get_error(c->ssl, (int)w);
                if ((e == SSL_ERROR_WANT_READ && wait_fd(c->ufd, POLLIN)) ||
                    (e == SSL_ERROR_WANT_WRITE && wait_fd(c->ufd, POLLOUT)))
                    continue;
                return -1;
            }
        }
        off += (size_t)w;
    }
    return 0;
}

static void parse_upstream(Conn *c) {
    char *u = c->upstream;
    if (!strncasecmp(u, "https://", 8)) { c->use_tls = 1; u += 8; }
    else if (!strncasecmp(u, "http://", 7)) { c->use_tls = 0; u += 7; }
    else c->use_tls = 1;
    char *slash = strchr(u, '/');
    char *colon = strchr(u, ':');
    if (colon && (!slash || colon < slash)) {
        *colon = 0;
        c->up_port = atoi(colon + 1);
    } else if (slash) {
        *slash = 0;
    }
    c->up_host = u;
    if (!c->up_port) c->up_port = c->use_tls ? 443 : 80;
}

static void close_upstream(Conn *c) {
    if (c->ssl) { SSL_free(c->ssl); c->ssl = NULL; }
    if (c->ufd >= 0) { close(c->ufd); c->ufd = -1; }
}

static int tcp_connect(const char *host, const char *port) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *ai = NULL;
    if (getaddrinfo(host, port, &hints, &ai)) return -1;
    int fd = -1;
    for (struct addrinfo *p = ai; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        int fl = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) {
            fcntl(fd, F_SETFL, fl);
            break;
        }
        if (errno != EINPROGRESS) { close(fd); fd = -1; continue; }
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        int r;
        do { r = poll(&pfd, 1, CONNECT_TIMEOUT_MS); } while (r < 0 && errno == EINTR);
        int soerr = 0;
        socklen_t sl = sizeof soerr;
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl);
        if (r > 0 && !soerr) { fcntl(fd, F_SETFL, fl); break; }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(ai);
    return fd;
}

static int connect_upstream(Conn *c) {
    char port[8];
    snprintf(port, sizeof port, "%d", c->up_port);
    int fd = tcp_connect(c->up_host, port);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    c->ufd = fd;
    if (c->use_tls) {
        SSL *s = SSL_new(g_ssl_ctx);
        SSL_set_fd(s, fd);
        SSL_set_tlsext_host_name(s, c->up_host);
        SSL_set1_host(s, c->up_host);
        if (SSL_connect(s) != 1) {
            char eb[256];
            ERR_error_string_n(ERR_get_error(), eb, sizeof eb);
            fprintf(stderr, "tls handshake to %s failed: %s\n", c->up_host, eb);
            SSL_free(s);
            close(fd);
            c->ufd = -1;
            return -1;
        }
        c->ssl = s;
    }
    return 0;
}

static void init_tls(void) {
    OPENSSL_init_ssl(0, NULL);
    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_ssl_ctx) {
        fprintf(stderr, "SSL_CTX_new failed\n");
        exit(1);
    }
    SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_2_VERSION);
    if (SSL_CTX_set_default_verify_paths(g_ssl_ctx) != 1) {
        fprintf(stderr, "no CA certificates found\n");
        exit(1);
    }
}

static void send_error(Conn *c, const char *status_line) {
    char buf[256];
    int n = snprintf(buf, sizeof buf,
                     "HTTP/1.1 %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                     status_line);
    cl_write_all(c, buf, (size_t)n);
}

static char *find_hdr_end(char *buf, size_t len) {
    return memmem(buf, len, "\r\n\r\n", 4);
}

static int hdr_is(const char *line, size_t len, const char *name) {
    size_t nl = strlen(name);
    if (len < nl + 1 || line[nl] != ':') return 0;
    for (size_t i = 0; i < nl; i++)
        if (tolower((unsigned char)line[i]) != (unsigned char)name[i]) return 0;
    return 1;
}

typedef void (*hdr_fn)(const char *line, size_t len, void *ctx);

static void each_header(const char *buf, size_t blen, hdr_fn fn, void *ctx) {
    const char *l1 = memchr(buf, '\n', blen);
    if (!l1) return;
    const char *ln = l1 + 1;
    while (ln < buf + blen) {
        const char *le = memchr(ln, '\r', (size_t)(buf + blen - ln));
        if (!le) return;
        fn(ln, (size_t)(le - ln), ctx);
        ln = le + 2;
    }
}

struct uint_ctx { const char *name; uint64_t val; int bad; };
static void uint_hdr(const char *ln, size_t ll, void *p) {
    struct uint_ctx *u = p;
    if (u->val != UINT64_MAX || !hdr_is(ln, ll, u->name)) return;
    const char *v = memchr(ln, ':', ll) + 1;
    while (*v == ' ' || *v == '\t') v++;
    errno = 0;
    uint64_t n = strtoull(v, NULL, 10);
    if (errno == ERANGE || n == UINT64_MAX || *v == '-') u->bad = 1;
    else u->val = n;
}
static int header_uint(const char *buf, size_t blen, const char *name, uint64_t *out) {
    struct uint_ctx u = { name, UINT64_MAX, 0 };
    each_header(buf, blen, uint_hdr, &u);
    if (u.bad) return -1;
    *out = u.val;
    return 0;
}

struct test_ctx { const char *name; const char *needle; int found; };
static void test_hdr(const char *ln, size_t ll, void *p) {
    struct test_ctx *t = p;
    if (!t->found && hdr_is(ln, ll, t->name) && strcasestr(ln, t->needle)) t->found = 1;
}
static int header_has(const char *buf, size_t blen, const char *name, const char *needle) {
    struct test_ctx t = { name, needle, 0 };
    each_header(buf, blen, test_hdr, &t);
    return t.found;
}

static int read_client_headers(Conn *c) {
    for (;;) {
        if (c->cbuf_len > BUFSZ) return -1;
        if (find_hdr_end(c->cbuf, c->cbuf_len)) return 0;
        struct pollfd p = { .fd = c->cfd, .events = POLLIN };
        int r;
        do { r = poll(&p, 1, IDLE_TIMEOUT_MS); } while (r < 0 && errno == EINTR);
        if (r <= 0) return -1;
        ssize_t n = cl_read(c, c->cbuf + c->cbuf_len, sizeof(c->cbuf) - c->cbuf_len);
        if (n <= 0) return -1;
        c->cbuf_len += (size_t)n;
    }
}

static int parse_request_line(Conn *c, char **method, size_t *mlen, char **target,
                              size_t *tlen, int *ver11, size_t *hdr_end) {
    char *e = find_hdr_end(c->cbuf, c->cbuf_len);
    if (!e) return -1;
    *hdr_end = (size_t)(e - c->cbuf);
    char *l1 = memchr(c->cbuf, '\n', *hdr_end);
    if (!l1 || l1 == c->cbuf || l1[-1] != '\r') return -1;
    char *le = l1 - 1;
    char *s1 = memchr(c->cbuf, ' ', (size_t)(le - c->cbuf));
    char *s2 = s1 ? memchr(s1 + 1, ' ', (size_t)(le - s1 - 1)) : NULL;
    if (!s1 || !s2) return -1;
    *method = c->cbuf;
    *mlen = (size_t)(s1 - c->cbuf);
    *target = s1 + 1;
    *tlen = (size_t)(s2 - s1 - 1);
    char *ver = s2 + 1;
    size_t vlen = (size_t)(le - ver);
    if (**target != '/') return -1;
    if (vlen < 5 || memcmp(ver, "HTTP/", 5)) return -1;
    *ver11 = vlen == 8 && !memcmp(ver, "HTTP/1.1", 8);
    return 0;
}

static int bucket_ok(const char *bucket, const char *t, size_t tl) {
    size_t bl = strlen(bucket);
    if (tl < bl + 1) return 0;
    if (memcmp(t + 1, bucket, bl)) return 0;
    return tl == bl + 1 || t[bl + 1] == '/';
}

struct build_ctx { Conn *c; size_t o; };
static void req_hdr(const char *ln, size_t ll, void *p) {
    struct build_ctx *b = p;
    Conn *c = b->c;
    if (b->o == (size_t)-1) return;
    if (hdr_is(ln, ll, "host")) {
        int n = (c->use_tls && c->up_port != 443) || (!c->use_tls && c->up_port != 80)
            ? snprintf(c->out + b->o, sizeof(c->out) - b->o, "Host: %s:%d\r\n", c->up_host, c->up_port)
            : snprintf(c->out + b->o, sizeof(c->out) - b->o, "Host: %s\r\n", c->up_host);
        if (n <= 0 || (size_t)n >= sizeof(c->out) - b->o) { b->o = (size_t)-1; return; }
        b->o += (size_t)n;
    } else if (hdr_is(ln, ll, "connection") || hdr_is(ln, ll, "te") ||
               hdr_is(ln, ll, "trailer") || hdr_is(ln, ll, "upgrade")) {
        return;
    } else {
        if (ll + 2 > sizeof(c->out) - b->o) { b->o = (size_t)-1; return; }
        memcpy(c->out + b->o, ln, ll + 2);
        b->o += ll + 2;
    }
}

static int build_req_hdrs(Conn *c, const char *method, size_t mlen,
                          const char *target, size_t tlen, size_t hdr_end) {
    int n = snprintf(c->out, sizeof(c->out), "%.*s %.*s HTTP/1.1\r\n",
                     (int)mlen, method, (int)tlen, target);
    if (n <= 0 || (size_t)n >= sizeof(c->out)) return -1;
    struct build_ctx b = { c, (size_t)n };
    each_header(c->cbuf, hdr_end + 2, req_hdr, &b);
    if (b.o == (size_t)-1 || b.o + 2 > sizeof(c->out)) return -1;
    memcpy(c->out + b.o, "\r\n", 2);
    c->out_len = b.o + 2;
    return 0;
}

static void resp_hdr(const char *ln, size_t ll, void *p) {
    struct build_ctx *b = p;
    if (b->o == (size_t)-1) return;
    if (hdr_is(ln, ll, "connection") || hdr_is(ln, ll, "te") ||
        hdr_is(ln, ll, "trailer") || hdr_is(ln, ll, "upgrade"))
        return;
    if (ll + 2 > sizeof(b->c->out) - b->o) { b->o = (size_t)-1; return; }
    memcpy(b->c->out + b->o, ln, ll + 2);
    b->o += ll + 2;
}

static int build_resp_hdrs(Conn *c, size_t hlen) {
    char *l1 = memchr(c->ubuf, '\n', hlen);
    if (!l1) return -1;
    size_t o = (size_t)(l1 + 1 - c->ubuf);
    memcpy(c->out, c->ubuf, o);
    struct build_ctx b = { c, o };
    each_header(c->ubuf, hlen - 2, resp_hdr, &b);
    if (b.o == (size_t)-1 || b.o + 2 > sizeof(c->out)) return -1;
    memcpy(c->out + b.o, "\r\n", 2);
    c->out_len = b.o + 2;
    return 0;
}

static int parse_status(const char *buf, size_t len) {
    const char *sp = memchr(buf, ' ', len);
    if (!sp) return 0;
    return atoi(sp + 1);
}

struct frame_ctx { int chunked; int close; uint64_t cl; int cl_bad; };
static void frame_hdr(const char *ln, size_t ll, void *p) {
    struct frame_ctx *f = p;
    if (hdr_is(ln, ll, "transfer-encoding") && strcasestr(ln, "chunked")) f->chunked = 1;
    else if (hdr_is(ln, ll, "content-length")) {
        const char *v = memchr(ln, ':', ll) + 1;
        while (*v == ' ' || *v == '\t') v++;
        errno = 0;
        uint64_t n = strtoull(v, NULL, 10);
        if (errno == ERANGE || n == UINT64_MAX || *v == '-') f->cl_bad = 1;
        else f->cl = n;
    }
    else if (hdr_is(ln, ll, "connection") && strcasestr(ln, "close")) f->close = 1;
}

static void parse_resp_framing(Conn *c, size_t hlen, int *status, int *chunked,
                               uint64_t *cl, int *cl_bad, int *keep_up) {
    *status = parse_status(c->ubuf, hlen);
    struct frame_ctx f = { 0, 0, UINT64_MAX, 0 };
    each_header(c->ubuf, hlen - 2, frame_hdr, &f);
    *chunked = f.chunked;
    *cl = f.cl;
    *cl_bad = f.cl_bad;
    *keep_up = !f.close && !memcmp(c->ubuf, "HTTP/1.1", 8);
}

static int read_resp_headers(Conn *c) {
    for (;;) {
        if (c->ubuf_len > BUFSZ) return -1;
        char *e = find_hdr_end(c->ubuf, c->ubuf_len);
        if (e) {
            size_t hlen = (size_t)(e - c->ubuf) + 4;
            int st = parse_status(c->ubuf, hlen);
            if (st >= 100 && st < 200) {
                if (cl_write_all(c, c->ubuf, hlen)) return -1;
                memmove(c->ubuf, c->ubuf + hlen, c->ubuf_len - hlen);
                c->ubuf_len -= hlen;
                continue;
            }
            return 0;
        }
        ssize_t n = up_read(c, c->ubuf + c->ubuf_len, sizeof(c->ubuf) - c->ubuf_len);
        if (n <= 0) return -1;
        c->ubuf_len += (size_t)n;
    }
}

enum { CS_LINE, CS_DATA, CS_CRLF };

typedef struct {
    int state;
    uint64_t rem;
    int crlf;
    int in_trailers;
    int done;
    char line[CHUNK_LINE_MAX];
    size_t line_len;
} Chunker;

static void chunker_init(Chunker *k) { memset(k, 0, sizeof *k); }

static int chunker_feed(Chunker *k, const char *buf, size_t len, size_t *consumed, int *done) {
    size_t i = 0;
    while (i < len && !k->done) {
        if (k->state == CS_LINE) {
            int got = 0;
            for (; i < len; i++) {
                char ch = buf[i];
                if (ch == '\n') { got = 1; i++; break; }
                if (ch != '\r') {
                    if (k->line_len >= CHUNK_LINE_MAX - 1) return -1;
                    k->line[k->line_len++] = ch;
                }
            }
            if (!got) break;
            if (!k->in_trailers) {
                uint64_t sz = 0;
                int digits = 0;
                for (size_t j = 0; j < k->line_len; j++) {
                    char ch = k->line[j];
                    if (ch == ';') break;
                    int d;
                    if (ch >= '0' && ch <= '9') d = ch - '0';
                    else if (ch >= 'a' && ch <= 'f') d = ch - 'a' + 10;
                    else if (ch >= 'A' && ch <= 'F') d = ch - 'A' + 10;
                    else return -1;
                    sz = sz * 16 + (uint64_t)d;
                    digits++;
                }
                if (!digits) return -1;
                if (sz == 0) k->in_trailers = 1;
                else { k->rem = sz; k->state = CS_DATA; }
            } else if (k->line_len == 0) {
                k->done = 1;
            }
            k->line_len = 0;
        } else if (k->state == CS_DATA) {
            size_t n = len - i;
            if (n > k->rem) n = (size_t)k->rem;
            i += n;
            k->rem -= n;
            if (k->rem == 0) k->state = CS_CRLF;
        } else {
            while (i < len && k->crlf < 2) {
                char want = k->crlf == 0 ? '\r' : '\n';
                if (buf[i] != want) return -1;
                i++;
                k->crlf++;
            }
            if (k->crlf == 2) { k->crlf = 0; k->state = CS_LINE; }
        }
    }
    *consumed = i;
    *done = k->done;
    return 0;
}

static int pump_client_body(Conn *c, int chunked, uint64_t rem, Chunker *k, int *early) {
    int req_done = 0;
    for (;;) {
        while (!req_done && c->cbuf_len) {
            size_t consumed = 0;
            if (chunked) {
                if (chunker_feed(k, c->cbuf, c->cbuf_len, &consumed, &req_done) < 0) return -1;
            } else {
                consumed = c->cbuf_len < rem ? c->cbuf_len : (size_t)rem;
                rem -= consumed;
                if (rem == 0) req_done = 1;
            }
            if (consumed && up_write_all(c, c->cbuf, consumed)) return -1;
            if (consumed) {
                memmove(c->cbuf, c->cbuf + consumed, c->cbuf_len - consumed);
                c->cbuf_len -= consumed;
            }
        }
        if (req_done) return 0;
        struct pollfd p[2];
        p[0].fd = c->cfd;
        p[0].events = POLLIN;
        p[1].fd = c->ufd;
        p[1].events = POLLIN;
        int r;
        do { r = poll(p, 2, -1); } while (r < 0 && errno == EINTR);
        if (r < 0) return -1;
        if (p[0].revents & (POLLIN | POLLHUP)) {
            ssize_t n = cl_read(c, c->cbuf + c->cbuf_len, sizeof(c->cbuf) - c->cbuf_len);
            if (n <= 0) return -1;
            c->cbuf_len += (size_t)n;
        }
        if (p[1].revents & (POLLIN | POLLHUP)) {
            ssize_t n = up_read(c, c->ubuf + c->ubuf_len, sizeof(c->ubuf) - c->ubuf_len);
            if (n <= 0) return -1;
            c->ubuf_len += (size_t)n;
            char *e = find_hdr_end(c->ubuf, c->ubuf_len);
            if (e) {
                size_t hlen = (size_t)(e - c->ubuf) + 4;
                int st = parse_status(c->ubuf, hlen);
                if (st == 0) return -1;
                if (st >= 200) { *early = 1; return 0; }
                if (cl_write_all(c, c->ubuf, hlen)) return -1;
                memmove(c->ubuf, c->ubuf + hlen, c->ubuf_len - hlen);
                c->ubuf_len -= hlen;
            }
        }
    }
}

static int pump_resp_body(Conn *c, int chunked, uint64_t rem, int *up_eof) {
    Chunker k;
    chunker_init(&k);
    for (;;) {
        while (c->ubuf_len) {
            size_t consumed = 0;
            int done = 0;
            if (chunked) {
                if (chunker_feed(&k, c->ubuf, c->ubuf_len, &consumed, &done) < 0) return -1;
            } else {
                consumed = c->ubuf_len < rem ? c->ubuf_len : (size_t)rem;
                rem -= consumed;
                if (rem == 0) done = 1;
            }
            if (consumed) {
                if (cl_write_all(c, c->ubuf, consumed)) return -1;
                memmove(c->ubuf, c->ubuf + consumed, c->ubuf_len - consumed);
                c->ubuf_len -= consumed;
            }
            if (done) return 0;
        }
        ssize_t n = up_read(c, c->ubuf, sizeof(c->ubuf));
        if (n < 0) return -1;
        if (n == 0) { *up_eof = 1; return 0; }
        c->ubuf_len = (size_t)n;
    }
}

static int is_head(const char *m, size_t ml) { return ml == 4 && !memcmp(m, "HEAD", 4); }

static void *handle_conn(void *arg) {
    Conn c = *(Conn *)arg;
    free(arg);
    double t_start = 0;
    char tlog[256] = "";
    for (;;) {
        if (read_client_headers(&c)) goto done;
        char *method, *target;
        size_t mlen, tlen, hdr_end;
        int ver11;
        if (parse_request_line(&c, &method, &mlen, &target, &tlen, &ver11, &hdr_end)) {
            send_error(&c, "400 Bad Request");
            goto done;
        }
        if (g_debug) fprintf(stderr, "[debug] %.*s %.*s\n", (int)mlen, method, (int)tlen, target);
        t_start = now_ms();
        int head_req = is_head(method, mlen);
        size_t tcopy = tlen < sizeof(tlog) - 1 ? tlen : sizeof(tlog) - 1;
        memcpy(tlog, target, tcopy);
        tlog[tcopy] = 0;
        if (c.bucket && !bucket_ok(c.bucket, target, tlen)) {
            fprintf(stderr, "blocked: path outside bucket %s: %.*s\n", c.bucket, (int)tlen, target);
            send_error(&c, "403 Forbidden");
            goto done;
        }
        int client_keep = ver11 && !header_has(c.cbuf, hdr_end + 2, "connection", "close");
        int chunked = header_has(c.cbuf, hdr_end + 2, "transfer-encoding", "chunked");
        uint64_t cl;
        if (header_uint(c.cbuf, hdr_end + 2, "content-length", &cl) < 0) {
            send_error(&c, "400 Bad Request");
            goto done;
        }
        if (build_req_hdrs(&c, method, mlen, target, tlen, hdr_end) < 0) {
            send_error(&c, "431 Request Header Fields Too Large");
            goto done;
        }
        memmove(c.cbuf, c.cbuf + hdr_end + 4, c.cbuf_len - hdr_end - 4);
        c.cbuf_len -= hdr_end + 4;

        int bodyless_req = !chunked && cl == UINT64_MAX;
        int retried = 0;
        int early = 0;
        for (;;) {
            if (c.ufd < 0 && connect_upstream(&c)) {
                fprintf(stderr, "upstream error: connect to %s:%d failed: %s\n",
                        c.up_host, c.up_port, strerror(errno));
                send_error(&c, "502 Bad Gateway");
                goto done;
            }
            if (up_write_all(&c, c.out, c.out_len)) {
                fprintf(stderr, "upstream error: write to %s failed: %s\n",
                        c.up_host, strerror(errno));
                close_upstream(&c);
                if (!retried) { retried = 1; continue; }
                send_error(&c, "502 Bad Gateway");
                goto done;
            }
            if (!bodyless_req) {
                Chunker ck;
                chunker_init(&ck);
                if (pump_client_body(&c, chunked, cl, &ck, &early)) {
                    fprintf(stderr, "upstream error: %s: %s\n", c.up_host, strerror(errno));
                    send_error(&c, "502 Bad Gateway");
                    goto done;
                }
            }
            if (early) break;
            if (read_resp_headers(&c) == 0) break;
            fprintf(stderr, "upstream error: %s closed before responding: %s\n",
                    c.up_host, strerror(errno));
            close_upstream(&c);
            c.ubuf_len = 0;
            if (retried || !bodyless_req) {
                send_error(&c, "502 Bad Gateway");
                goto done;
            }
            retried = 1;
        }

        char *he = find_hdr_end(c.ubuf, c.ubuf_len);
        if (!he) {
            send_error(&c, "502 Bad Gateway");
            goto done;
        }
        size_t hlen = (size_t)(he - c.ubuf) + 4;
        int status, rchunked, keep_up, rcl_bad;
        uint64_t rcl;
        parse_resp_framing(&c, hlen, &status, &rchunked, &rcl, &rcl_bad, &keep_up);
        if (rcl_bad) {
            fprintf(stderr, "upstream error: bad content-length from %s\n", c.up_host);
            send_error(&c, "502 Bad Gateway");
            goto done;
        }
        if (build_resp_hdrs(&c, hlen) < 0) {
            send_error(&c, "502 Bad Gateway");
            goto done;
        }
        if (cl_write_all(&c, c.out, c.out_len)) goto done;
        memmove(c.ubuf, c.ubuf + hlen, c.ubuf_len - hlen);
        c.ubuf_len -= hlen;

        int up_eof = 0;
        int bodyless = head_req || (status >= 100 && status < 200) ||
                       status == 204 || status == 205 || status == 304;
        if (!bodyless) {
            if (rchunked) {
                if (pump_resp_body(&c, 1, 0, &up_eof)) goto done;
            } else if (rcl == UINT64_MAX) {
                if (pump_resp_body(&c, 0, UINT64_MAX, &up_eof)) goto done;
            } else if (rcl > 0) {
                if (pump_resp_body(&c, 0, rcl, &up_eof)) goto done;
            }
        }
        if (g_debug) fprintf(stderr, "[debug] %10.1fms  upstream %s\n", now_ms() - t_start, tlog);
        if (!keep_up || up_eof) close_upstream(&c);
        if (early || up_eof || !client_keep) goto done;
    }
done:;
    if (g_debug && t_start > 0) fprintf(stderr, "[debug] %10.1fms  total %s\n", now_ms() - t_start, tlog);
    close_upstream(&c);
    close(c.cfd);
    free(c.upstream);
    return NULL;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    const char *dbg = getenv("DEBUG");
    g_debug = dbg && (!strcmp(dbg, "1") || !strcasecmp(dbg, "true"));
    const char *bind_addr = getenv("BIND");
    if (!bind_addr || !*bind_addr) bind_addr = "0.0.0.0:8080";
    const char *upstream = getenv("UPSTREAM");
    if (!upstream || !*upstream) upstream = "https://onsilo.dev";
    const char *bucket = getenv("BUCKET");

    init_tls();

    char hostbuf[256];
    const char *bhost = bind_addr;
    const char *bport = "8080";
    if (*bind_addr == '[') {
        const char *rb = strchr(bind_addr, ']');
        if (rb > bind_addr) {
            size_t hl = (size_t)(rb - bind_addr - 1);
            if (hl >= sizeof hostbuf) hl = sizeof hostbuf - 1;
            memcpy(hostbuf, bind_addr + 1, hl);
            hostbuf[hl] = 0;
            bhost = hostbuf;
            if (rb[1] == ':') bport = rb + 2;
        }
    } else {
        const char *colon = strrchr(bind_addr, ':');
        if (colon) {
            size_t hl = (size_t)(colon - bind_addr);
            if (hl >= sizeof hostbuf) hl = sizeof hostbuf - 1;
            memcpy(hostbuf, bind_addr, hl);
            hostbuf[hl] = 0;
            bhost = hostbuf;
            bport = colon + 1;
        }
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    struct addrinfo *ai = NULL;
    if (getaddrinfo(*bhost ? bhost : NULL, *bport ? bport : NULL, &hints, &ai)) {
        fprintf(stderr, "bad BIND address: %s\n", bind_addr);
        return 1;
    }
    int lfd = -1;
    for (struct addrinfo *p = ai; p; p = p->ai_next) {
        lfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (lfd < 0) continue;
        int one = 1;
        setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (bind(lfd, p->ai_addr, p->ai_addrlen) == 0 && listen(lfd, 1024) == 0) break;
        close(lfd);
        lfd = -1;
    }
    freeaddrinfo(ai);
    if (lfd < 0) {
        fprintf(stderr, "failed to bind %s\n", bind_addr);
        return 1;
    }

    fprintf(stderr, "siloproxy listening on %s -> %s", bind_addr, upstream);
    if (bucket) fprintf(stderr, " (bucket %s only)", bucket);
    fprintf(stderr, "\n");

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&attr, 1 << 20);

    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }
        int one = 1;
        setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        Conn *cn = calloc(1, sizeof(Conn));
        if (!cn) { close(cfd); continue; }
        cn->cfd = cfd;
        cn->ufd = -1;
        cn->upstream = strdup(upstream);
        if (!cn->upstream) { free(cn); close(cfd); continue; }
        cn->bucket = bucket;
        parse_upstream(cn);
        pthread_t th;
        if (pthread_create(&th, &attr, handle_conn, cn) != 0) {
            free(cn->upstream);
            free(cn);
            close(cfd);
        }
    }
}
