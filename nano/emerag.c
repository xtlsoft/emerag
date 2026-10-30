#include "tls.h"
#include "crypto.h"

#ifdef _WIN32
#define NANO_POPEN _popen
#define NANO_PCLOSE _pclose
#else
#define NANO_POPEN popen
#define NANO_PCLOSE pclose
#endif

#define NANO_VERSION "0.1.0"
#define NANO_MAX_MSGS 12
#define NANO_SHELL_OUT 8192

static void console_utf8(void) {
#ifdef _WIN32
    /* The CRT's console I/O uses the active code page. Without this, UTF-8
     * replies print as mojibake and Chinese input reaches the API as GBK. */
    SetConsoleCP(65001);
    SetConsoleOutputCP(65001);
#endif
}

typedef struct {
    char *role;
    char *content;
} Msg;

static const char *SYSTEM_PROMPT =
    "You are emerag-nano, a tiny emergency shell agent running on the user's machine. "
    "You are connected through a deliberately minimal TLS/HTTP stack; there is no MCP, "
    "no scripting language, and no tool JSON. "
    "When you need a shell command, answer with exactly one line starting with "
    "SHELL: followed by the command. Do not use markdown fences. "
    "The controller runs the command and sends you its output as the next user message. "
    "Otherwise answer briefly and directly. Inspect before changing. Never print secrets.\n";

static char *xstrdup(const char *s) {
    size_t n = strlen(s) + 1;
    char *p = (char *)nano_alloc(n);
    memcpy(p, s, n);
    return p;
}

static void msg_free(Msg *m) {
    if (m->role) nano_free(m->role);
    if (m->content) nano_free(m->content);
    m->role = NULL;
    m->content = NULL;
}

static void msg_add(Msg *msgs, int *n, const char *role, const char *content) {
    int i;
    if (*n >= NANO_MAX_MSGS) {
        /* Keep system at index 0; drop the oldest message. */
        msg_free(&msgs[1]);
        for (i = 1; i < *n - 1; i++) msgs[i] = msgs[i+1];
        (*n)--;
    }
    msgs[*n].role = xstrdup(role);
    msgs[*n].content = xstrdup(content);
    (*n)++;
}

static void json_escape(Buf *b, const char *s) {
    const unsigned char *p = (const unsigned char *)s;
    while (*p) {
        switch (*p) {
            case '"': buf_puts(b, "\\\""); break;
            case '\\': buf_puts(b, "\\\\"); break;
            case '\n': buf_puts(b, "\\n"); break;
            case '\r': buf_puts(b, "\\r"); break;
            case '\t': buf_puts(b, "\\t"); break;
            case '\b': buf_puts(b, "\\b"); break;
            case '\f': buf_puts(b, "\\f"); break;
            default:
                if (*p < 0x20) {
                    char tmp[8];
                    sprintf(tmp, "\\u%04x", (unsigned)*p);
                    buf_puts(b, tmp);
                } else {
                    buf_putc(b, *p);
                }
        }
        p++;
    }
}

static void http_request_body(Buf *b, const char *model, Msg *msgs, int nmsg) {
    int i;
    buf_puts(b, "{\"model\":\"");
    json_escape(b, model);
    buf_puts(b, "\",\"messages\":[");
    for (i = 0; i < nmsg; i++) {
        if (i) buf_putc(b, ',');
        buf_puts(b, "{\"role\":\"");
        json_escape(b, msgs[i].role);
        buf_puts(b, "\",\"content\":\"");
        json_escape(b, msgs[i].content);
        buf_puts(b, "\"}");
    }
    buf_puts(b, "],\"stream\":false,\"max_tokens\":2048}");
}

static char *json_string_after(const char *p, const char *key) {
    const char *q = strstr(p, key);
    Buf out;
    if (!q) return NULL;
    q += strlen(key);
    while (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n') q++;
    if (*q != ':') return NULL;
    q++;
    while (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n') q++;
    if (strncmp(q, "null", 4) == 0) return xstrdup("");
    if (*q != '"') return NULL;
    q++;
    buf_init(&out);
    while (*q && *q != '"') {
        if (*q == '\\') {
            q++;
            switch (*q) {
                case '"': buf_putc(&out, '"'); q++; break;
                case '\\': buf_putc(&out, '\\'); q++; break;
                case '/': buf_putc(&out, '/'); q++; break;
                case 'b': buf_putc(&out, '\b'); q++; break;
                case 'f': buf_putc(&out, '\f'); q++; break;
                case 'n': buf_putc(&out, '\n'); q++; break;
                case 'r': buf_putc(&out, '\r'); q++; break;
                case 't': buf_putc(&out, '\t'); q++; break;
                case 'u': {
                    unsigned code = 0;
                    int i;
                    q++;
                    for (i = 0; i < 4 && *q; i++) {
                        code <<= 4;
                        if (*q >= '0' && *q <= '9') code |= (unsigned)(*q - '0');
                        else if (*q >= 'a' && *q <= 'f') code |= (unsigned)(*q - 'a' + 10);
                        else if (*q >= 'A' && *q <= 'F') code |= (unsigned)(*q - 'A' + 10);
                        q++;
                    }
                    if (code < 0x80) {
                        buf_putc(&out, (int)code);
                    } else if (code < 0x800) {
                        buf_putc(&out, (int)(0xc0 | (code >> 6)));
                        buf_putc(&out, (int)(0x80 | (code & 0x3f)));
                    } else {
                        buf_putc(&out, (int)(0xe0 | (code >> 12)));
                        buf_putc(&out, (int)(0x80 | ((code >> 6) & 0x3f)));
                        buf_putc(&out, (int)(0x80 | (code & 0x3f)));
                    }
                    break;
                }
                default: buf_putc(&out, *q); if (*q) q++; break;
            }
        } else {
            buf_putc(&out, *q++);
        }
    }
    buf_putc(&out, 0);
    return (char *)out.p;
}

static char *extract_content(const char *json) {
    const char *msg = strstr(json, "\"message\"");
    char *p;
    if (!msg) msg = json;
    p = json_string_after(msg, "\"content\"");
    if (p && *p) return p;
    if (p) nano_free(p);
    /* Some gateways put the visible answer in reasoning_content and leave
     * content empty. Do not discard a usable reply. */
    p = json_string_after(msg, "\"reasoning_content\"");
    return p ? p : xstrdup("");
}

static int dechunk(const u8 *in, size_t len, Buf *out) {
    size_t off = 0;
    while (off < len) {
        size_t line = off;
        size_t sz = 0;
        while (off < len && in[off] != '\r') off++;
        if (off >= len) return -1;
        {
            char tmp[32];
            size_t n = off - line;
            if (n >= sizeof(tmp)) return -1;
            memcpy(tmp, in + line, n);
            tmp[n] = 0;
            sz = (size_t)strtoul(tmp, NULL, 16);
        }
        off += 2;
        if (sz == 0) return 0;
        if (off + sz > len) return -1;
        buf_put(out, in + off, sz);
        off += sz;
        if (off + 2 <= len && in[off] == '\r' && in[off+1] == '\n') off += 2;
    }
    return 0;
}

static int http_post(Tls *t, const char *host, const char *path,
                     const char *key, const char *body, size_t bodylen,
                     Buf *response, char *err, size_t errlen) {
    Buf req;
    char line[512];
    int n;
    u8 tmp[4096];
    size_t header_end = 0;
    size_t content_length = 0;
    int have_length = 0;
    int chunked = 0;

    buf_init(&req);
    sprintf(line, "POST %s HTTP/1.1\r\n", path);
    buf_puts(&req, line);
    sprintf(line, "Host: %s\r\n", host);
    buf_puts(&req, line);
    buf_puts(&req, "User-Agent: emerag-nano/" NANO_VERSION "\r\n");
    buf_puts(&req, "Accept: application/json\r\n");
    buf_puts(&req, "Content-Type: application/json\r\n");
    if (key && *key) {
        buf_puts(&req, "Authorization: Bearer ");
        buf_puts(&req, key);
        buf_puts(&req, "\r\n");
    }
    sprintf(line, "Content-Length: %u\r\n", (unsigned)bodylen);
    buf_puts(&req, line);
    buf_puts(&req, "Connection: keep-alive\r\n\r\n");
    buf_put(&req, body, bodylen);

    if (tls_write(t, req.p, req.len) != 0) {
        buf_free(&req);
        strncpy(err, "TLS write failed", errlen - 1); err[errlen-1] = 0;
        return -1;
    }
    buf_free(&req);

    for (;;) {
        n = tls_read(t, tmp, sizeof(tmp));
        if (n <= 0) break;
        buf_put(response, tmp, (size_t)n);
        if (!header_end) {
            {
                size_t i;
                for (i = 0; i + 3 < response->len; i++) {
                    if (response->p[i] == '\r' && response->p[i+1] == '\n' &&
                        response->p[i+2] == '\r' && response->p[i+3] == '\n') {
                        header_end = i + 4;
                        break;
                    }
                }
            }
            if (header_end) {
                char *headers = (char *)nano_alloc(header_end + 1);
                char *p;
                memcpy(headers, response->p, header_end);
                headers[header_end] = 0;
                p = strstr(headers, "Content-Length:");
                if (!p) p = strstr(headers, "content-length:");
                if (p) {
                    p += 15;
                    while (*p == ' ') p++;
                    content_length = (size_t)strtoul(p, NULL, 10);
                    have_length = 1;
                }
                if (strstr(headers, "Transfer-Encoding: chunked") ||
                    strstr(headers, "transfer-encoding: chunked")) {
                    chunked = 1;
                }
                nano_free(headers);
            }
        }
        if (have_length && !chunked && response->len >= header_end + content_length) break;
        if (chunked) {
            /* A terminating zero chunk near the end is enough for this client. */
            if (response->len >= 5) {
                const u8 *q = response->p + response->len - 5;
                if (memcmp(q, "0\r\n\r\n", 5) == 0) break;
            }
        }
    }
    if (response->len == 0) {
        strncpy(err, "empty HTTP response", errlen - 1); err[errlen-1] = 0;
        return -1;
    }
    return 0;
}

static int http_body(Buf *response, Buf *body, int *status) {
    size_t i, hdr = 0;
    char *text = (char *)nano_alloc(response->len + 1);
    char *p;
    int chunked = 0;
    memcpy(text, response->p, response->len);
    text[response->len] = 0;
    *status = 0;
    if (strncmp(text, "HTTP/1.", 7) == 0) {
        p = strchr(text, ' ');
        if (p) *status = atoi(p + 1);
    }
    for (i = 0; i + 3 < response->len; i++) {
        if (response->p[i] == '\r' && response->p[i+1] == '\n' &&
            response->p[i+2] == '\r' && response->p[i+3] == '\n') {
            hdr = i + 4; break;
        }
    }
    if (!hdr) { nano_free(text); return -1; }
    if (strstr(text, "Transfer-Encoding: chunked") ||
        strstr(text, "transfer-encoding: chunked")) chunked = 1;
    buf_init(body);
    if (chunked) {
        if (dechunk(response->p + hdr, response->len - hdr, body) != 0) {
            nano_free(text); return -1;
        }
    } else {
        buf_put(body, response->p + hdr, response->len - hdr);
    }
    nano_free(text);
    return 0;
}

static int run_shell(const char *cmd, Buf *out) {
    FILE *f = NANO_POPEN(cmd, "r");
    char line[512];
    if (!f) return -1;
    while (fgets(line, sizeof(line), f)) {
        buf_puts(out, line);
        if (out->len > NANO_SHELL_OUT) break;
    }
    NANO_PCLOSE(f);
    return 0;
}

static const char *shell_command(const char *content) {
    const char *p = content;
    while (*p) {
        const char *line = p;
        const char *end;
        while (*p && *p != '\n') p++;
        end = p;
        while (line < end && (*line == ' ' || *line == '\t')) line++;
        if (end - line >= 6 && strncmp(line, "SHELL:", 6) == 0) {
            line += 6;
            while (line < end && (*line == ' ' || *line == '\t')) line++;
            {
                static char cmd[2048];
                size_t n = (size_t)(end - line);
                if (n >= sizeof(cmd)) n = sizeof(cmd) - 1;
                memcpy(cmd, line, n);
                cmd[n] = 0;
                return cmd;
            }
        }
        if (*p == '\n') p++;
    }
    return NULL;
}

static int post_with_reconnect(Tls **tls, const char *host, const char *ip,
                               int port, const char *path, const char *key,
                               const char *body, size_t bodylen, Buf *response,
                               char *err, size_t errlen) {
    int rc = http_post(*tls, host, path, key, body, bodylen, response, err, errlen);
    if (rc == 0) return 0;
    /* Proxies and servers routinely close an HTTP/1.1 connection after one
     * response even when keep-alive was requested. Reconnect and retry once
     * instead of turning every later prompt into a TLS write failure. */
    buf_free(response);
    buf_init(response);
    tls_close(*tls);
    *tls = tls_connect(host, ip && *ip ? ip : NULL, port, err, errlen);
    if (!*tls) return -1;
    return http_post(*tls, host, path, key, body, bodylen, response, err, errlen);
}

static int chat_turn(Tls **tls, const char *host, const char *ip, int port,
                     const char *path, const char *model, const char *key,
                     Msg *msgs, int *nmsg, int ask, int allow_shell,
                     int max_turns) {
    int turn;
    for (turn = 0; turn < max_turns; turn++) {
        Buf body, response, resp_body;
        char *content;
        int status = 0;
        char err[256];
        Buf req;

        buf_init(&body);
        http_request_body(&body, model, msgs, *nmsg);
        buf_init(&req);
        buf_put(&req, body.p, body.len);
        buf_free(&body);

        buf_init(&response);
        if (post_with_reconnect(tls, host, ip, port, path, key,
                                (const char *)req.p, req.len,
                                &response, err, sizeof(err)) != 0) {
            buf_free(&req); buf_free(&response);
            fprintf(stderr, "emerag-nano: %s\n", err);
            return -1;
        }
        buf_free(&req);
        if (http_body(&response, &resp_body, &status) != 0) {
            buf_free(&response);
            fprintf(stderr, "emerag-nano: malformed HTTP response\n");
            return -1;
        }
        buf_free(&response);
        buf_putc(&resp_body, 0);
        if (status != 200) {
            fprintf(stderr, "emerag-nano: HTTP %d: %.500s\n", status, (char *)resp_body.p);
            buf_free(&resp_body);
            return -1;
        }
        content = extract_content((char *)resp_body.p);
        buf_free(&resp_body);
        if (!content) {
            fprintf(stderr, "emerag-nano: no message content in response\n");
            return -1;
        }
        if (*content) {
            printf("%s", content);
            if (content[strlen(content)-1] != '\n') printf("\n");
            fflush(stdout);
        }
        msg_add(msgs, nmsg, "assistant", content);

        {
            const char *cmd = shell_command(content);
            if (!cmd || !*cmd || !allow_shell) {
                nano_free(content);
                return 0;
            }
            printf("[shell] %s\n", cmd);
            fflush(stdout);
            if (ask) {
                char answer[32];
                printf("run? [y/N] ");
                fflush(stdout);
                if (!fgets(answer, sizeof(answer), stdin) ||
                    (answer[0] != 'y' && answer[0] != 'Y')) {
                    msg_add(msgs, nmsg, "user", "Command denied by the user.");
                    nano_free(content);
                    continue;
                }
            }
            {
                Buf out;
                buf_init(&out);
                if (run_shell(cmd, &out) != 0) {
                    buf_puts(&out, "command failed to start\n");
                }
                if (out.len > NANO_SHELL_OUT) {
                    out.len = NANO_SHELL_OUT;
                    buf_puts(&out, "\n[output truncated]\n");
                }
                buf_putc(&out, 0);
                printf("%s", (char *)out.p);
                fflush(stdout);
                msg_add(msgs, nmsg, "user", (char *)out.p);
                buf_free(&out);
            }
        }
        nano_free(content);
    }
    fprintf(stderr, "emerag-nano: tool loop limit reached\n");
    return -1;
}

static void copy_str(char *dst, size_t cap, const char *src) {
    if (cap == 0) return;
    if (!src) src = "";
    strncpy(dst, src, cap - 1);
    dst[cap - 1] = 0;
}

/* Parse https://host[:port][/path]. Returns 0 on success, -1 on a bad URL,
 * -2 when the URL is plain http (nano has TLS only). */
static int parse_endpoint(const char *url, char *host, size_t hostcap,
                          char *path, size_t pathcap, int *port) {
    const char *p = url;
    const char *slash;
    char *colon;
    size_t n;
    if (!url || !*url) return -1;
    if (strncmp(p, "https://", 8) == 0) {
        p += 8;
    } else if (strncmp(p, "http://", 7) == 0) {
        return -2;
    }
    slash = strchr(p, '/');
    n = slash ? (size_t)(slash - p) : strlen(p);
    if (n == 0 || n >= hostcap) return -1;
    memcpy(host, p, n);
    host[n] = 0;
    colon = strchr(host, ':');
    if (colon) {
        *colon = 0;
        if (!colon[1]) return -1;
        *port = atoi(colon + 1);
        if (*port < 1 || *port > 65535) return -1;
    } else {
        *port = 443;
    }
    if (!slash || !slash[1]) {
        copy_str(path, pathcap, "/chat/completions");
    } else {
        copy_str(path, pathcap, slash);
        if (strcmp(path, "/") == 0) {
            copy_str(path, pathcap, "/chat/completions");
        } else if (strlen(path) >= 3 &&
                   strcmp(path + strlen(path) - 3, "/v1") == 0) {
            if (strlen(path) + 17 >= pathcap) return -1;
            strcat(path, "/chat/completions");
        }
    }
    return 0;
}

static void compact_msgs(Msg *msgs, int *nmsg) {
    int keep = 4;
    int old = *nmsg;
    int drop;
    int i;
    if (old <= keep + 1) {
        printf("compact: nothing to do (%d messages)\n", old);
        return;
    }
    drop = old - 1 - keep;
    for (i = 1; i <= drop; i++) msg_free(&msgs[i]);
    for (i = 1 + drop; i < old; i++) msgs[i - drop] = msgs[i];
    *nmsg = old - drop;
    for (i = *nmsg; i < old; i++) {
        msgs[i].role = NULL;
        msgs[i].content = NULL;
    }
    printf("compact: dropped %d oldest messages; %d remain\n", drop, *nmsg);
}

static void clear_msgs(Msg *msgs, int *nmsg) {
    int i;
    for (i = 1; i < *nmsg; i++) msg_free(&msgs[i]);
    *nmsg = 1;
    printf("session cleared\n");
}

static void nano_help(void) {
    printf("commands:\n");
    printf("  /help                         this text\n");
    printf("  /compact                      drop oldest messages, keep recent context\n");
    printf("  /clear                        clear the conversation, keep the system prompt\n");
    printf("  /yolo                         toggle auto-run of model SHELL commands\n");
    printf("  /model URL KEY [IP]           change endpoint, key and optional pinned IPv4\n");
    printf("  /quit                         exit\n");
}

/* Change endpoint/key and reconnect. The old connection is kept if the new
 * one fails, so a typo does not destroy a working session. */
static void cmd_model(char *args, char *host, size_t hostcap,
                      char *path, size_t pathcap, char *key, size_t keycap,
                      char *ip, size_t ipcap, int *port, Tls **tls) {
    char *url;
    char *newkey;
    char *newip;
    char newhost[256];
    char newpath[512];
    char newipbuf[64];
    char err[256];
    int newport = 443;
    int rc;
    Tls *newtls;

    url = strtok(args, " \t");
    newkey = strtok(NULL, " \t");
    newip = strtok(NULL, " \t");
    if (!url) {
        printf("endpoint: %s:%d%s\n", host, *port, path);
        printf("usage: /model https://host[/path] KEY [IP]\n");
        return;
    }
    if (!newkey || !*newkey) {
        printf("usage: /model https://host[/path] KEY [IP]\n");
        return;
    }
    if (strtok(NULL, " \t")) {
        printf("usage: /model https://host[/path] KEY [IP]\n");
        return;
    }
    newipbuf[0] = 0;
    if (newip) copy_str(newipbuf, sizeof(newipbuf), newip);
    rc = parse_endpoint(url, newhost, sizeof(newhost),
                        newpath, sizeof(newpath), &newport);
    if (rc == -2) {
        printf("nano speaks TLS only; use https://\n");
        return;
    }
    if (rc != 0) {
        printf("bad endpoint: %s\n", url);
        return;
    }
    newtls = tls_connect(newhost, newipbuf[0] ? newipbuf : NULL, newport,
                         err, sizeof(err));
    if (!newtls) {
        printf("cannot connect to %s:%d: %s (old endpoint kept)\n",
               newhost, newport, err);
        return;
    }
    tls_close(*tls);
    *tls = newtls;
    copy_str(host, hostcap, newhost);
    copy_str(path, pathcap, newpath);
    copy_str(key, keycap, newkey);
    copy_str(ip, ipcap, newipbuf);
    *port = newport;
    printf("endpoint: %s:%d%s (key set%s%s)\n", host, *port, path,
           ip[0] ? ", ip " : "", ip);
}

static void usage(void) {
    printf("emerag-nano %s - tiny C emergency agent\n", NANO_VERSION);
    printf("TLS 1.3 + Chat Completions only. NO CERTIFICATE VERIFICATION.\n\n");
    printf("Usage: emerag-nano [options] [prompt]\n\n");
    printf("  --host HOST       API host / TLS name (default api.deepseek.com)\n");
    printf("  --ip ADDR         connect to IPv4, keep HOST for TLS/SNI\n");
    printf("  --port PORT       TCP port (default 443)\n");
    printf("  --path PATH       chat path (default /chat/completions)\n");
    printf("  --model ID        model (default deepseek-chat)\n");
    printf("  --key KEY         API key (or EMERAG_API_KEY)\n");
    printf("  -p, --once TEXT   run one prompt and exit\n");
    printf("  --ask             ask before running a shell command\n");
    printf("  --no-shell        never execute model-requested commands\n");
    printf("  --max-turns N     shell loop limit (default 6)\n");
    printf("  --version         print version\n");
    printf("  -h, --help        this text\n\n");
    printf("Environment: EMERAG_API_KEY, EMERAG_MODEL, EMERAG_HOST\n");
}

int main(int argc, char **argv) {
    char hostbuf[256];
    char pathbuf[512];
    char keybuf[1024];
    char ipbuf[64];
    const char *host = "api.deepseek.com";
    const char *path = "/chat/completions";
    const char *model = "deepseek-chat";
    const char *key = "";
    const char *once = NULL;
    const char *ip = NULL;
    int port = 443;
    int ask = 0;
    int allow_shell = 1;
    int max_turns = 6;
    int i;
    Msg msgs[NANO_MAX_MSGS];
    int nmsg = 0;
    Tls *tls;
    char err[256];

    console_utf8();
    memset(msgs, 0, sizeof(msgs));
    if (getenv("EMERAG_API_KEY")) key = getenv("EMERAG_API_KEY");
    if (getenv("EMERAG_MODEL")) model = getenv("EMERAG_MODEL");
    if (getenv("EMERAG_HOST")) host = getenv("EMERAG_HOST");

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) host = argv[++i];
        else if (strcmp(argv[i], "--ip") == 0 && i + 1 < argc) ip = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--path") == 0 && i + 1 < argc) path = argv[++i];
        else if (strcmp(argv[i], "--model") == 0 && i + 1 < argc) model = argv[++i];
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) key = argv[++i];
        else if ((strcmp(argv[i], "--once") == 0 || strcmp(argv[i], "-p") == 0) && i + 1 < argc) once = argv[++i];
        else if (strcmp(argv[i], "--ask") == 0) ask = 1;
        else if (strcmp(argv[i], "--no-shell") == 0) allow_shell = 0;
        else if (strcmp(argv[i], "--max-turns") == 0 && i + 1 < argc) max_turns = atoi(argv[++i]);
        else if (strcmp(argv[i], "--insecure") == 0) { /* always */ }
        else if (strcmp(argv[i], "--version") == 0) { printf("emerag-nano %s\n", NANO_VERSION); return 0; }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) { usage(); return 0; }
        else if (argv[i][0] == '-') { fprintf(stderr, "emerag-nano: unknown option %s\n", argv[i]); return 2; }
        else once = argv[i];
    }
    copy_str(hostbuf, sizeof(hostbuf), host);
    copy_str(pathbuf, sizeof(pathbuf), path);
    copy_str(keybuf, sizeof(keybuf), key);
    copy_str(ipbuf, sizeof(ipbuf), ip ? ip : "");
    host = hostbuf;
    path = pathbuf;
    key = keybuf;
    ip = ipbuf[0] ? ipbuf : NULL;
    if (!once) {
        /* Nothing: interactive */
    }
    printf("emerag-nano %s\n", NANO_VERSION);
    printf("TLS 1.3 / Chat Completions / C\n");
    printf("WARNING: certificate verification is disabled; no CA store is embedded.\n");
    printf("host %s:%d%s  model %s\n", host, port, path, model);
    if (!key || !*key) printf("warning: no API key (set --key or EMERAG_API_KEY)\n");
    printf("Type /help for commands. Commands requested by the model are printed before running.\n\n");
    fflush(stdout);

    tls = tls_connect(host, ip, port, err, sizeof(err));
    if (!tls) {
        fprintf(stderr, "emerag-nano: TLS: %s\n", err);
        return 1;
    }
    msg_add(msgs, &nmsg, "system", SYSTEM_PROMPT);
    if (once) {
        msg_add(msgs, &nmsg, "user", once);
        chat_turn(&tls, host, ip, port, path, model, key, msgs, &nmsg,
                  ask, allow_shell, max_turns);
    } else {
        char line[4096];
        for (;;) {
            printf("nano> ");
            fflush(stdout);
            if (!fgets(line, sizeof(line), stdin)) break;
            {
                size_t n = strlen(line);
                while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r')) line[--n] = 0;
            }
            if (strcmp(line, "/quit") == 0 || strcmp(line, "/q") == 0) break;
            if (line[0] == 0) continue;
            if (strcmp(line, "/help") == 0) {
                nano_help();
                continue;
            }
            if (strcmp(line, "/compact") == 0) {
                compact_msgs(msgs, &nmsg);
                continue;
            }
            if (strcmp(line, "/clear") == 0) {
                clear_msgs(msgs, &nmsg);
                continue;
            }
            if (strcmp(line, "/yolo") == 0) {
                ask = !ask;
                printf("mode: %s\n", ask ? "ask before SHELL commands" : "yolo: run SHELL commands without asking");
                if (!allow_shell) printf("note: --no-shell is still in effect\n");
                continue;
            }
            if (strncmp(line, "/model", 6) == 0 &&
                (line[6] == 0 || line[6] == ' ' || line[6] == '\t')) {
                char *arg = line + 6;
                while (*arg == ' ' || *arg == '\t') arg++;
                cmd_model(arg, hostbuf, sizeof(hostbuf),
                          pathbuf, sizeof(pathbuf),
                          keybuf, sizeof(keybuf),
                          ipbuf, sizeof(ipbuf), &port, &tls);
                continue;
            }
            if (line[0] == '/') {
                printf("unknown command '%s'; /help\n", line);
                continue;
            }
            msg_add(msgs, &nmsg, "user", line);
            chat_turn(&tls, host, ip, port, path, model, key, msgs, &nmsg,
                      ask, allow_shell, max_turns);
            if (nmsg >= NANO_MAX_MSGS - 1) {
                /* keep system + last few */
                while (nmsg > 4) {
                    msg_free(&msgs[1]);
                    for (i = 1; i < nmsg - 1; i++) msgs[i] = msgs[i+1];
                    nmsg--;
                }
            }
        }
    }
    for (i = 0; i < nmsg; i++) msg_free(&msgs[i]);
    tls_close(tls);
    return 0;
}
