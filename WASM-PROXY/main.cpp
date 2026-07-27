/*
 * minetest-wasm-proxy-cpp
 * WebSocket <-> UDP proxy for minetest-wasm browser clients.
 * Uses uWebSockets for WebSocket, raw POSIX sockets for UDP relay.
 */

#include "App.h"
#include <libusockets.h>

#include <string>
#include <string_view>
#include <vector>
#include <regex>
#include <fstream>
#include <iostream>
#include <cstring>
#include <ctime>
#include <csignal>
#include <algorithm>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <cerrno>

/* ─── Config ─────────────────────────────────────────────────── */

struct Config {
    int port = 8888;
    std::string upstream_host = "127.0.0.1";
    int upstream_port = 30000;
    std::string dns_ip = "1.1.1.1";
};

static Config load_config(const char* path = "config.yml") {
    Config cfg;
    std::ifstream f(path);
    if (!f.is_open()) {
        std::cerr << "Warning: config.yml not found, using defaults" << std::endl;
        return cfg;
    }
    std::string line;
    while (std::getline(f, line)) {
        auto pos = line.find_first_not_of(" \t\r\n");
        if (pos == std::string::npos || line[pos] == '#') continue;
        auto end = line.find_last_not_of(" \t\r\n");
        line = line.substr(pos, end - pos + 1);

        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string key = line.substr(0, colon);
        std::string val = line.substr(colon + 1);
        auto vpos = val.find_first_not_of(" \t");
        if (vpos != std::string::npos) val = val.substr(vpos);

        if (key == "port") cfg.port = std::stoi(val);
        else if (key == "upstream") {
            auto c = val.find(':');
            if (c != std::string::npos) {
                cfg.upstream_host = val.substr(0, c);
                cfg.upstream_port = std::stoi(val.substr(c + 1));
            }
        } else if (key == "dns_ip") cfg.dns_ip = val;
    }
    return cfg;
}

/* ─── Global state ───────────────────────────────────────────── */

static Config g_config;
static sockaddr_in g_upstream_addr = {};

void log_line(const char* level, const std::string& msg) {
    time_t now = time(nullptr);
    char ts[20];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
    printf("[%s] %-5s %s\n", ts, level, msg.c_str());
    fflush(stdout);
}

/* Parse IPv4 from string to sockaddr_in */
static bool parse_addr(const std::string& host, int port, sockaddr_in& out) {
    memset(&out, 0, sizeof(out));
    out.sin_family = AF_INET;
    out.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &out.sin_addr) == 1) return true;

    struct addrinfo hints = {}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) == 0) {
        out.sin_addr = ((sockaddr_in*)res->ai_addr)->sin_addr;
        freeaddrinfo(res);
        return true;
    }
    return false;
}

static int create_udp_socket() {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    fcntl(fd, F_SETFL, O_NONBLOCK);
    return fd;
}

/* ─── Session state ──────────────────────────────────────────── */

enum SessionState { HANDSHAKE, RELAY_UDP, RELAY_DNS, SINK, DEAD };

struct SessionData {
    SessionState state = HANDSHAKE;
    int udp_fd = -1;
    std::string addr;         // real client IP (from X-Forwarded-For or remote addr)
};

/* Active UDP relay list — polled by the event-loop timer.
   All access from the event-loop thread, no locking needed. */
struct UdpRelay {
    uWS::WebSocket<false, true, SessionData>* ws;
    int fd;
};
static std::vector<UdpRelay> g_udp_relays;

/* ─── Proxy protocol ─────────────────────────────────────────── */

/* Parse and dispatch a PROXY handshake command.
   Returns true if the connection is now in a relay state. */
static void handle_handshake(
    uWS::WebSocket<false, true, SessionData>* ws,
    const std::string& text)
{
    auto* data = ws->getUserData();

    std::regex proxy_re(
        R"(PROXY\s+IPV[46]\s+(UDP|TCP)\s+(\S+)\s+(\d+))",
        std::regex::icase);
    std::smatch m;
    if (!std::regex_search(text, m, proxy_re)) {
        ws->send("UNSUPPORTED", uWS::OpCode::TEXT);
        return;
    }

    std::string proto = m[1].str();
    for (auto& c : proto) c = (char)toupper((unsigned char)c);
    std::string client_ip = m[2].str();
    int client_port = std::stoi(m[3].str());

    if (proto == "UDP") {
        int fd = create_udp_socket();
        if (fd < 0) {
            log_line("WARN", "[" + data->addr + "] failed to create UDP socket");
            ws->send("PROXY FAIL", uWS::OpCode::TEXT);
            return;
        }

        char buf[256];
        snprintf(buf, sizeof(buf),
            "[%s] UDP (client asked %s:%d) -> upstream %s:%d",
            data->addr.c_str(), client_ip.c_str(), client_port,
            g_config.upstream_host.c_str(), g_config.upstream_port);
        log_line("INFO", buf);

        data->state = RELAY_UDP;
        data->udp_fd = fd;
        g_udp_relays.push_back({ws, fd});
        ws->send("PROXY OK", uWS::OpCode::TEXT);
        return;
    }

    if (proto == "TCP" && client_ip == "10.0.0.1" && client_port == 53) {
        log_line("INFO", "[" + data->addr + "] DNS (fake)");
        data->state = RELAY_DNS;
        ws->send("PROXY OK", uWS::OpCode::TEXT);
        return;
    }

    if (proto == "TCP") {
        log_line("INFO", "[" + data->addr + "] TCP sink " +
            client_ip + ":" + std::to_string(client_port));
        data->state = SINK;
        ws->send("PROXY OK", uWS::OpCode::TEXT);
        return;
    }
}

/* ─── UDP polling timer callback ─────────────────────────────── */

static void poll_udp(us_timer_t* /*t*/) {
    char buf[65536];
    for (auto it = g_udp_relays.begin(); it != g_udp_relays.end(); ) {
        sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(it->fd, buf, sizeof(buf), MSG_DONTWAIT,
                             (sockaddr*)&from, &fromlen);
        if (n > 0) {
            it->ws->send(std::string_view(buf, (size_t)n), uWS::OpCode::BINARY);
            ++it;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            ++it;  // no data, try next
        } else {
            /* Socket error — the close handler will clean up.
               Keep iterating. */
            ++it;
        }
    }
}

/* ─── Main ───────────────────────────────────────────────────── */

int main(int argc, char** argv) {
    /* Load config — support alternative path via argv */
    const char* config_path = (argc > 1) ? argv[1] : "config.yml";
    g_config = load_config(config_path);

    if (!parse_addr(g_config.upstream_host, g_config.upstream_port,
                    g_upstream_addr)) {
        fprintf(stderr, "ERROR: Failed to resolve upstream: %s\n",
                g_config.upstream_host.c_str());
        return 1;
    }

    printf("minetest-wasm-proxy-cpp  ws://0.0.0.0:%d\n", g_config.port);
    printf("upstream: %s:%d\n",
           g_config.upstream_host.c_str(), g_config.upstream_port);
    printf("dns_ip:   %s\n", g_config.dns_ip.c_str());
    fflush(stdout);

    /* Build the uWS application */
    auto app = uWS::App()
    .ws<SessionData>("/*", {
        /* Behaviour settings */
        .compression = uWS::SHARED_COMPRESSOR,
        .maxPayloadLength = 64 * 1024 * 1024,   // 64 MiB
        .idleTimeout = 0,                        // never timeout
        .maxBackpressure = 64 * 1024 * 1024,
        .closeOnBackpressureLimit = false,
        .resetIdleTimeoutOnSend = false,         // timeout is disabled anyway
        .sendPingsAutomatically = false,

        /* Handlers */
        .upgrade = [](auto *res, auto *req, auto *context) {
            /* Read X-Forwarded-For from the HTTP upgrade request.
               When behind nginx/Cloudflare, the direct TCP connection
               comes from localhost — the real browser IP is in this header. */
            std::string real_ip;
            auto xff = req->getHeader("x-forwarded-for");
            if (!xff.empty()) {
                // X-Forwarded-For may contain a comma-separated chain;
                // the leftmost IP is the original client.
                auto comma = xff.find(',');
                real_ip = (comma != std::string_view::npos)
                    ? std::string(xff.substr(0, comma))
                    : std::string(xff);
                // Trim whitespace
                auto start = real_ip.find_first_not_of(" \t");
                if (start == std::string::npos) start = 0;
                real_ip = real_ip.substr(start);
            }
            SessionData sd;
            sd.state = HANDSHAKE;
            sd.addr = real_ip;

            res->template upgrade<SessionData>(
                std::move(sd),
                req->getHeader("sec-websocket-key"),
                req->getHeader("sec-websocket-protocol"),
                req->getHeader("sec-websocket-extensions"),
                context);
        },

        .open = [](auto* ws) {
            auto* data = ws->getUserData();
            data->state = HANDSHAKE;
            data->udp_fd = -1;
            // Use the real IP captured in .upgrade; fall back to
            // ws->getRemoteAddressAsText() if no X-Forwarded-For was set
            if (data->addr.empty())
                data->addr = std::string(ws->getRemoteAddressAsText());
            log_line("INFO", "[" + data->addr + "] connected");
        },

        .message = [](auto* ws, std::string_view message,
                      uWS::OpCode opCode) {
            auto* data = ws->getUserData();
            if (data->state == DEAD) return;

            /* ── Handshake: first message must be a PROXY text
               command ── */
            if (data->state == HANDSHAKE) {
                if (opCode != uWS::OpCode::TEXT) {
                    ws->close();
                    return;
                }
                handle_handshake(ws, std::string(message));
                return;
            }

            /* ── UDP relay: forward binary to upstream ── */
            if (data->state == RELAY_UDP) {
                sendto(data->udp_fd, message.data(), message.size(), 0,
                       (const sockaddr*)&g_upstream_addr,
                       sizeof(g_upstream_addr));
                return;
            }

            /* ── DNS: respond with the configured fake IP ── */
            if (data->state == RELAY_DNS) {
                std::string hostname(message);
                if (!hostname.empty() && hostname.back() == '\0')
                    hostname.pop_back();
                log_line("INFO", "[" + data->addr + "] DNS: " +
                    (hostname.empty() ? "(empty)" : hostname) +
                    " -> " + g_config.dns_ip);

                unsigned int a = 0, b = 0, c = 0, d = 0;
                char ip_buf[4];
                if (sscanf(g_config.dns_ip.c_str(), "%u.%u.%u.%u",
                           &a, &b, &c, &d) == 4) {
                    ip_buf[0] = (char)a;
                    ip_buf[1] = (char)b;
                    ip_buf[2] = (char)c;
                    ip_buf[3] = (char)d;
                    ws->send(std::string_view(ip_buf, 4),
                             uWS::OpCode::BINARY);
                }
                return;
            }

            /* ── SINK: silently discard ── */
        },

        .close = [](auto* ws, int /*code*/, std::string_view /*msg*/) {
            auto* data = ws->getUserData();
            if (data->state == RELAY_UDP && data->udp_fd >= 0) {
                g_udp_relays.erase(
                    std::remove_if(g_udp_relays.begin(),
                                   g_udp_relays.end(),
                        [ws](const UdpRelay& r) { return r.ws == ws; }),
                    g_udp_relays.end());
                close(data->udp_fd);
                data->udp_fd = -1;
            }
            log_line("INFO", "[" + data->addr + "] disconnected");
            data->state = DEAD;
        }
    })
    .listen(g_config.port, [](auto* listen_socket) {
        if (listen_socket) {
            std::cout << "Listening on port "
                      << g_config.port << std::endl;
        } else {
            std::cerr << "ERROR: Failed to listen on port "
                      << g_config.port << std::endl;
            exit(1);
        }
    });

    /* Get the event loop and install the UDP polling timer */
    auto* loop = app.getLoop();
    auto* us_loop = reinterpret_cast<struct us_loop_t*>(loop);
    struct us_timer_t* poll_timer = us_create_timer(us_loop, 1, 0);
    us_timer_set(poll_timer, poll_udp, 1, 1);  // 1 ms period

    /* Graceful shutdown on signals */
    signal(SIGINT, [](int) {
        log_line("INFO", "Received SIGINT, shutting down");
        exit(0);
    });
    signal(SIGTERM, [](int) {
        log_line("INFO", "Received SIGTERM, shutting down");
        exit(0);
    });

    app.run();
    return 0;
}
