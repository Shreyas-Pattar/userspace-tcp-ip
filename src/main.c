#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include "tap.h"
#include "netdev.h"
#include "arp.h"
#include "ipv4.h"
#include "tcp.h"

static volatile int running = 1;

static void handle_sigint(int sig) {
    (void)sig;
    running = 0;
}

static uint8_t MY_MAC[ETH_ALEN] = {0x00, 0x0c, 0x29, 0xab, 0xcd, 0xef};

int main(void) {
    /* Disable glibc stdout heap buffer allocation */
    setvbuf(stdout, NULL, _IONBF, 0);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigint;
    sigaction(SIGINT, &sa, NULL);

    char dev_name[16] = "tap0";
    int tap_fd = tap_alloc(dev_name);

    if (tap_fd < 0) {
        fprintf(stderr, "Failed to allocate TAP device %s\n", dev_name);
        return 1;
    }

    uint32_t my_ip;
    inet_pton(AF_INET, "10.0.0.2", &my_ip);

    arp_init();
    tcp_init();

    printf("[+] Interface %s up (fd=%d)\n", dev_name, tap_fd);
    printf("[+] Userspace Stack IP: 10.0.0.2 | MAC: 00:0c:29:ab:cd:ef\n");
    printf("[+] Waiting for frames...\n");

    uint8_t buffer[BUF_SIZE];

    while (running) {
        ssize_t nread = read(tap_fd, buffer, sizeof(buffer));
        if (nread < 0) {
            break;
        }

        if ((size_t)nread < ETH_HLEN) continue;

        struct eth_hdr *eth = (struct eth_hdr *)buffer;
        uint16_t proto = ntohs(eth->ethertype);

        if (proto == ETH_P_ARP) {
            handle_arp(tap_fd, buffer, (size_t)nread, my_ip, MY_MAC);
        } else if (proto == ETH_P_IP) {
            handle_ipv4(tap_fd, buffer, (size_t)nread, my_ip, MY_MAC);
        }
    }

    printf("\n[+] Clean shutdown. Closing TAP device.\n");
    close(tap_fd);
    return 0;
}
