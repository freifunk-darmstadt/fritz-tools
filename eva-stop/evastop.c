// SPDX-License-Identifier: GPL-3.0-only

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <linux/if.h>
#include <linux/in.h>

#include <sys/types.h>
#include <sys/socket.h>

#define EVA_ADDRESS         "255.255.255.255"
#define EVA_PORT            5035
#define EVA_PACKET_SIZE     16

#define RCV_BUF_SIZE        25

void show_help(char *app)
{
    printf("Usage: %s IFNAME BOXIP\n", app);
}

int main(int argc, char *argv[])
{
    char packet[EVA_PACKET_SIZE] = {0x00, 0x00, 0x12, 0x01, 0x01, 0x00, 0x00, 0x00,
                                    0xc0, 0xa8, 0xb2, 0x01, 0x00, 0x00, 0x00, 0x00};
    char *packet_ip = &packet[8];

    char rcv_buf[RCV_BUF_SIZE];

    struct timeval sock_timeout = {0};
    struct sockaddr_in src = {0};
    struct sockaddr_in dst = {0};
    const int sock_bcast_enabled = 1;

    char *ipaddress;
    char *ifname;
    int ret;
    int sd;

    sock_timeout.tv_sec = 1;
    sock_timeout.tv_usec = 0;

    src.sin_family = AF_INET;
    src.sin_port = htons(EVA_PORT);

    dst.sin_family = AF_INET;
    dst.sin_port = htons(EVA_PORT);

    if (argc != 3) {
        show_help(argv[0]);
        return 1;
    }

    ifname = argv[1];
    ipaddress = argv[2];

    if (inet_pton(AF_INET, ipaddress, packet_ip) != 1) {
        printf("%s is not a valid IPv4 address\n", ipaddress);
        return 1;
    }

    if (inet_pton(AF_INET, EVA_ADDRESS, &dst.sin_addr) != 1) {
        perror("Error converting EVA IP address");
        return 1;
    }

    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0) {
        perror("Error creating socket");
        return 1;
    }

    if (bind(sd, (struct sockaddr *) &src, sizeof(src)) < 0) {
        perror("Error binding socket to port");
        close(sd);
        return 1;
    }

    if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strnlen(ifname, IFNAMSIZ)) < 0) {
        perror("Error binding to interface");
        close(sd);
        return 1;
    }

    if (setsockopt(sd, SOL_SOCKET, SO_BROADCAST, &sock_bcast_enabled, sizeof(sock_bcast_enabled)) < 0) {
        perror("Error enabling broadcast");
        close(sd);
        return 1;
    }

    if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &sock_timeout, sizeof(sock_timeout)) < 0) {
        perror("Error setting socket receive timeout");
        close(sd);
        return 1;
    }

    for (int i = 1; 1; i++) {
        printf("Sending halt %d.\n", i);
        if (sendto(sd, packet, EVA_PACKET_SIZE, 0, (const void *) &dst, sizeof(dst)) < 0) {
            perror("Error sending message");
            close(sd);
            return 1;
        }
        
        ret = recv(sd, &rcv_buf, RCV_BUF_SIZE, 0);
        if (ret > 0) {
            break;
        }
    }

    close(sd);
    return 0;
}