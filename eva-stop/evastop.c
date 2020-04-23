// SPDX-License-Identifier: GPL-3.0-only

#include <byteswap.h>
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
#define EVA_PACKET_IP_OFF   8

#define RCV_BUF_SIZE        25

#define IP4_ADDRESS_SIZE    4

void show_help(char *app)
{
    printf("Usage: %s IFNAME BOXIP\n", app);
}

void reverse(char *input, char *output, size_t len)
{
	for (int i = 0; i < len; i++) {
		output[i] = input[len - 1 - i];
	}
}

int create_socket(char *ifname)
{
    struct sockaddr_in src = {0};
    struct timeval timeout = {0};
    const int bcast_flag = 1;
    int sd;

    src.sin_family = AF_INET;
    src.sin_port = htons(EVA_PORT);

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0) {
        perror("Error creating socket");
        return -1;
    }

    if (bind(sd, (struct sockaddr *) &src, sizeof(struct sockaddr_in)) < 0) {
        perror("Error binding socket to port");
        close(sd);
        return -1;
    }

    if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strnlen(ifname, IFNAMSIZ)) < 0) {
        perror("Error binding to interface");
        close(sd);
        return -1;
    }

    if (setsockopt(sd, SOL_SOCKET, SO_BROADCAST, &bcast_flag, sizeof(int)) < 0) {
        perror("Error enabling broadcast");
        close(sd);
        return -1;
    }

    if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) < 0) {
        perror("Error setting socket receive timeout");
        close(sd);
        return -1;
    }

    return sd;
}

int add_conntrack(int sd, char *ipaddress)
{
    struct sockaddr_in dst = {0};
    char packet[] = "a";

    dst.sin_family = AF_INET;
    dst.sin_port = htons(EVA_PORT);
    memcpy(&dst.sin_addr, ipaddress, IP4_ADDRESS_SIZE);

    return sendto(sd, packet, sizeof(packet), 0, (const void *) &dst, sizeof(dst));
}

char *receive_response(int sd, char *out)
{
    char ip_buf[IP4_ADDRESS_SIZE] = {0};
    char rcv_buf[RCV_BUF_SIZE] = {0};
    int ret;

    ret = recv(sd, &rcv_buf, RCV_BUF_SIZE, 0);

    if (ret <= 0) {
        return 0;
    }

    reverse(&rcv_buf[EVA_PACKET_IP_OFF], ip_buf, IP4_ADDRESS_SIZE);
    inet_ntop(AF_INET, ip_buf, out, INET_ADDRSTRLEN);
    return out;
}

int main(int argc, char *argv[])
{
    char packet[EVA_PACKET_SIZE] = {0x00, 0x00, 0x12, 0x01, 0x01, 0x00, 0x00, 0x00,
                                    0xc0, 0xa8, 0xb2, 0x01, 0x00, 0x00, 0x00, 0x00};
    char *packet_ip = &packet[EVA_PACKET_IP_OFF];

    char box_ip_str[INET_ADDRSTRLEN] = {0};

    struct sockaddr_in dst = {0};

    char *ipaddress;
    char *ifname;

    int ret;
    int sd;

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

    sd = create_socket(ifname);

    if (sd < 0) {
        /* Error was already given to the user */
        return 1;
    }

    if (add_conntrack(sd, packet_ip) < 0) {
            perror("Error adding conntrack");
            close(sd);
            return 1;
    }

    for (int i = 1; 1; i++) {
        printf("Sending halt %d to device.\n", i);
        if (sendto(sd, packet, EVA_PACKET_SIZE, 0, (const void *) &dst, sizeof(dst)) < 0) {
            perror("Error sending message");
            close(sd);
            return 1;
        }

        receive_response(sd, box_ip_str);
        if (receive_response(sd, box_ip_str) > 0) {
            break;
        }
    }

    printf("EVA is now ready at %s\n", box_ip_str);

    close(sd);
    return 0;
}
