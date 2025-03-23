#include <iostream>
#include <iomanip>
#include <cstring>
#include <vector>
#include <chrono>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <unistd.h>
#include <poll.h>

using namespace std;

#define MAX_TTL 30
#define PACKET_SIZE 64
#define TIMEOUT_MS 1000
#define ATTEMPTS 3

// Function to compute ICMP checksum
uint16_t compute_icmp_checksum(const void *buff, int length) {
    const uint16_t *ptr = static_cast<const uint16_t *>(buff);
    uint32_t sum = 0;
    
    for (int i = 0; i < length / 2; i++)
        sum += ptr[i];

    sum = (sum >> 16) + (sum & 0xffff);
    return ~static_cast<uint16_t>(sum + (sum >> 16));
}

// Structure for ICMP Packet
struct IcmpPacket {
    struct icmphdr header;
    char payload[PACKET_SIZE - sizeof(icmphdr)];
};

// Function to create ICMP packet
void create_icmp_packet(IcmpPacket &packet, int sequence) {
    memset(&packet, 0, sizeof(IcmpPacket));
    packet.header.type = ICMP_ECHO;
    packet.header.code = 0;
    packet.header.un.echo.id = getpid();
    packet.header.un.echo.sequence = sequence;
    packet.header.checksum = compute_icmp_checksum(&packet, sizeof(IcmpPacket));
}

// Function to send ICMP packet
void send_icmp(int sockfd, const sockaddr_in &target, int ttl, int sequence) {
    setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

    IcmpPacket packet;
    create_icmp_packet(packet, sequence);

    sendto(sockfd, &packet, sizeof(packet), 0, (struct sockaddr *)&target, sizeof(target));
}

// Function to receive ICMP response
bool receive_icmp(int sockfd, string &router_ip, double &rtt) {
    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);
    uint8_t buffer[IP_MAXPACKET];

    struct pollfd fds = {sockfd, POLLIN, 0};
    auto start = chrono::high_resolution_clock::now();

    int ret = poll(&fds, 1, TIMEOUT_MS);
    if (ret > 0) {
        ssize_t packet_len = recvfrom(sockfd, buffer, IP_MAXPACKET, 0, (struct sockaddr *)&sender, &sender_len);
        if (packet_len > 0) {
            auto end = chrono::high_resolution_clock::now();
            rtt = chrono::duration<double, milli>(end - start).count();

            char sender_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(sender.sin_addr), sender_ip_str, sizeof(sender_ip_str));
            router_ip = sender_ip_str;
            return true;
        }
    }

    rtt = -1;  // Timeout
    return false;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <destination IP>" << endl;
        return EXIT_FAILURE;
    }

    string destination = argv[1];
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("Socket error");
        return EXIT_FAILURE;
    }

    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    inet_pton(AF_INET, destination.c_str(), &target.sin_addr);

    cout << "Traceroute to " << destination << ", max " << MAX_TTL << " hops:\n";

    for (int ttl = 1; ttl <= MAX_TTL; ++ttl) {
        vector<string> routers;
        vector<double> times;

        for (int i = 0; i < ATTEMPTS; ++i) {
            send_icmp(sockfd, target, ttl, ttl * 10 + i);

            string router_ip;
            double rtt;
            if (receive_icmp(sockfd, router_ip, rtt)) {
                routers.push_back(router_ip);
                times.push_back(rtt);
            } else {
                routers.push_back("*");
            }
        }

        cout << ttl << ". ";
        if (routers[0] == "*" && routers[1] == "*" && routers[2] == "*") {
            cout << "*\n";
        } else {
            for (const auto &ip : routers) {
                cout << ip << " ";
            }

            if (times[0] < 0 && times[1] < 0 && times[2] < 0) {
                cout << "??? ms";
            } else {
                cout << fixed << setprecision(2) << (times[0] + times[1] + times[2]) / 3.0 << " ms";
            }

            cout << endl;
        }

        if (!routers.empty() && routers[0] == destination) {
            break;
        }
    }

    close(sockfd);
    return 0;
}
