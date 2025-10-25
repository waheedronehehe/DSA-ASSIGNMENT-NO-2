// Use Sudo Command to run code as it does capturing of packets
// Compile: g++ -std=c++17 
// Run: sudo ./network_monitor <interface> <filter_src_IP> <filter_dst_IP>

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>           // for interface flags and ifreq
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_packet.h> 
#include <linux/if_ether.h>   
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <ctime>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>


using namespace std;

// constant elements
constexpr int MAX_PACKET_SIZE = 65536;
constexpr int ETH_MTU = 1500;
constexpr int MAX_QUEUE_CAPACITY = 5000;
constexpr int REPLAY_RETRIES = 2;
constexpr int SKIP_OVERSIZED_THRESHOLD = 10; // threshold
constexpr int OVERSIZED_DECAY_SECONDS = 30;  // reset oversizedCount every 30s
constexpr int DEMO_DURATION_SECONDS = 60;    // 1 minute demo

// utilities
static string nowStr() {
    time_t t = time(nullptr);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&t));
    return string(buf);
}

static string ipToStr(uint32_t ip_net_order) {
    struct in_addr a; a.s_addr = ip_net_order;
    return string(inet_ntoa(a));
}

static string ipv6ToStr(const struct in6_addr &addr6) {
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &addr6, buf, sizeof(buf));
    return string(buf);
}

// LayerStack 
struct LayerStack {
    const static int MAX_LAYERS = 16;
    string layers[MAX_LAYERS];
    int top;
    LayerStack(): top(-1) {}
    bool push(const string &s) {
        if (top >= MAX_LAYERS - 1) return false;
        layers[++top] = s;
        return true;
    }
    string pop() {
        if (top < 0) return string();
        return layers[top--];
    }
    bool isEmpty() const { return top < 0; }
};

// packet struct
struct Packet {
    uint64_t id;
    string timestamp;
    int size;
    unsigned char data[MAX_PACKET_SIZE]; // fixed buffer
    // parsed fields
    bool is_ipv4;
    bool is_ipv6;
    string srcIP;
    string dstIP;
    uint16_t srcPort;
    uint16_t dstPort;

    Packet() {
        id = 0; size = 0; is_ipv4 = is_ipv6 = false;
        srcPort = dstPort = 0;
        timestamp.clear(); srcIP.clear(); dstIP.clear();
    }
};


// circular PacketQueue
struct PacketQueue {
    Packet buffer[MAX_QUEUE_CAPACITY];
    int head;
    int tail;
    int count;
    mutex m;
    condition_variable cv;
    PacketQueue(): head(0), tail(-1), count(0) {}

    bool enqueue(const Packet &p) {
        unique_lock<mutex> lock(m);
        if (count >= MAX_QUEUE_CAPACITY) return false;
        tail = (tail + 1) % MAX_QUEUE_CAPACITY;
        buffer[tail] = p;
        ++count;
        cv.notify_one();
        return true;
    }

    // blocking dequeue 
    bool dequeue(Packet &out, atomic<bool> &running) {
        unique_lock<mutex> lock(m);
        cv.wait(lock, [&]() { return count > 0 || !running.load(); });
        if (count == 0) return false;
        out = buffer[head];
        head = (head + 1) % MAX_QUEUE_CAPACITY;
        --count;
        return true;
    }

    bool try_dequeue(Packet &out) {
        unique_lock<mutex> lock(m);
        if (count == 0) return false;
        out = buffer[head];
        head = (head + 1) % MAX_QUEUE_CAPACITY;
        --count;
        return true;
    }

    int size() {
        unique_lock<mutex> lock(m);
        return count;
    }

    void notify_all() {
        cv.notify_all();
    }
};


// Global queues
PacketQueue mainQueue;    
PacketQueue filterQueue;  
PacketQueue replayQueue;  
PacketQueue backupQueue; 

atomic<bool> running(false);
atomic<uint64_t> globalPacketID(1);
atomic<int> oversizedCount(0);
atomic<uint64_t> capturedSuccessfullyCount(0);
time_t lastOversizedReset = 0; // manage decay

// helpers for interface
int getInterfaceIndex(int sockfd, const string &ifname) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) return -1;
    return ifr.ifr_ifindex;
}

bool getInterfaceMAC(int sockfd, const string &ifname, unsigned char mac_out[6]) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) return false;
    memcpy(mac_out, ifr.ifr_hwaddr.sa_data, 6);
    return true;
}


// Globals from command-line
string filter_src_ip;
string filter_dst_ip;
bool filterIsV4 = false;
bool filterIsV6 = false;


void captureThreadFunc(const string &ifname, atomic<bool> &captureReady) {
    int rawsock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (rawsock == -1) {
        perror("capture: socket");
        captureReady = false;
        return;
    }

    int ifindex = getInterfaceIndex(rawsock, ifname);
    if (ifindex < 0) {
        cerr << "[" << nowStr() << "] capture: cannot get index for interface " << ifname << "\n";
        close(rawsock);
        captureReady = false;
        return;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;
    if (bind(rawsock, (struct sockaddr*)&sll, sizeof(sll)) == -1) {
        perror("capture: bind");
        close(rawsock);
        captureReady = false;
        return;
    }

    // show interface MAC
    unsigned char mac[6];
    if (getInterfaceMAC(rawsock, ifname, mac)) {
        char macs[64];
        snprintf(macs, sizeof(macs), "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        cout << "[" << nowStr() << "] Interface " << ifname << " MAC: " << macs << "\n";
    }

    captureReady = true;
    cout << "[" << nowStr() << "] Capture thread started on " << ifname << "\n";

    unsigned char buffer[MAX_PACKET_SIZE];

    while (running.load()) {
        ssize_t data_size = recvfrom(rawsock, buffer, MAX_PACKET_SIZE, 0, nullptr, nullptr);
        if (data_size < 0) {
            if (errno == EINTR) continue;
            perror("capture: recvfrom");
            // continue in loop, allow transient errors
            continue;
        }

        Packet p;
        p.id = globalPacketID.fetch_add(1);
        p.timestamp = nowStr();
        p.size = (int)data_size;
        if (p.size > MAX_PACKET_SIZE) p.size = MAX_PACKET_SIZE;
        memcpy(p.data, buffer, p.size);

        // Oversized handling: check BEFORE incrementing the counter
        time_t now = time(nullptr);
        if (now - lastOversizedReset >= OVERSIZED_DECAY_SECONDS) {
            oversizedCount.store(0);
            lastOversizedReset = now;
        }

        if (p.size > ETH_MTU) {
            int curr = oversizedCount.load();
            if (curr >= SKIP_OVERSIZED_THRESHOLD) {
                cout << "[" << nowStr() << "] Skipping oversized packet #" << p.id << " size=" << p.size << " (threshold reached)\n";
                continue; // skip enqueue
            } else {
                oversizedCount.fetch_add(1);
            }
        }

        if (!mainQueue.enqueue(p)) {
            cerr << "[" << nowStr() << "] mainQueue full; dropping packet " << p.id << "\n";
            continue;
        } else {
            capturedSuccessfullyCount.fetch_add(1);
            // Do NOT duplicate to other queues. Dissector will read from mainQueue.
            cout << "[" << nowStr() << "] Captured packet id=" << p.id << " size=" << p.size << "\n";
        }
    }

    close(rawsock);
    cout << "[" << nowStr() << "] Capture thread exiting\n";
}

// IPv6 extension header helper
// returns offset advanced (or same) and next header in 'next_hdr'. If failure, returns false.
bool skipIPv6Extensions(const unsigned char *data, int size, size_t &offset, uint8_t &next_hdr) {
    if (offset + sizeof(struct ip6_hdr) > (size_t)size) return false;
    struct ip6_hdr *ip6h = (struct ip6_hdr *)(data + offset);
    next_hdr = ip6h->ip6_nxt;
    offset += sizeof(struct ip6_hdr);

    // Loop through common extension headers: Hop-by-Hop (0), Routing (43), Fragment (44), Destination Options (60)
    // Each extension header has: next header (1 byte), hdr ext len (1 byte), then body.
    while (next_hdr == 0 || next_hdr == 43 || next_hdr == 44 || next_hdr == 60) {
        if (offset + 2 > (size_t)size) return false;
        uint8_t nh = *(data + offset); // next header
        uint8_t hdrlen = *(data + offset + 1); // in 8-octet units, not including first 8 bytes for some types
        size_t skip = 8 + (size_t)hdrlen * 8; // general formula
        // For fragment header (44), length is fixed 8 bytes
        if (next_hdr == 44) skip = 8;
        if (offset + skip > (size_t)size) return false;
        offset += skip;
        next_hdr = nh;
    }
    return true;
}

// Dissection thread: 
void dissectPacketInPlace(Packet &p) {
    LayerStack ls;
    ls.push("Ethernet");

    if (p.size < (int)sizeof(struct ethhdr)) {
        cout << "[" << nowStr() << "] Packet " << p.id << " too small for Ethernet header\n";
        return;
    }

    struct ethhdr *eth = (struct ethhdr *)p.data;
    uint16_t eth_type = ntohs(eth->h_proto);

    size_t offset = sizeof(struct ethhdr);

    if (eth_type == ETH_P_IP) {
        ls.push("IPv4");
        if (p.size >= (int)(offset + sizeof(struct iphdr))) {
            struct iphdr *iph = (struct iphdr *)(p.data + offset);
            p.is_ipv4 = true;
            p.srcIP = ipToStr(iph->saddr);
            p.dstIP = ipToStr(iph->daddr);
            int iphdrlen = iph->ihl * 4;
            offset += iphdrlen;
            if (iph->protocol == IPPROTO_TCP) {
                ls.push("TCP");
                if (p.size >= (int)(offset + sizeof(struct tcphdr))) {
                    struct tcphdr *tcph = (struct tcphdr *)(p.data + offset);
                    p.srcPort = ntohs(tcph->source);
                    p.dstPort = ntohs(tcph->dest);
                }
            } else if (iph->protocol == IPPROTO_UDP) {
                ls.push("UDP");
                if (p.size >= (int)(offset + sizeof(struct udphdr))) {
                    struct udphdr *udph = (struct udphdr *)(p.data + offset);
                    p.srcPort = ntohs(udph->source);
                    p.dstPort = ntohs(udph->dest);
                }
            }
        } else {
            cout << "[" << nowStr() << "] Packet " << p.id << " malformed IPv4\n";
        }
    } else if (eth_type == ETH_P_IPV6) {
        ls.push("IPv6");
        uint8_t next_hdr = 0;
        size_t new_offset = offset - sizeof(struct ethhdr);
if (skipIPv6Extensions(p.data, p.size, new_offset, next_hdr)) {
            // Note: skipIPv6Extensions advanced offset relative to eth header processing, so
            // we recompute absolute offset:
            size_t ip6_offset = sizeof(struct ethhdr) + sizeof(struct ip6_hdr);
            // However skipIPv6Extensions already moved offset; rebuild offset for safety:
            // We'll do a conservative approach: re-parse ip6 header at eth offset:
            size_t base = sizeof(struct ethhdr);
            if (p.size >= (int)(base + sizeof(struct ip6_hdr))) {
                struct ip6_hdr *ip6h = (struct ip6_hdr *)(p.data + base);
                p.is_ipv6 = true;
                p.srcIP = ipv6ToStr(ip6h->ip6_src);
                p.dstIP = ipv6ToStr(ip6h->ip6_dst);
                // Attempt to find TCP/UDP after extension parsing:
                size_t off = base + sizeof(struct ip6_hdr);
                uint8_t nxt = ip6h->ip6_nxt;
                // If extension headers present, perform safe skip
                bool ok = true;
                while (nxt == 0 || nxt == 43 || nxt == 44 || nxt == 60) {
                    if (off + 2 > (size_t)p.size) { ok = false; break; }
                    uint8_t nh = *(p.data + off);
                    uint8_t hdrlen = *(p.data + off + 1);
                    size_t skip = 8 + (size_t)hdrlen * 8;
                    if (nxt == 44) skip = 8;
                    if (off + skip > (size_t)p.size) { ok = false; break; }
                    off += skip;
                    nxt = nh;
                }
                if (ok) {
                    if (nxt == IPPROTO_TCP) {
                        ls.push("TCP");
                        if (off + sizeof(struct tcphdr) <= (size_t)p.size) {
                            struct tcphdr *tcph = (struct tcphdr *)(p.data + off);
                            p.srcPort = ntohs(tcph->source);
                            p.dstPort = ntohs(tcph->dest);
                        }
                    } else if (nxt == IPPROTO_UDP) {
                        ls.push("UDP");
                        if (off + sizeof(struct udphdr) <= (size_t)p.size) {
                            struct udphdr *udph = (struct udphdr *)(p.data + off);
                            p.srcPort = ntohs(udph->source);
                            p.dstPort = ntohs(udph->dest);
                        }
                    }
                }
            }
        } else {
            // fallback: try to read ip6 header directly if skip failed
            if (p.size >= (int)(offset + sizeof(struct ip6_hdr))) {
                struct ip6_hdr *ip6h = (struct ip6_hdr *)(p.data + offset);
                p.is_ipv6 = true;
                p.srcIP = ipv6ToStr(ip6h->ip6_src);
                p.dstIP = ipv6ToStr(ip6h->ip6_dst);
            }
        }
    } else {
        // other EtherType — nothing else required
    }

    // Show dissection order
    cout << "[" << nowStr() << "] Dissection Packet " << p.id << " - Layers:\n";
    while (!ls.isEmpty()) {
        cout << "   - " << ls.pop() << "\n";
    }

    cout << "   ID=" << p.id << " ts=" << p.timestamp << " size=" << p.size;
    if (p.is_ipv4 || p.is_ipv6) {
        cout << " src=" << p.srcIP << " dst=" << p.dstIP;
        if (p.srcPort || p.dstPort) cout << " sport=" << p.srcPort << " dport=" << p.dstPort;
    }
    cout << "\n";
}

void dissectionThreadFunc() {
    cout << "[" << nowStr() << "] Dissection thread started\n";
    while (running.load()) {
        Packet p;
        if (!mainQueue.dequeue(p, running)) continue;
        dissectPacketInPlace(p);
        // After dissection, enqueue into filterQueue
        if (!filterQueue.enqueue(p)) {
            cerr << "[" << nowStr() << "] filterQueue full; dropping packet " << p.id << "\n";
        }
    }
    cout << "[" << nowStr() << "] Dissection thread exiting\n";
}


// Filtering
bool packetMatchesFilter(const Packet &p) {
    if (filterIsV4 && p.is_ipv4) {
        return (p.srcIP == filter_src_ip && p.dstIP == filter_dst_ip);
    }
    if (filterIsV6 && p.is_ipv6) {
        return (p.srcIP == filter_src_ip && p.dstIP == filter_dst_ip);
    }
    return false;
}

void filteringThreadFunc() {
    cout << "[" << nowStr() << "] Filtering thread started\n";
    while (running.load()) {
        Packet p;
        if (!filterQueue.dequeue(p, running)) continue;

        // Oversized skip check (consistent with capture)
        if (p.size > ETH_MTU) {
            if (oversizedCount.load() >= SKIP_OVERSIZED_THRESHOLD) {
                cout << "[" << nowStr() << "] Filter: skipping oversized packet " << p.id << "\n";
                continue;
            }
        }

        if (packetMatchesFilter(p)) {
            double delay_ms = ((double)p.size) / 1000.0;
            cout << "[" << nowStr() << "] Filter: Packet " << p.id << " matches. Estimated delay=" << delay_ms << " ms\n";
            if (!replayQueue.enqueue(p)) {
                cerr << "[" << nowStr() << "] replayQueue full; moving to backup " << p.id << "\n";
                backupQueue.enqueue(p);
            }
        } else {
            // not a match -> do nothing
        }
    }
    cout << "[" << nowStr() << "] Filtering thread exiting\n";
}

// Replay 
void replayThreadFunc(const string &ifname, atomic<bool> &replayReady) {
    cout << "[" << nowStr() << "] Replay thread starting\n";
    int send_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (send_sock < 0) {
        perror("replay: socket");
        replayReady = false;
        return;
    }

    int ifindex = getInterfaceIndex(send_sock, ifname);
    if (ifindex < 0) {
        cerr << "[" << nowStr() << "] replay: cannot get interface index\n";
        close(send_sock);
        replayReady = false;
        return;
    }

    replayReady = true;

    struct sockaddr_ll device;
    memset(&device, 0, sizeof(device));
    device.sll_family = AF_PACKET;
    device.sll_ifindex = ifindex;
    device.sll_halen = ETH_ALEN;

    while (running.load()) {
        Packet p;
        if (!replayQueue.dequeue(p, running)) continue;

        // Prepare destination MAC from packet's Ethernet header (first 6 bytes)
        if (p.size >= (int)sizeof(struct ethhdr)) {
            memcpy(device.sll_addr, p.data, 6); // dest MAC at start of frame
        } else {
            memset(device.sll_addr, 0xff, 6); // fallback: broadcast
        }

        bool success = false;
        for (int attempt = 0; attempt <= REPLAY_RETRIES; ++attempt) {
            ssize_t sent = sendto(send_sock, p.data, p.size, 0, (struct sockaddr*)&device, sizeof(device));
            if (sent == (ssize_t)p.size) {
                cout << "[" << nowStr() << "] Replayed packet " << p.id << " successfully (attempt " << (attempt+1) << ")\n";
                success = true;
                break;
            } else {
                cerr << "[" << nowStr() << "] Replay attempt " << (attempt+1) << " failed for packet " << p.id << " errno=" << errno << "\n";
                if (attempt < REPLAY_RETRIES) {
                    this_thread::sleep_for(chrono::milliseconds(100));
                }
            }
        }
        if (!success) {
            cout << "[" << nowStr() << "] Moving packet " << p.id << " to backup after failed replay\n";
            backupQueue.enqueue(p);
        }
    }

    close(send_sock);
    cout << "[" << nowStr() << "] Replay thread exiting\n";
}

// Backup thread 
void backupThreadFunc() {
    cout << "[" << nowStr() << "] Backup thread started\n";
    while (running.load()) {
        int bsize = backupQueue.size();
        if (bsize > 0) {
            cout << "[" << nowStr() << "] Backup queue has " << bsize << " packets\n";
        }
        this_thread::sleep_for(chrono::seconds(5));
    }
    cout << "[" << nowStr() << "] Backup thread exiting\n";
}

// Display thread
void displayThreadFunc() {
    lastOversizedReset = time(nullptr);
    cout << "[" << nowStr() << "] Display thread started\n";
    while (running.load()) {
        cout << "STATUS (" << nowStr() << ") \n";
        cout << " mainQueue size: " << mainQueue.size() << "\n";
        cout << " filterQueue size: " << filterQueue.size() << "\n";
        cout << " replayQueue size: " << replayQueue.size() << "\n";
        cout << " backupQueue size: " << backupQueue.size() << "\n";
        cout << " Oversized count (window): " << oversizedCount.load() << "\n";
        cout << " Captured successfully: " << capturedSuccessfullyCount.load() << "\n";

        // Periodic decay of oversizedCount (safety reset)
        time_t now = time(nullptr);
        if (now - lastOversizedReset >= OVERSIZED_DECAY_SECONDS) {
            oversizedCount.store(0);
            lastOversizedReset = now;
        }

        this_thread::sleep_for(chrono::seconds(5));
    }
    cout << "[" << nowStr() << "] Display thread exiting\n";
}

// Validate filter IPs
bool validateFilterIPs(const string &src, const string &dst) {
    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, src.c_str(), &a4) == 1 && inet_pton(AF_INET, dst.c_str(), &a4) == 1) {
        filterIsV4 = true;
        filterIsV6 = false;
        return true;
    }
    if (inet_pton(AF_INET6, src.c_str(), &a6) == 1 && inet_pton(AF_INET6, dst.c_str(), &a6) == 1) {
        filterIsV6 = true;
        filterIsV4 = false;
        return true;
    }
    // Mixed family not supported for filtering in this simple implementation
    return false;
}

// MAIN
int main(int argc, char *argv[]) {
    if (argc < 4) {
        cerr << "Usage: sudo " << argv[0] << " <interface> <filter_src_IP> <filter_dst_IP>\n";
        cerr << "Example: sudo " << argv[0] << " eth0 192.168.1.10 192.168.1.20\n";
        return 1;
    }
    string ifname = argv[1];
    filter_src_ip = argv[2];
    filter_dst_ip = argv[3];

    if (!validateFilterIPs(filter_src_ip, filter_dst_ip)) {
        cerr << "Error: filter IPs invalid or mismatched families. Provide both IPv4 or both IPv6 addresses.\n";
        return 1;
    }

    cout << "Network Monitor starting on interface " << ifname << "\n";
    cout << "Filter: " << filter_src_ip << " -> " << filter_dst_ip << "\n";
    cout << "Demo will run for " << DEMO_DURATION_SECONDS << " seconds.\n";
    cout << "Ensure you run as root (raw sockets require privileges).\n";

    // Start threads carefully: create capture first and ensure it is ready
    running = true;
    atomic<bool> captureReady(false);
    atomic<bool> replayReady(false);

    thread capThread(captureThreadFunc, ifname, ref(captureReady));
    // Wait briefly for capture to initialize
    this_thread::sleep_for(chrono::seconds(1));
    if (!captureReady.load()) {
        cerr << "[" << nowStr() << "] Capture initialization failed. Exiting.\n";
        running = false;
        if (capThread.joinable()) capThread.join();
        return 1;
    }

    // start rest of threads
    thread disThread(dissectionThreadFunc);
    thread filtThread(filteringThreadFunc);
    thread repThread(replayThreadFunc, ifname, ref(replayReady));
    // Wait for replay initialization
    this_thread::sleep_for(chrono::milliseconds(500));
    if (!replayReady.load()) {
        cerr << "[" << nowStr() << "] Replay initialization failed. Stopping.\n";
        running = false;
        // notify to wake any blocking waits
        mainQueue.notify_all();
        filterQueue.notify_all();
        replayQueue.notify_all();
        backupQueue.notify_all();
        if (capThread.joinable()) capThread.join();
        if (disThread.joinable()) disThread.join();
        if (filtThread.joinable()) filtThread.join();
        return 1;
    }

    thread backThread(backupThreadFunc);
    thread dispThread(displayThreadFunc);

    // Run demo for required duration
    this_thread::sleep_for(chrono::seconds(DEMO_DURATION_SECONDS));

    // Stop
    cout << "[" << nowStr() << "] Demo time elapsed. Shutting down threads...\n";
    running = false;

    // notify all queues to wake blocked threads
    mainQueue.notify_all();
    filterQueue.notify_all();
    replayQueue.notify_all();
    backupQueue.notify_all();

    if (capThread.joinable()) capThread.join();
    if (disThread.joinable()) disThread.join();
    if (filtThread.joinable()) filtThread.join();
    if (repThread.joinable()) repThread.join();
    if (backThread.joinable()) backThread.join();
    if (dispThread.joinable()) dispThread.join();

    cout << "[" << nowStr() << "] Network Monitor demo finished.\n";
    cout << "Captured successfully: " << capturedSuccessfullyCount.load() << "\n";
    cout << "Total attempts (IDs issued): " << (globalPacketID.load() - 1) << "\n";
    cout << "Backup queue size: " << backupQueue.size() << "\n";
    cout << "Final oversized count (window): " << oversizedCount.load() << "\n";

    return 0;
}
