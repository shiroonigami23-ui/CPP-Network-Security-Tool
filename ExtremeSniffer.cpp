
#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h> // For TCP header
#include <netinet/udp.h> // For UDP header
#include <arpa/inet.h>
#include <vector>
#include <map>
#include <set> // For tracking distinct ports
#include <string> // For string manipulation
#include <cstring> // For strstr, memcpy
#include <queue>   // For packet queue
#include <pthread.h> // For multithreading primitives
#include <unistd.h> // For sleep
#include <sstream> // For building JSON strings
#include <maxminddb.h> // For Geo-IP lookup

// --- Configuration ---
#define PORT_SCAN_THRESHOLD 5
#define CONNECTION_FLOOD_THRESHOLD 15 // Number of distinct connections for flood alert (IP:Port pairs)
#define PACKET_FLOOD_THRESHOLD 50    // Number of packets from a source for packet flood alert
#define NUM_PROCESSING_THREADS 2
#define PACKET_CAPTURE_LIMIT 100 // Limit for pcap_loop for demonstration
#define MMDB_DATABASE_PATH "/content/drive/My Drive/CPPNetworkSecurity/GeoLite2-City.mmdb"

// --- Data Structures ---

// Struct to hold general flow statistics
struct Stats {
    long total_bytes = 0;
    int packet_count = 0;
};

// Struct to hold raw packet data for thread-safe transfer
struct PacketData {
    struct pcap_pkthdr header;
    u_char *data; // Dynamically allocated raw packet data

    // Constructor to handle allocation and copying
    PacketData(const struct pcap_pkthdr *h, const u_char *p) : header(*h) {
        data = new u_char[header.len];
        memcpy(data, p, header.len);
    }

    // Destructor to handle deallocation
    ~PacketData() {
        delete[] data;
    }

    // Disable copy constructor and assignment operator to avoid double free issues
    PacketData(const PacketData&) = delete;
    PacketData& operator=(const PacketData&) = delete;

    // Enable move constructor and move assignment for efficiency with std::queue
    PacketData(PacketData&& other) noexcept
        : header(other.header), data(other.data) {
        other.data = nullptr; // Ensure source doesn't free the data
    }
    PacketData& operator=(PacketData&& other) noexcept {
        if (this != &other) {
            delete[] data; // Free existing data if any
            header = other.header;
            data = other.data;
            other.data = nullptr;
        }
        return *this;
    }
};

// --- Global Shared Resources ---
std::queue<PacketData> packet_queue;
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;
bool terminate_processing = false; // Flag to signal processing threads to exit

// Map to monitor general flow statistics by source IP
std::map<std::string, Stats> flow_monitor;

// Map to monitor distinct destination ports per source IP for anomaly detection (Port Scan)
std::map<std::string, std::set<u_int16_t>> port_scan_monitor;

// New: Map to monitor distinct connections (dst_ip:dst_port) per source IP for anomaly detection (Connection Flood)
std::map<std::string, std::set<std::pair<std::string, u_int16_t>>> connection_flood_monitor;

// MaxMindDB structures
MMDB_s mmdb;
pthread_mutex_t mmdb_mutex = PTHREAD_MUTEX_INITIALIZER; // Mutex for MMDB access

// --- Utility Functions ---

// Function to extract hostname from DNS query payload
std::string extract_dns_query_name(const u_char *payload, u_int16_t payload_len) {
    if (payload_len < 12) return ""; // DNS header is 12 bytes

    const u_char *qname_ptr = payload + 12; // Pointer to the start of the QNAME
    std::string qname_str;
    u_int label_len;

    while (qname_ptr < payload + payload_len && (label_len = *qname_ptr++) != 0) {
        if (qname_ptr + label_len > payload + payload_len) break; // Avoid buffer overflow
        if (!qname_str.empty()) qname_str += ".";
        qname_str.append(reinterpret_cast<const char*>(qname_ptr), label_len);
        qname_ptr += label_len;
    }
    return qname_str;
}

// Function to generate JSON alert
void generate_json_alert(const std::string& anomaly_type,
                         const std::string& src_ip,
                         const std::string& dst_ip,
                         long detected_value,
                         long threshold) {
    std::cout << "{\n";
    std::cout << "  \"anomaly_type\": \"" << anomaly_type << "\",\n";
    std::cout << "  \"source_ip\": \"" << src_ip << "\",\n";
    std::cout << "  \"destination_ip\": \"" << dst_ip << "\",\n";
    std::cout << "  \"detected_value\": " << detected_value << ",\n";
    std::cout << "  \"threshold\": " << threshold << "\n";
    std::cout << "}\n";
}

// Function to perform Geo-IP lookup and return string (City, Country)
std::string get_geo_info(const std::string& ip_address) {
    std::string country = "N/A";
    std::string city = "N/A";

    pthread_mutex_lock(&mmdb_mutex); // Protect MMDB access
    int gai_error, mmdb_error;
    MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, ip_address.c_str(), &gai_error, &mmdb_error);

    if (gai_error != 0) {
        // std::cerr << "Error from getaddrinfo for IP " << ip_address << ": " << gai_strerror(gai_error) << std::endl;
    } else if (mmdb_error != MMDB_SUCCESS) {
        // std::cerr << "Error from MaxMindDB lookup for IP " << ip_address << ": " << MMDB_strerror(mmdb_error) << std::endl;
    } else if (result.found_entry) {
        MMDB_entry_data_s entry_data;
        if (MMDB_get_value(&result.entry, &entry_data, "country", "names", "en", NULL) == MMDB_SUCCESS) {
            if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
                country.assign(entry_data.utf8_string, entry_data.data_size);
            }
        }
        if (MMDB_get_value(&result.entry, &entry_data, "city", "names", "en", NULL) == MMDB_SUCCESS) {
            if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
                city.assign(entry_data.utf8_string, entry_data.data_size);
            }
        }
    }
    pthread_mutex_unlock(&mmdb_mutex);
    return city + ", " + country;
}

// --- Packet Processing Logic (formerly secure_packet_handler) ---
void process_packet_data(const struct pcap_pkthdr *header, const u_char *packet) {
    // Skip Ethernet header (14 bytes) to get to the IP header
    struct ip *ip_header = (struct ip *)(packet + 14);

    std::string src_ip = inet_ntoa(ip_header->ip_src);
    std::string dst_ip = inet_ntoa(ip_header->ip_dst);

    u_int16_t src_port = 0;
    u_int16_t dst_port = 0;

    // Calculate IP header length
    u_int ip_header_len = ip_header->ip_hl * 4;

    const u_char *payload_start = NULL;
    u_int payload_len = 0;

    // Deep Packet Inspection (DPI-lite): Parse TCP/UDP headers
    if (ip_header->ip_p == IPPROTO_TCP) { // TCP protocol
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header_len);
        src_port = ntohs(tcp_header->th_sport);
        dst_port = ntohs(tcp_header->th_dport);

        // For Port Scan Detection: Track distinct destination ports for anomaly detection
        port_scan_monitor[src_ip].insert(dst_port);

        // For Connection Flood Detection: Track unique destination IP:Port connections
        connection_flood_monitor[src_ip].insert(std::make_pair(dst_ip, dst_port));


        // Calculate TCP header length and payload start/length
        u_int tcp_header_len = tcp_header->th_off * 4;
        payload_start = packet + 14 + ip_header_len + tcp_header_len;
        payload_len = header->len - (14 + ip_header_len + tcp_header_len);

        // HTTP DPI: Check for common HTTP ports and parse request/response
        if ((dst_port == 80 || dst_port == 8080) && payload_len > 0) {
            const char *http_payload = reinterpret_cast<const char*>(payload_start);
            // Ensure payload_str does not read beyond payload_len
            std::string payload_str(http_payload, payload_len < 200 ? payload_len : 200); // Limit string copy for safety

            // Detect HTTP method
            if (payload_str.rfind("GET ", 0) == 0) {
                std::cout << "    [HTTP] Method: GET" << std::endl;
            } else if (payload_str.rfind("POST ", 0) == 0) {
                std::cout << "    [HTTP] Method: POST" << std::endl;
            } else if (payload_str.rfind("PUT ", 0) == 0) {
                std::cout << "    [HTTP] Method: PUT" << std::endl;
            } else if (payload_str.rfind("DELETE ", 0) == 0) {
                std::cout << "    [HTTP] Method: DELETE" << std::endl;
            } else if (payload_str.rfind("HEAD ", 0) == 0) {
                std::cout << "    [HTTP] Method: HEAD" << std::endl;
            }

            // Extract User-Agent
            size_t ua_pos = payload_str.find("User-Agent: ");
            if (ua_pos != std::string::npos) {
                size_t ua_end = payload_str.find("\r\n", ua_pos);
                if (ua_end != std::string::npos) {
                    std::cout << "    [HTTP] User-Agent: " << payload_str.substr(ua_pos + 12, ua_end - (ua_pos + 12)) << std::endl;
                }
            }
        }
    } else if (ip_header->ip_p == IPPROTO_UDP) { // UDP protocol
        struct udphdr *udp_header = (struct udphdr *)(packet + 14 + ip_header_len);
        src_port = ntohs(udp_header->uh_sport);
        dst_port = ntohs(udp_header->uh_dport);

        // For Port Scan Detection: Track distinct destination ports for anomaly detection
        port_scan_monitor[src_ip].insert(dst_port);

        // For Connection Flood Detection: Track unique destination IP:Port connections
        connection_flood_monitor[src_ip].insert(std::make_pair(dst_ip, dst_port));

        // Calculate UDP header length and payload start/length
        u_int udp_header_len = 8; // UDP header is always 8 bytes
        payload_start = packet + 14 + ip_header_len + udp_header_len;
        payload_len = header->len - (14 + ip_header_len + udp_header_len);

        // DNS DPI: Check for DNS port and parse query
        if (dst_port == 53 && payload_len >= 12) { // DNS header is 12 bytes
            // Check if it's a DNS query (QR flag in flags field should be 0)
            u_int16_t flags = ntohs(*reinterpret_cast<const u_int16_t*>(payload_start + 2));
            if (!((flags >> 15) & 0x01)) { // QR bit (most significant bit) is 0 for query
                std::cout << "    [DNS] Query Detected!" << std::endl;
                std::string query_name = extract_dns_query_name(payload_start, payload_len);
                if (!query_name.empty()) {
                    std::cout << "    [DNS] Query Name: " << query_name << std::endl;
                }
                // For simplicity, we won't parse QTYPE and QCLASS in this basic example.
            }
        }
    }

    // Update real-time flow statistics
    flow_monitor[src_ip].total_bytes += header->len;
    flow_monitor[src_ip].packet_count++;

    // --- Anomaly Detection Logic ---

    // 1. Basic Anomaly Detection: Port Scanning
    if (port_scan_monitor[src_ip].size() >= PORT_SCAN_THRESHOLD) {
        generate_json_alert("Port Scan", src_ip, "N/A", port_scan_monitor[src_ip].size(), PORT_SCAN_THRESHOLD);
        // Optionally, reset the monitor for this IP or implement a more sophisticated time-based detection
        // port_scan_monitor[src_ip].clear();
    }

    // 2. Anomaly Detection: Connection Flood
    if (connection_flood_monitor[src_ip].size() >= CONNECTION_FLOOD_THRESHOLD) {
        generate_json_alert("Connection Flood", src_ip, "N/A", connection_flood_monitor[src_ip].size(), CONNECTION_FLOOD_THRESHOLD);
        // Optionally, reset the monitor for this IP
        // connection_flood_monitor[src_ip].clear();
    }

    // 3. Anomaly Detection: Packet Flood (using flow_monitor's packet_count)
    if (flow_monitor[src_ip].packet_count >= PACKET_FLOOD_THRESHOLD) {
        generate_json_alert("Packet Flood", src_ip, dst_ip, flow_monitor[src_ip].packet_count, PACKET_FLOOD_THRESHOLD);
        // This threshold needs to be considered carefully as packet_count is cumulative.
        // For a more realistic flood detection, one would use a time window.
    }


    // General Monitor Alert (every 10 packets from a source)
    if (flow_monitor[src_ip].packet_count % 10 == 0) {
        std::cout << "\n--- Packet Summary ---\n";
        std::cout << "  Source IP: " << src_ip << ":" << src_port << " (Geo: " << get_geo_info(src_ip) << ")\n";
        std::cout << "  Dest IP:   " << dst_ip << ":" << dst_port << " (Geo: " << get_geo_info(dst_ip) << ")\n";
        std::cout << "  Protocol:  " << (ip_header->ip_p == IPPROTO_TCP ? "TCP" : (ip_header->ip_p == IPPROTO_UDP ? "UDP" : "Other")) << "\n";
        std::cout << "  Total bytes from " << src_ip << ": " << flow_monitor[src_ip].total_bytes << "\n";
        std::cout << "----------------------\n\n";
    }
}

// --- Packet Capture Callback (Producer) ---
// This function is called by pcap_loop for each captured packet.
void pcap_callback_wrapper(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Create a PacketData object, copying the raw packet data
    // Using std::move when pushing to queue to avoid extra copies and ensure proper ownership transfer
    PacketData pkt_data(header, packet);

    pthread_mutex_lock(&queue_mutex);
    packet_queue.push(std::move(pkt_data)); // Move packet data into the queue
    pthread_cond_signal(&queue_cond); // Signal one waiting consumer
    pthread_mutex_unlock(&queue_mutex);
}

// --- Capture Thread Function ---
void* capture_thread_func(void* arg) {
    pcap_t *descr = static_cast<pcap_t*>(arg);
    std::cout << "[Capture Thread] Started capturing packets..." << std::endl;

    // pcap_loop with a limit for demonstration purposes. Use -1 for infinite capture.
    int packets_captured = pcap_loop(descr, PACKET_CAPTURE_LIMIT, pcap_callback_wrapper, NULL);

    if (packets_captured == -1) {
        std::cerr << "[Capture Thread] Error in pcap_loop: " << pcap_geterr(descr) << std::endl;
    } else {
        std::cout << "[Capture Thread] Captured " << packets_captured << " packets." << std::endl;
    }

    // Signal termination to processing threads after capture is done
    pthread_mutex_lock(&queue_mutex);
    terminate_processing = true;
    pthread_cond_broadcast(&queue_cond); // Wake all processing threads
    pthread_mutex_unlock(&queue_mutex);

    std::cout << "[Capture Thread] Exiting." << std::endl;
    return NULL;
}

// --- Processing Thread Function (Consumer) ---
void* processing_thread_func(void* arg) {
    long thread_id = reinterpret_cast<long>(arg);
    std::cout << "[Processing Thread " << thread_id << "] Started." << std::endl;

    while (true) {
        pthread_mutex_lock(&queue_mutex);

        // Wait if the queue is empty and we are not terminating
        while (packet_queue.empty() && !terminate_processing) {
            pthread_cond_wait(&queue_cond, &queue_mutex);
        }

        // Check for termination condition: if queue is empty and termination signaled
        if (packet_queue.empty() && terminate_processing) {
            pthread_mutex_unlock(&queue_mutex);
            break; // Exit loop
        }

        // Move packet data from queue to a local PacketData object
        PacketData current_packet = std::move(packet_queue.front());
        packet_queue.pop();
        pthread_mutex_unlock(&queue_mutex);

        // Process the packet data using the core logic
        std::cout << "[Processing Thread " << thread_id << "] Processing packet, queue size: " << packet_queue.size() << std::endl;
        process_packet_data(&current_packet.header, current_packet.data);
        // The PacketData destructor will automatically deallocate current_packet.data
    }
    std::cout << "[Processing Thread " << thread_id << "] Exiting." << std::endl;
    return NULL;
}

// --- Main Function ---
int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *descr = NULL;

    // Open the MaxMindDB database
    int mmdb_open_error = MMDB_open(MMDB_DATABASE_PATH, MMDB_MODE_MMAP, &mmdb);
    if (mmdb_open_error != MMDB_SUCCESS) {
        std::cerr << "Error opening MaxMindDB database " << MMDB_DATABASE_PATH << ": " << MMDB_strerror(mmdb_open_error) << std::endl;
        return 1;
    }
    std::cout << "MaxMindDB database opened successfully." << std::endl;

    // Initialize mutex and condition variable (already done with PTHREAD_MUTEX_INITIALIZER, but explicit is fine)
    // pthread_mutex_init(&queue_mutex, NULL);
    // pthread_cond_init(&queue_cond, NULL);

    // Find the default network device
    char *dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        std::cerr << "Error finding device: " << errbuf << std::endl;
        MMDB_close(&mmdb); // Close DB before exit
        return 1;
    }
    std::cout << "Monitoring Interface: " << dev << std::endl;

    descr = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (descr == NULL) {
        std::cerr << "Open failed. Note: RAW sockets usually require sudo/root. Error: " << errbuf << std::endl;
        MMDB_close(&mmdb); // Close DB before exit
        return 1;
    }

    // Set a BPF (Berkeley Packet Filter) to only watch TCP and UDP traffic for this example
    struct bpf_program fp;
    // Filter for TCP or UDP traffic to ensure port information is available
    if (pcap_compile(descr, &fp, "tcp or udp", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error compiling BPF filter: " << pcap_geterr(descr) << std::endl;
        pcap_close(descr);
        MMDB_close(&mmdb); // Close DB before exit
        return 1;
    }
    if (pcap_setfilter(descr, &fp) == -1) {
        std::cerr << "Error setting BPF filter: " << pcap_geterr(descr) << std::endl;
        pcap_freecode(&fp);
        pcap_close(descr);
        MMDB_close(&mmdb); // Close DB before exit
        return 1;
    }

    std::cout << "\u26D2\uFE0F Extreme System Monitor: Filtering for TCP and UDP... " << std::endl;
    std::cout << "\u26A0\uFE0F Port Scan Threshold: " << PORT_SCAN_THRESHOLD << " distinct destination ports per source IP." << std::endl;
    std::cout << "\u26A0\uFE0F Connection Flood Threshold: " << CONNECTION_FLOOD_THRESHOLD << " distinct connections (IP:Port) per source IP." << std::endl;
    std::cout << "\u26A0\uFE0F Packet Flood Threshold: " << PACKET_FLOOD_THRESHOLD << " packets per source IP." << std::endl;
    std::cout << "Starting packet capture and processing threads..." << std::endl;

    pthread_t capture_tid;
    pthread_t processing_tids[NUM_PROCESSING_THREADS];

    // Create capture thread
    if (pthread_create(&capture_tid, NULL, capture_thread_func, (void*)descr) != 0) {
        std::cerr << "Error creating capture thread." << std::endl;
        pcap_freecode(&fp);
        pcap_close(descr);
        MMDB_close(&mmdb); // Close DB before exit
        return 1;
    }

    // Create processing threads
    for (long i = 0; i < NUM_PROCESSING_THREADS; ++i) {
        if (pthread_create(&processing_tids[i], NULL, processing_thread_func, (void*)i) != 0) {
            std::cerr << "Error creating processing thread " << i << std::endl;
            // Clean up already created threads and exit
            terminate_processing = true;
            pthread_cond_broadcast(&queue_cond);
            pthread_join(capture_tid, NULL);
            for (long j = 0; j < i; ++j) pthread_join(processing_tids[j], NULL);
            pcap_freecode(&fp);
            pcap_close(descr);
            MMDB_close(&mmdb); // Close DB before exit
            return 1;
        }
    }

    // Wait for capture thread to finish
    pthread_join(capture_tid, NULL);
    std::cout << "Main thread joined capture thread." << std::endl;

    // Wait for all processing threads to finish
    for (int i = 0; i < NUM_PROCESSING_THREADS; ++i) {
        pthread_join(processing_tids[i], NULL);
        std::cout << "Main thread joined processing thread " << i << "." << std::endl;
    }

    // Clean up
    pcap_freecode(&fp);
    pcap_close(descr);
    pthread_mutex_destroy(&queue_mutex);
    pthread_cond_destroy(&queue_cond);
    MMDB_close(&mmdb); // Close MaxMindDB database

    std::cout << "\n\u2705 All threads finished, capture and processing complete." << std::endl;

    return 0;
}
