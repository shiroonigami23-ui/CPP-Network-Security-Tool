# C++ Network Security Tool

This project provides a robust C++ network security tool for deep packet inspection (DPI), advanced anomaly detection, multithreaded packet processing, and Geo-IP lookup. It leverages the `libpcap` library to capture and analyze network traffic in real-time, helping to identify suspicious activities or unusual patterns.

![C++ Network Security Banner](./visual/banner.png)

## Table of Contents
- [Features](#features)
- [Project Structure](#project-structure)
- [Cybersecurity Analysis](#cybersecurity-analysis)
- [Build and Run Instructions](#build-and-run-instructions)
- [License](#license)

## Features
- **Deep Packet Inspection (DPI)**: Analyzes packet headers and payload data to extract critical information such as source/destination IP addresses, ports, protocol types, HTTP methods (GET, POST), User-Agent strings, and DNS query types.
- **Advanced Anomaly Detection**: Implements sophisticated heuristics to identify suspicious network behavior, including:
    - **Port Scanning**: Detects when a source IP attempts to connect to an unusual number of distinct destination ports.
    - **Connection Flood**: Flags a source IP making an excessive number of distinct connections (IP:Port pairs).
    - **Packet Flood**: Identifies when a source IP sends a high volume of packets.
    Alerts for detected anomalies are output in a structured JSON format.
- **Multithreaded Architecture**: Employs a producer-consumer model where a dedicated capture thread feeds raw packets into a ring buffer (implemented as a `std::queue`), and multiple processing threads concurrently analyze packets from this buffer.
- **Real-time Monitoring**: Captures and processes packets live from a specified network interface.
- **Customizable Filtering**: Supports Berkeley Packet Filter (BPF) syntax for precise traffic filtering (e.g., filtering for TCP or UDP traffic).
- **Geo-IP Lookup**: Integrates `libmaxminddb` to provide geographical information (city, country) for source and destination IP addresses, enriching anomaly alerts and packet summaries.

## Project Structure
```
CPPNetworkSecurity/
├── ExtremeSniffer.cpp             # Main C++ source code for the network security tool
├── ExtremeSniffer                 # Compiled executable of the sniffer
├── NetworkSniffer.cpp             # Basic C++ sniffer (initial version)
├── NetworkSniffer                 # Compiled executable of the basic sniffer
├── README.md                      # Project documentation (this file)
├── LICENSE                        # MIT License details
├── CybersecurityAnalysis.md       # Detailed cybersecurity analysis of the tool
└── visual/
    └── banner.png                 # Placeholder for project banner image
```

## Cybersecurity Analysis
For a detailed analysis of the tool's security posture, threat model, limitations, and future enhancements, please refer to the [Cybersecurity Analysis document](./CybersecurityAnalysis.md).

## Build and Run Instructions

### Prerequisites
- A C++ compiler (like g++)
- `libpcap-dev` library (`sudo apt-get install libpcap-dev`)
- `libmaxminddb-dev` library (`sudo apt-get install libmaxminddb-dev`)
- MaxMind GeoLite2 City database (`GeoLite2-City.mmdb`) placed in the project root directory. You can obtain this from the [MaxMind website](https://www.maxmind.com/en/geolite2/downloads).

### Cloning the Repository
```bash
git clone https://github.com/shiroonigami23-ui/CPP-Network-Security-Tool.git
cd CPP-Network-Security-Tool
```

### Building the Project
Navigate to the project directory and compile the source code, linking against `libpcap` and `libmaxminddb`:

```bash
g++ ExtremeSniffer.cpp -o ExtremeSniffer -lpcap -pthread -lmaxminddb
```

### Running the Tool
To run the compiled executable, you will likely need root/sudo privileges due to raw socket access requirements for `libpcap`:

```bash
sudo ./ExtremeSniffer
```

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
