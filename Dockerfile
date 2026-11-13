FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends g++ libpcap-dev libmaxminddb-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY ExtremeSniffer.cpp .
RUN g++ ExtremeSniffer.cpp -o ExtremeSniffer -lpcap -pthread -lmaxminddb
ENTRYPOINT ["./ExtremeSniffer"]
