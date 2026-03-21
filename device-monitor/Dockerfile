FROM rust:1.82-slim AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y \
    pkg-config \
    libpcap-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Cache dependencies
COPY Cargo.toml ./
RUN mkdir src && echo 'fn main(){}' > src/main.rs && cargo build --release && rm -rf src

# Build real binary
COPY src ./src
RUN touch src/main.rs && cargo build --release

# Runtime image
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -u 1001 monitor
COPY --from=builder /app/target/release/device-monitor /usr/local/bin/device-monitor

# Give NET_RAW capability to binary so it can run without root
RUN apt-get update && apt-get install -y libcap2-bin && rm -rf /var/lib/apt/lists/* \
    && setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/device-monitor

USER monitor
EXPOSE 8080

CMD ["device-monitor"]
