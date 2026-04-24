# Build Stage
FROM golang:1.21-bullseye AS builder
RUN apt-get update && apt-get install -y libpcap-dev
WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o /destiny cmd/destiny/main.go

# Run Stage
FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y libpcap0.8 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /destiny /usr/local/bin/destiny
# Destiny needs raw network access
ENTRYPOINT ["destiny"]