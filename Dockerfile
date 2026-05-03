FROM golang:1.26-alpine AS builder

# 1. Install build tools and libpcap headers
RUN apk add --no-cache gcc musl-dev libpcap-dev

WORKDIR /app

# 2. Copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./
RUN go mod download

# 3. Copy the rest of the source
COPY . .

# 4. Build the binary with CGO enabled (required for gopacket)
RUN CGO_ENABLED=1 GOOS=linux go build -o destiny ./cmd/destiny/main.go

# 5. Final Stage (Smaller Image)
FROM alpine:latest
RUN apk add --no-cache libpcap
WORKDIR /app
COPY --from=builder /app/destiny .
ENTRYPOINT ["./destiny"]