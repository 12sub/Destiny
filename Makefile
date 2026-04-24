# Destiny Build & Run Makefile

BINARY_NAME=destiny

build:
	@echo "🔨 Building Destiny..."
	go build -o $(BINARY_NAME) cmd/destiny/main.go

run: build
	@echo "🚀 Running Monitor..."
	sudo ./$(BINARY_NAME) monitor -i eno1

scan: build
	@echo "🔍 Scanning Network..."
	sudo ./$(BINARY_NAME) scan 192.168.1.0/24

clean:
	@echo "🧹 Cleaning up..."
	rm -f $(BINARY_NAME)