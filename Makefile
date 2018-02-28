
BINARY=r10k-webhook

BUILD_TIME=$(shell date +%Y-%m-%dT%H:%M:%S%z)
BUILD_COMMIT=$(shell git rev-list -1 HEAD)
LDFLAGS="-s -w -X main.buildTime=$(BUILD_TIME) -X main.buildCommit=$(BUILD_COMMIT)"

export GOOS=linux

.PHONY: clean

$(BINARY): $(BINARY).go
	go build -ldflags=$(LDFLAGS) $(BINARY).go
	upx $(BINARY)

clean:
	/bin/rm -f $(BINARY)