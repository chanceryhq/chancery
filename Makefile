.PHONY: build test vet demo clean

build:
	go build -o chancery ./cmd/chancery

test:
	go vet ./...
	go test ./...

demo: build
	CHANCERY=./chancery bash scripts/demo.sh

clean:
	rm -f chancery
