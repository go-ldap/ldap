.PHONY: default install build test quicktest fmt vet lint 

# List of all release tags "supported" by our current Go version
# E.g. ":go1.1:go1.2:go1.3:go1.4:go1.5:go1.6:go1.7:go1.8:go1.9:go1.10:go1.11:go1.12:"
GO_RELEASE_TAGS := $(shell go list -f ':{{join (context.ReleaseTags) ":"}}:' runtime)

# Only use the `-race` flag on newer versions of Go (version 1.3 and newer)
ifeq (,$(findstring :go1.3:,$(GO_RELEASE_TAGS)))
	RACE_FLAG :=
else
	RACE_FLAG := -race -cpu 1,2,4
endif

default: fmt vet lint build quicktest

install:
	go get -t -v ./...

build:
	go build -v ./...

test:
	go test -v $(RACE_FLAG) -cover ./...

quicktest:
	go test ./...

# Capture output and force failure when there is non-empty output
fmt:
	@echo gofmt -l .
	@OUTPUT=`gofmt -l . 2>&1`; \
	if [ "$$OUTPUT" ]; then \
		echo "gofmt must be run on the following files:"; \
		echo "$$OUTPUT"; \
		exit 1; \
	fi

# Only run on go1.5+
vet:
	@go tool -n vet >/dev/null 2>&1; \
		if [ $$? -eq 0 ]; then \
			echo "go vet" ; \
			go tool vet \
				-atomic \
				-bool \
				-copylocks \
				-nilfunc \
				-printf \
				-shadow \
				-rangeloops \
				-unreachable \
				-unsafeptr \
				-unusedresult \
				. ; \
		fi ;


# https://github.com/golang/lint
# go get github.com/golang/lint/golint
# Capture output and force failure when there is non-empty output
# Only run on go1.5+
lint:
	@echo golint ./...
	@OUTPUT=`command -v golint >/dev/null 2>&1 && golint ./... 2>&1`; \
	if [ "$$OUTPUT" ]; then \
		echo "golint errors:"; \
		echo "$$OUTPUT"; \
		exit 1; \
	fi
