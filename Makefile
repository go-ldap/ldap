.PHONY: default install build test test fmt vet lint

default: fmt vet lint build test

CONTAINER_CMD := $(shell command -v podman 2>/dev/null)
ifeq ($(CONTAINER_CMD),)
    CONTAINER_CMD := $(shell command -v docker 2>/dev/null)
endif

# Check if we found either command
ifeq ($(CONTAINER_CMD),)
    $(error Neither podman nor docker found in PATH)
endif

install:
	go get -t -x ./...

build:
	go build -v ./...

LDAP_ADMIN_DN := cn=admin,dc=example,dc=com
LDAP_ADMIN_PASSWORD := admin123
LDAP_BASE_DN := dc=example,dc=com
LDAP_URL := ldap://127.0.0.1:389
CONTAINER_NAME := go-ldap-test

local-server:
	-$(CONTAINER_CMD) rm -f -t 10 $(CONTAINER_NAME)
	$(CONTAINER_CMD) \
	   run \
	   --rm \
	   -d \
	   --name $(CONTAINER_NAME) \
	   --hostname "$(CONTAINER_NAME).example.com" \
	   -p "127.0.0.1:3389:389" \
	   -p "127.0.0.1:3636:636" \
	   -e LDAP_ORGANISATION="Example Inc" \
	   -e LDAP_DOMAIN="example.com" \
	   -e LDAP_ADMIN_PASSWORD="$(LDAP_ADMIN_PASSWORD)" \
	   -e LDAP_TLS_VERIFY_CLIENT="never" \
	   docker.io/osixia/openldap:1.5.0

	@echo "Waiting for LDAP server to be ready..."
	@$(CONTAINER_CMD) exec $(CONTAINER_NAME) /bin/sh -c 'until ldapsearch -x -H $(LDAP_URL) -b "$(LDAP_BASE_DN)" -D "$(LDAP_ADMIN_DN)" -w $(LDAP_ADMIN_PASSWORD) > /dev/null 2>&1; do echo "LDAP server not ready yet, waiting..."; sleep 2; done'
	@echo "LDAP server is ready!"

	@echo "Configuring anonymous access..."
	@$(CONTAINER_CMD) exec $(CONTAINER_NAME) /bin/sh -c 'echo "dn: olcDatabase={1}mdb,cn=config\nchangetype: modify\nreplace: olcAccess\nolcAccess: {0}to * by * read" | ldapmodify -Y EXTERNAL -H ldapi:///'

	$(CONTAINER_CMD) cp -a ./testdata $(CONTAINER_NAME):/
	@echo "Loading LDIF files..."
	@$(CONTAINER_CMD) exec $(CONTAINER_NAME) /bin/sh -c 'for file in /testdata/*.ldif; do echo "Processing $$file..."; cat "$$file" | ldapadd -v -x -H $(LDAP_URL) -D "$(LDAP_ADMIN_DN)" -w $(LDAP_ADMIN_PASSWORD); done'

stop-local-server:
	-$(CONTAINER_CMD) rm -f -t 10 $(CONTAINER_NAME)

test:
	go test -v ./...

fuzz:
	go test -fuzz=FuzzParseDN				-fuzztime=600s .
	go test -fuzz=FuzzDecodeEscapedSymbols	-fuzztime=600s .
	go test -fuzz=FuzzEscapeDN 				-fuzztime=600s .

# Capture output and force failure when there is non-empty output
fmt:
	@echo gofmt -l .
	@OUTPUT=`gofmt -l . 2>&1`; \
	if [ "$$OUTPUT" ]; then \
		echo "gofmt must be run on the following files:"; \
		echo "$$OUTPUT"; \
		exit 1; \
	fi

vet:
	go vet \
    	-atomic \
    	-bool \
    	-copylocks \
    	-nilfunc \
    	-printf \
    	-rangeloops \
    	-unreachable \
    	-unsafeptr \
    	-unusedresult \
    	./...

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
