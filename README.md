[![GoDoc](https://godoc.org/github.com/go-ldap/ldap?status.svg)](https://godoc.org/github.com/go-ldap/ldap)

# Basic LDAP v3 functionality for the GO programming language.

The library implements the following specifications:

- https://datatracker.ietf.org/doc/html/rfc4511 for basic operations
- https://datatracker.ietf.org/doc/html/rfc3062 for password modify operation
- https://datatracker.ietf.org/doc/html/rfc4514 for distinguished names parsing
- https://datatracker.ietf.org/doc/html/rfc4533 for Content Synchronization Operation
- https://datatracker.ietf.org/doc/html/draft-armijo-ldap-treedelete-02 for Tree Delete Control
- https://datatracker.ietf.org/doc/html/rfc2891 for Server Side Sorting of Search Results
- https://datatracker.ietf.org/doc/html/rfc4532 for WhoAmI requests

## Features:

- Connecting to LDAP server (non-TLS, TLS, STARTTLS, through a custom dialer)
- Bind Requests / Responses (Simple Bind, GSSAPI, SASL)
- "Who Am I" Requests / Responses
- Search Requests / Responses (normal, paging and asynchronous)
- Modify Requests / Responses
- Add Requests / Responses
- Delete Requests / Responses
- Modify DN Requests / Responses
- Unbind Requests / Responses
- Password Modify Requests / Responses
- Content Synchronization Requests / Responses
- LDAPv3 Filter Compile / Decompile
- Server Side Sorting of Search Results
- LDAPv3 Extended Operations
- LDAPv3 Control Support

## Go Modules:

`go get github.com/go-ldap/ldap/v3`

## Contributing:

Bug reports and pull requests are welcome!

Before submitting a pull request, please make sure tests and verification scripts pass:

```
# Setup local directory server using Docker or Podman
make local-server

# Run gofmt, go vet and go test
cd ./v3
make -f ../Makefile

# (Optionally) Stop and delete the directory server container afterwards
cd ..
make stop-local-server
```

---

The Go gopher was designed by Renee French. (http://reneefrench.blogspot.com/)
The design is licensed under the Creative Commons 3.0 Attributions license.
Read this article for more details: http://blog.golang.org/gopher
