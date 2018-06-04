# Migrating gopkg.in/ldap.v2 to gopkg.in/ldap.v3

This documents the changes made between v2 and v3. 

## API Changes

### NewAddRequest()

The `NewAddRequest()` function now requires the controls as second parameter
like `NewDelRequest()`. To get the same behaviour as in v2, pass `nil`.

### DecodeControl()

`DecodeControl()` now returns an error also.

### ModifyDN() / ModifyDNRequest

... were added as functions / struct

### ModifyRequest

The `ModifyRequest` struct now contains a list of ordered [Changes](https://godoc.org/gopkg.in/ldap.v3#ModifyRequest)
instead of `AddAttributes`, `DeleteAttributes`, `ReplaceAttributes`.

### NewModifyRequest()

The `NewModifyRequest()` function now requires the controls as second parameter
like `NewDelRequest()`. To get the same behaviour as in v2, pass `nil`.

## Functional Changes

### *Conn.Bind() 

The `Bind()` call no longer does unauthenticated binds (i.e. empty passwords),
use the `UnauthenticatedBind()` method. In case of an empty password the
local error code 206 (ErrorEmptyPassword) is returned.

***FIXME*** add UnauthenticatedBind() to Client interface?

## Client interface

The `Client` interface got the `ModifyDN()` call added

