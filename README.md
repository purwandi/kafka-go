# kafka-go extensions

This repository contains standalone Go modules for SASL authentication with
[`kafka-go`](https://github.com/segmentio/kafka-go).

## Add a module to your project

Run `go get` from the directory of your Go project. For example, for Kerberos:

```bash
go get github.com/purwandi/kafka-go/kerberos@latest
```

For OAuth 2.0 client-credentials authentication:

```bash
go get github.com/purwandi/kafka-go/oauth@latest
```

This adds the module to your project's dependencies. For configuration and
usage examples, see the package READMEs.

Modules in this repository:

- [Kerberos (GSSAPI)](./kerberos/README.md)
- [OAuth 2.0 (OAUTHBEARER)](./oauth/README.md)
