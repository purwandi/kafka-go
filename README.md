# kafka-go extensions

This repository contains standalone Go modules for SASL authentication with
[`kafka-go`](https://github.com/segmentio/kafka-go).

## Add a module to your project

Run `go get` from the directory of your Go project. For Kerberos:

```bash
go get github.com/purwandi/kafka-go/kerberos@latest
```

This adds the module to your project's dependencies. For configuration and
usage examples, see the [Kerberos package README](./kerberos/README.md).

Modules in this repository:

- [Kerberos (GSSAPI)](./kerberos/README.md)
