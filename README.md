# QPACK

[![PkgGoDev](https://pkg.go.dev/badge/github.com/quic-go/qpack)](https://pkg.go.dev/github.com/quic-go/qpack)
[![Code Coverage](https://img.shields.io/codecov/c/github/quic-go/qpack/master.svg?style=flat-square)](https://codecov.io/gh/quic-go/qpack)
[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/quic-go.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:quic-go)

This is a minimal QPACK ([RFC 9204](https://datatracker.ietf.org/doc/html/rfc9204)) implementation in Go. It reuses the Huffman encoder / decoder code from the [HPACK implementation in the Go standard library](https://github.com/golang/net/tree/master/http2/hpack).

It is fully interoperable with other QPACK implementations (both encoders and decoders).

In addition to the state-less static-table decoder (`NewDecoder`), the package provides a connection-scoped decoder (`NewConnectionDecoder`) that implements the QPACK dynamic table as required by [RFC 9204](https://datatracker.ietf.org/doc/html/rfc9204): it consumes encoder stream instructions and field sections from individual request streams, keeps field sections that reference not-yet-inserted entries in a bounded waiting area, and produces Section Acknowledgment, Stream Cancellation and Insert Count Increment feedback. It performs no network I/O and does not depend on a QUIC transport.

## Running the Interop Tests

Install the [QPACK interop files](https://github.com/qpackers/qifs/) by running
```bash
git submodule update --init --recursive
```

Then run the tests:
```bash
go test -v ./interop
```
