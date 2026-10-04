# QPACK

[![PkgGoDev](https://pkg.go.dev/badge/github.com/quic-go/qpack)](https://pkg.go.dev/github.com/quic-go/qpack)
[![Code Coverage](https://img.shields.io/codecov/c/github/quic-go/qpack/master.svg?style=flat-square)](https://codecov.io/gh/quic-go/qpack)
[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/quic-go.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:quic-go)

This is a minimal QPACK ([RFC 9204](https://datatracker.ietf.org/doc/html/rfc9204)) implementation in Go. It reuses the Huffman encoder / decoder code from the [HPACK implementation in the Go standard library](https://github.com/golang/net/tree/master/http2/hpack).

It is fully interoperable with other QPACK implementations (both encoders and decoders).

Two decoders are provided:

* the stateless `Decoder`, which relies solely on the static table and string literals (including Huffman encoding) and rejects header blocks with a non-zero Required Insert Count, and
* the connection-level `DynamicDecoder`, a transport-independent RFC 9204 decoder with dynamic table support. The HTTP/3 layer feeds it encoder stream instructions and field sections separately; it handles capacity changes, inserts (with name references or literal names), Duplicate, relative and post-base references, blocked streams, and the wrap-around encoding of the Required Insert Count. It emits Section Acknowledgment, Insert Count Increment and Stream Cancellation instructions for the decoder stream.

## Running the Interop Tests

Install the [QPACK interop files](https://github.com/qpackers/qifs/) by running
```bash
git submodule update --init --recursive
```

Then run the tests:
```bash
go test -v ./interop
```
