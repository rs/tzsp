# TaZmen Sniffer Protocol (TZSP) Parser [![godoc](http://img.shields.io/badge/godoc-reference-blue.svg?style=flat)](https://godoc.org/github.com/rs/tzsp) [![license](http://img.shields.io/badge/license-BSD-red.svg?style=flat)](https://raw.githubusercontent.com/rs/tzsp/master/LICENSE) [![Build Status](https://travis-ci.org/rs/tzsp.svg?branch=master)](https://travis-ci.org/rs/tzsp)

Package tzsp provides a basic TaZmen Sniffer Protocol parser.

## Usage

```go
conn, err := net.ListenUDP("udp", addr)
if err != nil {
    log.Fatal(err)
}

buf := make([]byte, 65535)
for {
    l, _, err := conn.ReadFrom(buf)
    if err != nil {
        panic(err)
    }
    p, err := tzsp.Parse(buf[:l])
    if err != nil {
        panic(err)
    }
    print(p.String())
    // Encapsulated packet data is in p.Data
}
```

# License

Copyright 2016 Olivier Poitrey. All rights reserved.
Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.
