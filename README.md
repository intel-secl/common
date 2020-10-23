# ISecL Common Library

This library provides several utility functions such as jwt token verification, setup tasks, input validation, abstraction for crypto and command execution operations.

### Install `go` version >= `go1.12.1` & <= `go1.14.1`
The `common` requires Go version 1.12.1 that has support for `go modules`. The build was validated with the latest version go1.14.1 of `go`. It is recommended that you use go1.14.1 version of `go`. You can use the following to install `go`.
```shell
wget https://dl.google.com/go/go1.14.1.linux-amd64.tar.gz
tar -xzf go1.14.1.linux-amd64.tar.gz
sudo mv go /usr/local
export GOROOT=/usr/local/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

### Direct dependencies

| Name                  | Repo URL                        | Minimum Version Required                           |
| ----------------------| --------------------------------| :-------------------------------------------------:|
| logrus                | github.com/sirupsen/logrus      | v1.4.0                                             |
| dgrijalva jwt-go      | github.com/Waterdrips/jwt-go    | v3.2.1-0.20200915121943-f6506928b72e+incompatible  |
| gorilla mux           | github.com/gorilla/mux          | v1.7.3  				                           |
| yaml for Go           | gopkg.in/yaml.v2                | v2.2.2                                             |

*Note: All dependencies are listed in go.mod*

# Links
https://01.org/intel-secl/
