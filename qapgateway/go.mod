
module qap-krakend-plugin

go 1.22.5

require github.com/nats-io/nats.go v1.34.1

require (
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/nats-io/nkeys v0.4.9 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
)

replace github.com/klauspost/compress => github.com/klauspost/compress v1.17.7

replace github.com/nats-io/nkeys => github.com/nats-io/nkeys v0.4.7

replace golang.org/x/crypto => golang.org/x/crypto v0.24.0

replace golang.org/x/sys => golang.org/x/sys v0.21.0
