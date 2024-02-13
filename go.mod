module ephemeral-signing-service

go 1.21.6

require (
	github.com/btcsuite/btcd/btcec/v2 v2.3.2
	github.com/btcsuite/btcd/chaincfg/chainhash v1.0.1
	github.com/davecgh/go-spew v1.1.1
)

require (
	github.com/decred/dcrd/crypto/blake256 v1.0.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
)

replace github.com/btcsuite/btcd/btcec/v2 => /Users/johan.halseth/go/src/github.com/btcsuite/btcd/btcec
