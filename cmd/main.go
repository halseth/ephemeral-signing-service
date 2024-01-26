package main

import (
	"ephemeral-signing-service/service"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

func main() {

	err := run2()
	fmt.Println(err)
}

func run2() error {
	const numCoSigners = 5

	localKey, err := btcec.NewPrivateKey()
	if err != nil {
		return err
	}

	localNonces, err := musig2.GenNonces(
		musig2.WithPublicKey(localKey.PubKey()),
	)
	if err != nil {
		return err
	}

	var (
		coSessions []*service.Session
		allPubs    []*btcec.PublicKey
	)

	for i := 0; i < numCoSigners; i++ {
		co, err := service.NewSession()
		if err != nil {
			return err
		}

		coSessions = append(coSessions, co)
		allPubs = append(allPubs, co.PubKey())
	}
	allPubs = append(allPubs, localKey.PubKey())

	allOpts := append(
		[]musig2.ContextOption{
			musig2.WithKnownSigners(allPubs),
		},
	)

	localContext, err := musig2.NewContext(localKey, true, allOpts...)
	if err != nil {
		fmt.Println("here", err)
		return err
	}

	var sessionOpts []musig2.SessionOption
	sessionOpts = append(
		sessionOpts, musig2.WithPreGeneratedNonce(localNonces),
	)

	localSession, err := localContext.NewSession(sessionOpts...)
	if err != nil {
		fmt.Println("here2", err)
		return err
	}

	for _, co := range coSessions {
		haveAll, err := localSession.RegisterPubNonce(co.PubNonce())
		if err != nil {
			fmt.Println("here99", err)
			return err
		}
		fmt.Println("local have all nonce", haveAll)
	}

	message := "Example message to sign"
	msg := []byte(message)
	msgHash := chainhash.DoubleHashH(msg)

	var opts []musig2.SignOption
	opts = append(opts, musig2.WithSortedKeys())

	_, err = localSession.Sign(msgHash, opts...)
	if err != nil {
		fmt.Println("here9", err)
		return err
	}

	var partialSigs []*musig2.PartialSignature

	for j, co := range coSessions {
		var coSigners []*service.Signer
		coSigners = append(coSigners, &service.Signer{
			PubKey:   localKey.PubKey(),
			PubNonce: localNonces.PubNonce,
		})

		for i := 0; i < numCoSigners; i++ {
			if i == j {
				continue
			}

			coSigners = append(coSigners, &service.Signer{
				PubKey:   coSessions[i].PubKey(),
				PubNonce: coSessions[i].PubNonce(),
			})
		}

		partial, err := co.Sign(msg, coSigners)
		if err != nil {
			fmt.Println("here3", err)
			return err
		}

		partialSigs = append(partialSigs, partial)
	}

	for _, partial := range partialSigs {
		haveAllSigs, err := localSession.CombineSig(partial)
		if err != nil {
			fmt.Println("here8", err)
			return err
		}

		fmt.Println("have all sigs", haveAllSigs)
	}

	finalSig := localSession.FinalSig()
	fmt.Println("final sig", finalSig)

	combinedKey, err := localContext.CombinedKey()
	if err != nil {
		return nil
	}

	_ = combinedKey
	fmt.Println(combinedKey)

	ok := finalSig.Verify(msgHash[:], combinedKey)
	fmt.Println("sigok: ", ok)

	return nil
}

func run() error {
	var (
		privKeys    []*btcec.PrivateKey
		pubKeys     []*btcec.PublicKey
		nonces      []*musig2.Nonces
		contexts    []*musig2.Context
		sessions    []*musig2.Session
		partialSigs []*musig2.PartialSignature
	)

	const numKeys = 5

	var coSigners []*service.Session
	localKey, err := btcec.NewPrivateKey()
	if err != nil {
		return err
	}

	localNonces, err := musig2.GenNonces(
		musig2.WithPublicKey(localKey.PubKey()),
	)
	if err != nil {
		return err
	}

	for i := 0; i < numKeys; i++ {
		co, err := service.NewSession()
		if err != nil {
			return err
		}

		coSigners = append(coSigners, co)

		priv, err := btcec.NewPrivateKey()
		if err != nil {
			return err
		}

		privKeys = append(privKeys, priv)

		pub := priv.PubKey()
		pubKeys = append(pubKeys, pub)

		nonce, err := musig2.GenNonces(
			musig2.WithPublicKey(pub),
		)
		if err != nil {
			return err
		}

		nonces = append(nonces, nonce)
	}

	var allPubs []*btcec.PublicKey
	allPubs = append(allPubs, localKey.PubKey())
	for _, co := range coSigners {
		allPubs = append(allPubs, co.PubKey())
	}

	allOpts := append(
		[]musig2.ContextOption{
			musig2.WithKnownSigners(pubKeys),
		},
	)

	for i := 0; i < len(privKeys); i++ {
		priv := privKeys[i]
		muSigContext, err := musig2.NewContext(priv, true, allOpts...)
		if err != nil {
			return err
		}

		contexts = append(contexts, muSigContext)

		var sessionOpts []musig2.SessionOption
		sessionOpts = append(
			sessionOpts, musig2.WithPreGeneratedNonce(nonces[i]),
		)

		muSigSession, err := muSigContext.NewSession(sessionOpts...)
		if err != nil {
			return err
		}

		sessions = append(sessions, muSigSession)
	}

	localContext, err := musig2.NewContext(localKey, true, allOpts...)
	if err != nil {
		return err
	}

	var sessionOpts []musig2.SessionOption
	sessionOpts = append(
		sessionOpts, musig2.WithPreGeneratedNonce(localNonces),
	)

	localSession, err := localContext.NewSession(sessionOpts...)
	if err != nil {
		return err
	}

	for i := 0; i < len(privKeys); i++ {
		session := sessions[i]
		for j := 0; j < len(privKeys); j++ {
			if i == j {
				continue
			}

			haveAll, err := session.RegisterPubNonce(nonces[j].PubNonce)
			if err != nil {
				return err
			}
			fmt.Println("have all nonce", haveAll)
		}
	}

	message := "Example message to sign"
	msg := chainhash.DoubleHashH([]byte(message))

	_ = msg

	var opts []musig2.SignOption
	opts = append(opts, musig2.WithSortedKeys())

	for i := 0; i < len(privKeys); i++ {
		session := sessions[i]
		partialSig, err := session.Sign(msg, opts...)
		if err != nil {
			return err
		}

		partialSigs = append(partialSigs, partialSig)
	}

	for i := 1; i < len(privKeys); i++ {
		haveAllSigs, err := localSession.CombineSig(partialSigs[i])
		if err != nil {
			return err
		}

		fmt.Println("have all sigs", haveAllSigs)
	}

	finalSig := localSession.FinalSig()
	fmt.Println("final sig", finalSig)

	var keyAggOpts []musig2.KeyAggOption
	sortKeys := true
	combinedKey, _, _, err := musig2.AggregateKeys(
		pubKeys, sortKeys, keyAggOpts...,
	)
	if err != nil {
		return nil
	}

	_ = combinedKey
	fmt.Println(combinedKey)

	ok := finalSig.Verify(msg[:], combinedKey.FinalKey)
	fmt.Println("sigok: ", ok)

	return nil
}
