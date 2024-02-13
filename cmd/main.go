package main

import (
	"ephemeral-signing-service/service"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/davecgh/go-spew/spew"
)

func main() {

	err := run2()
	fmt.Println(err)
}

func run2() error {
	const numCoSigners = 2

	//localKey, err := btcec.NewPrivateKey()
	//if err != nil {
	//	return err
	//}

	//	localNonces, err := musig2.GenNonces(
	//		musig2.WithPublicKey(localKey.PubKey()),
	//	)
	//	if err != nil {
	//		return err
	//	}

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
	//allPubs = append(allPubs, localKey.PubKey())

	//allOpts := append(
	//	[]musig2.ContextOption{
	//		musig2.WithKnownSigners(allPubs),
	//	},
	//)

	//localContext, err := musig2.NewContext(localKey, true, allOpts...)
	//if err != nil {
	//	fmt.Println("here", err)
	//	return err
	//}

	//var sessionOpts []musig2.SessionOption
	//sessionOpts = append(
	//	sessionOpts, musig2.WithPreGeneratedNonce(localNonces),
	//)

	//localSession, err := localContext.NewSession(sessionOpts...)
	//if err != nil {
	//	fmt.Println("here2", err)
	//	return err
	//}

	var pubNonces [][musig2.PubNonceSize]byte
	for _, co := range coSessions {
		pubNonces = append(pubNonces, co.PubNonce())
	}

	combinedNonce, err := musig2.AggregateNonces(pubNonces)
	if err != nil {
		return err
	}

	Rj, err := btcec.ParseJacobian(
		combinedNonce[:btcec.PubKeyBytesLenCompressed],
	)
	if err != nil {
		return err
	}
	Rj.ToAffine()
	R := btcec.NewPublicKey(&Rj.X, &Rj.Y)

	message := "Example message to sign"
	msg := []byte(message)
	msgHash := chainhash.DoubleHashH(msg)

	var mc [32]byte
	copy(mc[:], msgHash[:])
	var m btcec.ModNScalar
	m.SetByteSlice(mc[:])
	fmt.Printf("msg to sign: %v\n", m)

	var opts []musig2.SignOption
	opts = append(opts, musig2.WithSortedKeys())

	//_, err = localSession.Sign(msgHash, msgHash, opts...)
	//if err != nil {
	//	fmt.Println("here9", err)
	//	return err
	//}

	var partialSigs []*musig2.PartialSignature
	keys := musig2.SortKeys(allPubs)
	keysHash := musig2.KeyHashFingerprint(keys, true)
	uniqueKeyIndex := musig2.SecondUniqueKeyIndex(keys, true)

	combinedKey, _, _, err := musig2.AggregateKeys(
		keys, true,
	)
	if err != nil {
		return err
	}
	fmt.Printf("combined key: %x\n", combinedKey.FinalKey.SerializeCompressed())

	for i, co := range coSessions {
		pubNonce := co.PubNonce()
		secNonce := co.SecNonce()

		var k [32]byte
		copy(k[:], secNonce[:32])
		privKey := co.PrivKey()

		copy(mc[:], msgHash[:])
		pBytes := schnorr.SerializePubKey(co.PubKey())
		commitment := chainhash.TaggedHash(
			chainhash.TagBIP0340Challenge,
			pubNonce[1:33], pBytes, mc[:],
		)
		fmt.Printf("created commitment R=%x P=%x H=%x\n", pubNonce[1:33], pBytes, mc)

		fmt.Printf("schnorr using secnonce %x\n", k[:])

		var signOpts []schnorr.SignOption
		signOpts = []schnorr.SignOption{
			schnorr.CustomNonce(k),
		}

		copy(mc[:], msgHash[:])
		ssig, err := schnorr.Sign(privKey, mc[:], signOpts...)
		if err != nil {
			return err
		}

		copy(mc[:], msgHash[:])
		okSig := ssig.Verify(mc[:], co.PubKey())
		fmt.Printf("schnorr sig ok=%v for pub=%x and msg=%x\n", okSig, co.PubKey().SerializeCompressed(), mc)

		mu, c := musig2.AggregationCoefficient(
			keys, co.PubKey(), keysHash, uniqueKeyIndex,
		)

		fmt.Printf("c_%d=%x\n", i, mu)

		partial, err := co.Sign(*commitment, c)
		if err != nil {
			fmt.Println("here3", err)
			return err
		}

		partialSigs = append(partialSigs, partial)
	}

	//	for _, partial := range partialSigs {
	//		haveAllSigs, err := localSession.CombineSig(partial)
	//		if err != nil {
	//			fmt.Println("here8", err)
	//			return err
	//		}
	//
	//		fmt.Println("have all sigs", haveAllSigs)
	//	}
	//
	finalSig := musig2.CombineSigs(R, partialSigs)

	//finalSig := localSession.FinalSig()
	fmt.Println("final sig", spew.Sdump(finalSig))

	//	combinedKey, err := localContext.CombinedKey()
	//	if err != nil {
	//		return nil
	//	}

	_ = combinedKey
	fmt.Println(combinedKey)

	ok := finalSig.Verify(mc[:], combinedKey.FinalKey)
	copy(mc[:], msgHash[:])
	fmt.Printf("musig sig ok=%v for pub=%x and msg=%x\n", ok, combinedKey.FinalKey.SerializeCompressed(), mc)

	return nil
}
