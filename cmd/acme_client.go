package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/netzuser-acme-project/httpShutdown"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/netzuser-acme-project/logger"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/netzuser-acme-project/network"
	"log"
	"log/slog"
	"os"
	"time"

	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/netzuser-acme-project/dns01"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/netzuser-acme-project/http01"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/netzuser-acme-project/httpCertif"
)

func main() {
	// Positional argument must be either dns01 or http01
	if len(os.Args) < 2 {
		log.Fatal("Challenge type (required): {dns01 | http01}")
	}

	// Get the Challenge type
	challengeType := os.Args[1]
	if challengeType != "dns01" && challengeType != "http01" {
		log.Fatalf("Invalid challenge type: %s. Must be either dns01 or http01", challengeType)
	}

	// Keyword argument - create a new FlagSet to accept them
	flags := flag.NewFlagSet("Acme-Client", flag.ExitOnError)

	// Define the flags within this FlagSet
	dirURL := flags.String("dir", "", "ACME server directory URL (required)")
	ipv4Address := flags.String("record", "", "Returned IPv4 for A-record queries (required)")
	revoke := flags.Bool("revoke", false, "Revoke the certificate after obtaining it (optional; default false)")

	// Handle multiple --domain flags
	var domainList []string
	flags.Func("domain", "Domain for which to request the certificate (required, can be multiple)", func(domain string) error {
		domainList = append(domainList, domain)
		return nil
	})

	// Parse keyword argument flags (starting from the second argument since the first is a positional argument)
	err := flags.Parse(os.Args[2:])
	if err != nil {
		log.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required flags
	if *dirURL == "" {
		log.Fatal("--dir is required")
	}
	if *ipv4Address == "" {
		log.Fatal("--record is required")
	}
	if len(domainList) == 0 {
		log.Fatal("--domain is required (at least one domain must be specified)")
	}

	certFile := "./project/pebble.minica.pem"

	// Read the certificate file
	cert, err := os.ReadFile(certFile)
	if err != nil {
		log.Fatalf("Failed to read certificate file: %v", err)
	}

	// Create a new CertPool and append the certificate
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(cert); !ok {
		log.Fatalf("Failed to append certificate to pool")
	}

	logger.Logger().Debug().Msgf("\nDEBUG\n"+
		"- Challenge Type: %v\n"+
		"- Directory URL: %v \n"+
		"- IPv4 Address: %v \n"+
		"- Domains: %v \n"+
		"- Revoke: %v\n",
		challengeType, *dirURL, *ipv4Address, domainList, *revoke)

	messagesHTTP := make(chan string)
	messagesDNS := make(chan string)
	go http01.HTTP01(messagesHTTP)
	go dns01.DNS01(messagesDNS, *ipv4Address)
	go httpShutdown.HTTPShutdown()

	err, dir := retrieveDir(*dirURL, certPool)
	if err != nil {
		logger.Logger().Error().Msgf("Error while retrievingDir: %v", err)
		log.Fatalf("%v/%v has crashed!", network.AcmeClientName, network.AcmeClientVersion)
	}

	err, nonce := retrieveNonce(dir.NewNonce, certPool)
	if err != nil {
		logger.Logger().Error().Msgf("Error while retrievingNonce: %v", err)
		log.Fatalf("%v/%v has crashed!", network.AcmeClientName, network.AcmeClientVersion)
	}

	noncebis, kid, pKey, err := createAccount(dir.NewAccount, nonce, certPool)
	if err != nil {
		logger.Logger().Error().Msgf("Error while createAccount: %v", err)
		log.Fatalf("%v/%v has crashed!", network.AcmeClientName, network.AcmeClientVersion)
	}

	netState := network.NewStateNetwork(pKey, certPool, kid)
	err = netState.SetNonce(noncebis)
	if err != nil {
		logger.Logger().Error().Msgf("Error while creating network state: %v", err)
		log.Fatalf("%v/%v has crashed!", network.AcmeClientName, network.AcmeClientVersion)
	}

	order, orderLocation, err := createOrder(&netState, dir.NewOrder, domainList)
	if err != nil {
		logger.Logger().Error().Msgf("Error while createOrder: %v", err)
		log.Fatalf("%v/%v has crashed!", network.AcmeClientName, network.AcmeClientVersion)
	}

	for _, auth := range order.Authorizations {
		challenges, err := fetchChallenges(&netState, auth, false)
		if err != nil {
			logger.Logger().Error().Msgf("Error while fetchingChallenges: %v", err)
			log.Fatalf("%v/%v has crashed!", network.AcmeClientName, network.AcmeClientVersion)
		}

		thum, _ := getThumbprint(pKey)

		for _, chal := range challenges.Challenges {

			// Provide requested Challenge
			if chal.Type == "dns-01" && challengeType == "dns01" {
				hash := sha256.Sum256([]byte(chal.Token + "." + thum))
				keyAuth := base64.RawURLEncoding.EncodeToString(hash[:])

				messagesDNS <- keyAuth
			} else if chal.Type == "http-01" && challengeType == "http01" {
				messagesHTTP <- chal.Token + "." + thum
			} else {
				// If no valid challenge, we do not poll, continue to next iteration
				continue
			}

			// Poll mechanism
			chalnew, err := fetchChallenges(&netState, chal.Url, true)
			if err != nil {
				logger.Logger().Error().Msgf("Error while pingingFetchedChallenge: %v", err)
				log.Fatalf("%v/%v has crashed!", network.AcmeClientName, network.AcmeClientVersion)
			}
			time.Sleep(1 * time.Second)

			for count := 0; count < 5; count++ {
				logger.Logger().Debug().Msgf("\nATTEMPT: %v\n", count)

				// Query to get status
				chalnew, err = fetchChallenges(&netState, chal.Url, false)
				if err != nil {
					logger.Logger().Error().Msgf("Error while pingingFetchedChallenge: %v", err)
					log.Fatalf("%v/%v has crashed!", network.AcmeClientName, network.AcmeClientVersion)
				}

				if chalnew.Status == "valid" { // processing
					break
				}
				time.Sleep(5 * time.Second)
			}

		}

	}

	certifKeysEnc, err := genCertif(&netState, order.Finalize, domainList)
	if err != nil {
		logger.Logger().Error().Msgf("Error while gen certif: %v", err)
		log.Fatalf("%v/%v has crashed!", network.AcmeClientName, network.AcmeClientVersion)
	}

	orderReadyFlag := false
	var myOrder Order

	for !orderReadyFlag {
		myOrder, err = getOrderStatus(&netState, orderLocation)
		if err != nil {
			logger.Logger().Error().Msgf("Error while get Order: %v", err)
			log.Fatalf("%v/%v has crashed!", network.AcmeClientName, network.AcmeClientVersion)
		}

		if myOrder.Status == "valid" {
			orderReadyFlag = true
		}
		time.Sleep(100 * time.Millisecond)
	}

	certifBody, err := downloadCertificate(&netState, myOrder.Certificate)
	if err != nil {
		logger.Logger().Error().Msgf("Error while download certif: %v", err)
		log.Fatalf("%v/%v has crashed!", network.AcmeClientName, network.AcmeClientVersion)
	}

	certificateKeysString, _ := network.X509keysStringForDebug(certifKeysEnc, &certifKeysEnc.PublicKey)

	// DEBUG Code to generate *.pem files for certificate
	//err = os.WriteFile("cert.pem", []byte(certifBody), 0644)
	//if err != nil {
	//	log.Fatalf("Failed to write certificate to file: %v", err)
	//}
	//
	//err = os.WriteFile("key.pem", []byte(certificateKeysString), 0600)
	//if err != nil {
	//	log.Fatalf("Failed to write private key to file: %v", err)
	//}

	go httpCertif.HTTPCertificate(certifBody, certificateKeysString)

	if *revoke {
		blk, _ := pem.Decode([]byte(certifBody))
		err = revokeCert(&netState, dir.RevokeCert, base64.RawURLEncoding.EncodeToString(blk.Bytes))
		if err != nil {
			log.Fatalf("Failed to revoke certificate: %v", err)
		}
	}

	// Set a shutdown flag to break the polling loop for shutdown signal
	shutdownFlag := false

	for !shutdownFlag {
		select {
		case <-httpShutdown.ShutdownChannel: // Receive the sleep message
			slog.Info("Receive the sleepy message")
			if err := http01.Server.Shutdown(context.Background()); err != nil {
				slog.Error("Error while stopping the http01 server", "err", err)
			}
			if err := dns01.Server.Shutdown(); err != nil {
				slog.Error("Error while stopping the dns01 server", "err", err)
			}
			if err := httpCertif.Server.Shutdown(context.Background()); err != nil {
				slog.Error("Error while stopping the http certificate server", "err", err)
			}
			if err := httpShutdown.Server.Shutdown(context.Background()); err != nil {
				slog.Error("Error while stopping the http shutdown server", "err", err)
			}
			shutdownFlag = true
		case <-time.After(100 * time.Millisecond): // When done is closed, exit the loop
			continue
		}
	}

	slog.Info("Shutting down the ACME Client: %v/%v", network.AcmeClientName, network.AcmeClientVersion)
}

func getThumbprint(pKey *ecdsa.PrivateKey) (string, error) {
	xtostring := base64.RawURLEncoding.EncodeToString(pKey.PublicKey.X.Bytes())
	ytostring := base64.RawURLEncoding.EncodeToString(pKey.PublicKey.Y.Bytes())
	jwk := network.JWK{
		Crv: "P-256",
		Kty: "EC",
		X:   xtostring,
		Y:   ytostring,
	}
	encodedHeader, err := json.Marshal(jwk)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(encodedHeader)
	thumbprint := base64.RawURLEncoding.EncodeToString(hash[:])

	return thumbprint, nil
}
