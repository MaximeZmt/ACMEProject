package main

import (
	"encoding/json"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/netzuser-acme-project/logger"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/netzuser-acme-project/network"
	"io"
	"time"
)

type identifiers struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Order struct {
	Status         string        `json:"status"`
	Expires        time.Time     `json:"expires"`
	Identifiers    []identifiers `json:"identifiers"`
	Profile        string        `json:"profile"`
	Finalize       string        `json:"finalize"`
	NotBefore      time.Time     `json:"notBefore"`
	NotAfter       time.Time     `json:"notAfter"`
	Authorizations []string      `json:"authorizations"`
	Certificate    string        `json:"certificate"`
}

type newOrder struct {
	Identifiers []identifiers `json:"identifiers"`
}

func createOrder(netState *network.StateNetwork, url string, domainList []string) (Order, string, error) {
	var identifierList []identifiers

	for _, domain := range domainList {
		identif := identifiers{
			Type:  "dns",
			Value: domain,
		}
		identifierList = append(identifierList, identif)
	}

	payload := newOrder{
		Identifiers: identifierList,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return Order{}, "", err
	}

	res, err := network.SendPayloadThroughJWS(jsonPayload, url, netState)
	if err != nil {
		return Order{}, "", err
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return Order{}, "", err
	}

	logger.Logger().Debug().Msgf("\nRES:" + string(body) + "\n")

	// Init the data structure
	myOrders := Order{}

	err = json.Unmarshal(body, &myOrders)
	if err != nil {
		return Order{}, "", err
	}

	return myOrders, res.Header.Get("Location"), nil
}

func getOrderStatus(netState *network.StateNetwork, url string) (Order, error) {

	jsonPayload := []byte("")

	res, err := network.SendPayloadThroughJWS(jsonPayload, url, netState)
	if err != nil {
		return Order{}, err
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return Order{}, err
	}

	logger.Logger().Debug().Msgf("\nRES:" + string(body) + "\n")

	// Init the data structure
	myOrder := Order{}

	err = json.Unmarshal(body, &myOrder)
	if err != nil {
		return Order{}, err
	}

	return myOrder, nil
}
