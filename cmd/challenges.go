package main

import (
	"encoding/json"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/netzuser-acme-project/logger"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/netzuser-acme-project/network"
	"io"
	"time"
)

type challenge struct {
	Type   string `json:"type"`
	Url    string `json:"url"`
	Token  string `json:"token"`
	Status string `json:"status"`
}

type challengesList struct {
	Status     string `json:"status"`
	Identifier struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"identifier"`
	Challenges []challenge `json:"challenges"`
	Expires    time.Time   `json:"expires"`
}

func fetchChallenges(netState *network.StateNetwork, url string, includeCurlyBracesPayload bool) (challengesList, error) {

	var jsonPayload []byte

	if includeCurlyBracesPayload {
		jsonPayload = []byte("{}")
	}

	res, err := network.SendPayloadThroughJWS(jsonPayload, url, netState)
	if err != nil {
		return challengesList{}, err
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return challengesList{}, err
	}

	logger.Logger().Debug().Msgf("\nRES:" + string(body) + "\n")

	// Init the data structure
	challengeList := challengesList{}

	err = json.Unmarshal(body, &challengeList)
	if err != nil {
		return challengesList{}, err
	}

	return challengeList, nil
}
