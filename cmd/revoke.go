package main

import (
	"encoding/json"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/netzuser-acme-project/logger"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2024-acme/netzuser-acme-project/network"
	"io"
)

type revoke struct {
	Certificate string `json:"certificate"`
}

func revokeCert(netState *network.StateNetwork, url string, certID string) error {

	rev := revoke{
		Certificate: certID,
	}

	jsonPayload, err := json.Marshal(rev)
	if err != nil {
		return err
	}

	res, err := network.SendPayloadThroughJWS(jsonPayload, url, netState)
	if err != nil {
		return err
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	logger.Logger().Debug().Msgf("\nRES:" + string(body) + "\n")

	return nil
}
