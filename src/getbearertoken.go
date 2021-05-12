// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Tool that is used to get a bearer token from certificate based authentication
//
// Outputs:
//  - token file in json format
//
// Notes:
// Autorest adal reference: https://github.com/Azure/go-autorest/tree/master/autorest/adal
//

package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/paulomarquesc/getbearertoken/src/internal/utils"
)

const (
	ERR_AUTH_CONFIG               = 2
	ERR_AUTH_TOKEN                = 3
	ERR_INVALID_ARGUMENT          = 5
	ERR_CERTIFICATE_NOT_FOUND     = 10
	ERR_INVALID_AZURE_ENVIRONMENT = 11
	activeDirectoryEndpoint       = "https://login.microsoftonline.com/"
	resource                      = "https://management.core.windows.net/"
)

var (
	validEnvironments = []string{"AZUREPUBLICCLOUD", "AZUREUSGOVERNMENTCLOUD", "AZUREGERMANCLOUD", "AZURECHINACLOUD"}
	applicationID     = flag.String("applicationid", "", "service principal's application id")
	tenantID          = flag.String("tenantid", "", "service principal's tenant id")
	certificate       = flag.String("certificate", "", "full path to the certificate, pfx-formatted, containing the certificate and private key to be used in the authenticaton process")
	pfxPassword       = flag.String("pfxpassword", "", "optional, pfx file password, it defaults to empty string")
	tokenFileOutput   = flag.String("tokenfileoutput", "", "full filename of the generated token")
	cmdlineversion    = flag.Bool("version", false, "shows current tool version")
	exitCode          = 0
	version           = "0.1.0"
	stdout            = log.New(os.Stdout, "", log.LstdFlags)
	stderr            = log.New(os.Stderr, "", log.LstdFlags)
)

func exit(cntx context.Context, exitCode int) {
	if exitCode > 0 {
		os.Exit(exitCode)
	}
}

func decodePkcs12(pkcs []byte, password string) (*x509.Certificate, *rsa.PrivateKey, error) {
	return adal.DecodePfxCertificateData(pkcs, password)
}

func getOAuthConfig(tenantID string) (adal.OAuthConfig, error) {
	oauthConfig, err := adal.NewOAuthConfig(activeDirectoryEndpoint, tenantID)

	if err != nil {
		return adal.OAuthConfig{}, err
	}

	return *oauthConfig, nil
}

func getTokenUsingCertificate(certificatePath string,
	pfxPassword string,
	oauthConfig adal.OAuthConfig,
	callbacks ...adal.TokenRefreshCallback) (*adal.ServicePrincipalToken, error) {

	certData, err := ioutil.ReadFile(certificatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read the certificate file (%s): %v", certificatePath, err)
	}

	// Get the certificate and private key from pfx file
	certificate, rsaPrivateKey, err := decodePkcs12(certData, pfxPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to decode pkcs12 certificate while creating service principal token: %v", err)
	}

	spt, err := adal.NewServicePrincipalTokenFromCertificate(
		oauthConfig,
		*applicationID,
		certificate,
		rsaPrivateKey,
		resource,
		callbacks...)
	if err != nil {
		return nil, fmt.Errorf("failed to invoke NewServicePrincipalTokenFromCertificate: %v", err)
	}

	return spt, spt.Refresh()
}

func main() {
	cntx := context.Background()

	callback := func(token adal.Token) error {
		err := adal.SaveToken(*tokenFileOutput, 0600, token)
		if err != nil {
			return err
		}
		return nil
	}

	// Cleanup and exit handling
	defer func() { exit(cntx, exitCode); os.Exit(exitCode) }()

	flag.Parse()

	if len(os.Args[1:]) < 1 {
		utils.ConsoleOutput(fmt.Sprintf("<error> invalid number of arguments, please execute %v -h or --help for more information", os.Args[0]), stderr)
		exitCode = ERR_INVALID_ARGUMENT
		return
	}

	// Checks if version output is needed
	if *cmdlineversion == true {
		fmt.Println(version)
		exitCode = 0
		return
	}

	oauthConfig, err := getOAuthConfig(*tenantID)
	if err != nil {
		utils.ConsoleOutput(fmt.Sprintf("<error> an error ocurred getting OAuth Config: %v", err), stderr)
		exitCode = ERR_AUTH_CONFIG
		return
	}

	_, err = getTokenUsingCertificate(*certificate, *pfxPassword, oauthConfig, callback)
	if err != nil {
		utils.ConsoleOutput(fmt.Sprintf("<error> an error ocurred getting service principal token: %v", err), stderr)
		exitCode = ERR_AUTH_TOKEN
		return
	}
}
