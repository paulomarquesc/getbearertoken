// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// getbearertoken - Tool that is used to get a bearer token from certificate based authentication
//
// Outputs:
//  - token file in json format
//
// Notes:
// Autorest adal reference: https://github.com/Azure/go-autorest/tree/master/autorest/adal

package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"

	"getbearertoken/internal/utils"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"software.sslmate.com/src/go-pkcs12"
)

const (
	ERR_AUTH_CONFIG           = 2
	ERR_AUTH_TOKEN            = 3
	ERR_INVALID_ARGUMENT      = 4
	ERR_CERTIFICATE_NOT_FOUND = 5
	ERR_CERTIFICATE           = 6
	ERR_ARGUMENTS             = 7
	resource                  = "https://management.core.windows.net/" //TODO: make it a parameter for other clouds
)

var (
	applicationID      = flag.String("applicationid", "", "service principal's application id")
	tenantID           = flag.String("tenantid", "", "service principal's tenant id")
	certificateFile    = flag.String("certificate", "", "full path to the certificate, pfx-formatted, containing the certificate and private key to be used in the authenticaton process")
	pfxPassword        = flag.String("pfxpassword", "", "optional, pfx file password, it defaults to empty string")
	tokenFileOutput    = flag.String("tokenfileoutput", "", "full filename of the generated token")
	cmdLineVersion     = flag.Bool("version", false, "shows current tool version")
	sniAuth            = flag.Bool("usesniauth", false, "uses sn+i authentication option")
	useManagedIdentity = flag.Bool("usemanagedidentity", false, "use managed identity for authentication")
	exitCode           = 0
	version            = "1.1.0"
	stdout             = log.New(os.Stdout, "", log.LstdFlags)
	stderr             = log.New(os.Stderr, "", log.LstdFlags)
)

func exit(exitCode int) {
	if exitCode > 0 {
		os.Exit(exitCode)
	}
}

func decodePFX(certData []byte, pfxPassword string) (interface{}, *x509.Certificate, error) {
	rsaPrivateKey, certificate, err := pkcs12.Decode(certData, pfxPassword)
	if err != nil {
		utils.ConsoleOutput(fmt.Sprintf("failed to decode PKCS#12 certificate: %v", err), stderr)
		return nil, nil, err
	}

	return rsaPrivateKey, certificate, nil
}

func main() {
	cntx := context.Background()

	// Cleanup and exit handling
	defer func() { exit(exitCode); os.Exit(exitCode) }()

	flag.Parse()

	if len(os.Args[1:]) < 1 {
		utils.ConsoleOutput(fmt.Sprintf("<error> invalid number of arguments, please execute %v -h or --help for more information", os.Args[0]), stderr)
		exitCode = ERR_INVALID_ARGUMENT
		return
	}

	// Checks if version output is needed
	if *cmdLineVersion {
		fmt.Println(version)
		exitCode = 0
		return
	}

	// Checks if useManagedIdentity is set while using certificate arguments
	if *useManagedIdentity && (*sniAuth || *certificateFile != "" || *pfxPassword != "") {
		utils.ConsoleOutput("<error> cannot use certificate arguments while using -usemanagedidentity", stderr)
		exitCode = 7
		return
	}

	var err error
	var rsaPrivateKey interface{}
	var certificate *x509.Certificate
	clientCredentialOptions := azidentity.ClientCertificateCredentialOptions{}

	// Checking if cert file exists
	if !*useManagedIdentity {
		utils.ConsoleOutput("Checking if certificate file exists...", stdout)
		if _, err := os.Stat(*certificateFile); err != nil {
			utils.ConsoleOutput(fmt.Sprintf("<error> certificate file %v, not found: %v", *certificateFile, err), stderr)
			exitCode = ERR_CERTIFICATE_NOT_FOUND
			return
		}

		// Read the certificate file
		utils.ConsoleOutput("Reading the certificate file...", stdout)
		certData, err := os.ReadFile(*certificateFile)
		if err != nil {
			utils.ConsoleOutput(fmt.Sprintf("<error> failed to read the certificate file (%s): %v", *certificateFile, err), stderr)
			exitCode = ERR_CERTIFICATE_NOT_FOUND
			return
		}

		// Get the certificate and private key from pfx file
		utils.ConsoleOutput("Decoding the PFX to get the certificate and private key...", stdout)
		rsaPrivateKey, certificate, err = decodePFX(certData, *pfxPassword)
		if err != nil {
			utils.ConsoleOutput(fmt.Sprintf("failed to decode pkcs12 certificate while creating service principal token: %v", err), stderr)
			return
		}

		// Get the NewClientCertificateCredential
		utils.ConsoleOutput("Creating NewClientCertificateCredential...", stdout)

		if *sniAuth {
			clientCredentialOptions.SendCertificateChain = true
		}
	}

	var cred azcore.TokenCredential

	if *useManagedIdentity {
		// Create a credential using Managed Identity
		cred, err = azidentity.NewManagedIdentityCredential(nil)
		if err != nil {
			utils.ConsoleOutput(fmt.Sprintf("<error> an error occurred creating ManagedIdentityCredential: %v", err), stderr)
			exitCode = ERR_AUTH_CONFIG
			return
		}
	} else {
		// Create the credential based on certificate
		cred, err = azidentity.NewClientCertificateCredential(*tenantID, *applicationID, []*x509.Certificate{certificate}, rsaPrivateKey.(*rsa.PrivateKey), &clientCredentialOptions)
		if err != nil {
			utils.ConsoleOutput(fmt.Sprintf("<error> an error occurred creating ClientCertificateCredential: %v", err), stderr)
			exitCode = ERR_AUTH_CONFIG
			return
		}
	}

	// Get the token
	utils.ConsoleOutput("Getting the token...", stdout)
	tok, err := cred.GetToken(cntx, policy.TokenRequestOptions{Scopes: []string{resource + "/.default"}})
	if err != nil {
		utils.ConsoleOutput(fmt.Sprintf("<error> an error occurred getting the token: %v", err), stderr)
		exitCode = ERR_AUTH_TOKEN
		return
	}

	// Write the token to the output file
	utils.ConsoleOutput(fmt.Sprintf("Writing the token to the output file %v ...", *tokenFileOutput), stdout)
	err = os.WriteFile(*tokenFileOutput, []byte(tok.Token), 0600)
	if err != nil {
		utils.ConsoleOutput(fmt.Sprintf("<error> an error occurred writing the token to the file: %v", err), stderr)
		exitCode = ERR_AUTH_TOKEN
		return
	}
}
