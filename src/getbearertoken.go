// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Tool that is used to get a bearer token from certificate based authentication
//
// Output:
//

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/paulomarquesc/getbearertoken/getbearertoken/internal/iam"
	"github.com/paulomarquesc/getbearertoken/getbearertoken/internal/utils"
)

const (
	ERR_AUTHORIZER                = 2
	ERR_INVALID_ARGUMENT          = 3
	ERR_CERTIFICATE_NOT_FOUND     = 10
	ERR_INVALID_AZURE_ENVIRONMENT = 11
)

var (
	validEnvironments = []string{"AZUREPUBLICCLOUD", "AZUREUSGOVERNMENTCLOUD", "AZUREGERMANCLOUD", "AZURECHINACLOUD"}
	certificate       = flag.String("certificate", "", "full path to the certificate in PEM format containing the certificate and private key to be used in the authenticaton process")
	environment       = flag.String("environment", "AZUREPUBLICCLOUD", fmt.Sprintf("valid azure cloud environments: %v", validEnvironments))
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

func main() {
	cntx := context.Background()

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

	// Getting authorizer
	auth, err := iam.GetAuthorizer()
	if err != nil {
		utils.ConsoleOutput(fmt.Sprintf("an error ocurred while obtaining authorizer: %v.", err), stderr)
		exitCode = ERR_AUTHORIZER
		return
	}

	println(auth)
	// // Flag subcommands
	// versionCommand := flag.NewFlagSet("version", flag.ExitOnError)
	// createLeaseBlobCommand := flag.NewFlagSet("createleaseblob", flag.ExitOnError)
	// acquireCommand := flag.NewFlagSet("acquire", flag.ExitOnError)
	// renewCommand := flag.NewFlagSet("renew", flag.ExitOnError)
	// // TODO: Implement release command

	// // CreateLeaseBlob subcommand flag pointers
	// createLeaseBlobSubscriptionIDPtr := createLeaseBlobCommand.String("subscriptionid", "", "Subscription where the Storage Account is located")
	// createLeaseBlobResourceGroupNamePtr := createLeaseBlobCommand.String("resourcegroupname", "", "Storage Account Resource Group Name")
	// createLeaseBlobAccountNamePtr := createLeaseBlobCommand.String("accountname", "", "Storage Account Name")
	// createLeaseBlobBlobContainerPtr := createLeaseBlobCommand.String("container", "", "Blob container name")
	// createLeaseBlobBlobBlobNamePtr := createLeaseBlobCommand.String("blobname", config.BlobName(), "Blob name")
	// createLeaseBlobEnvironmentPtr := createLeaseBlobCommand.String("environment", "AZUREPUBLICCLOUD", fmt.Sprintf("Azure cloud type, currently supported ones are: %v", config.ValidEnvironments()))

	// // Acquire subcommand flag pointers
	// acquireSubscriptionIDPtr := acquireCommand.String("subscriptionid", "", "Subscription where the Storage Account is located")
	// acquireResourceGroupNamePtr := acquireCommand.String("resourcegroupname", "", "Storage Account Resource Group Name")
	// acquireAccountNamePtr := acquireCommand.String("accountname", "", "Storage Account Name")
	// acquireBlobContainerPtr := acquireCommand.String("container", "", "Blob container name")
	// acquireBlobNamePtr := acquireCommand.String("blobname", config.BlobName(), "Blob name")
	// acquireLeaseDurationPtr := acquireCommand.Int("leaseduration", 60, "Lease duration in seconds, valid values are between 15 and 60, -1 is not supported in this tool")
	// acquireRetriesPtr := acquireCommand.Int("retries", 1, "Lease acquire operation, number of retry attempts")
	// acquireWaitTimeSecPtr := acquireCommand.Int("waittimesec", 0, "Time in seconds between iterations to renew current lease, must be between 1 and 59 seconds, ideally half of the time used when acquiring lease")
	// acquireEnvironmentPtr := acquireCommand.String("environment", "AZUREPUBLICCLOUD", fmt.Sprintf("Azure cloud type, currently supported ones are: %v", config.ValidEnvironments()))

	// // Renew subcommand flag pointers
	// renewSubscriptionIDPtr := renewCommand.String("subscriptionid", "", "Subscription where the Storage Account is located")
	// renewResourceGroupNamePtr := renewCommand.String("resourcegroupname", "", "Storage Account Resource Group Name")
	// renewAccountNamePtr := renewCommand.String("accountname", "", "Storage Account Name")
	// renewBlobContainerPtr := renewCommand.String("container", "", "Blob container name")
	// renewBlobNamePtr := renewCommand.String("blobname", config.BlobName(), "Blob name")
	// renewLeaseIDPtr := renewCommand.String("leaseid", "", "GUID value that represents the acquired lease")
	// renewIterationsPtr := renewCommand.Int("iterations", 20, "Lease renew, number of times it will repeat renew operation")
	// renewWaitTimeSecPtr := renewCommand.Int("waittimesec", 30, "Time in seconds between iterations to renew current lease, must be between 1 and 59 seconds, ideally half of the time used when acquiring lease")
	// renewEnvironmentPtr := renewCommand.String("environment", "AZUREPUBLICCLOUD", fmt.Sprintf("Azure cloud type, currently supported ones are: %v", config.ValidEnvironments()))

	// flag.Parse()

	// if len(os.Args) < 2 {
	// 	utils.PrintHeader(fmt.Sprintf("azbloblease - CLI tool to help on leader elections based on Azure Blob Storage blob leasing process - v%v", config.Version()))

	// 	fmt.Println("")
	// 	fmt.Println("General usage")
	// 	fmt.Println("")
	// 	fmt.Println("\tazbloblease <command> <options>")
	// 	fmt.Println("")

	// 	fmt.Println("List of commands and their options")

	// 	fmt.Println("")
	// 	fmt.Println(fmt.Sprintf("%v - Creates a blob to be used for the lease process", createLeaseBlobCommand.Name()))
	// 	fmt.Println("")
	// 	createLeaseBlobCommand.PrintDefaults()
	// 	fmt.Println("")
	// 	fmt.Println("\tExample")
	// 	fmt.Println("\t\tazbloblease createleaseblob -accountname \"mystorageaccount\" -container \"azbloblease\" -blobname \"myblob\" -resourcegroupname \"my-rg\" -subscriptionid \"11111111-1111-1111-1111-111111111111\"")
	// 	fmt.Println("")
	// 	fmt.Println("\tOutputs")
	// 	fmt.Println("\t\tstdout - json response after createleaseblob process is executed")
	// 	fmt.Println("\t\tstderr - error messages")

	// 	fmt.Println("")
	// 	fmt.Println(fmt.Sprintf("%v - Acquires a lease", acquireCommand.Name()))
	// 	fmt.Println("")
	// 	acquireCommand.PrintDefaults()
	// 	fmt.Println("")
	// 	fmt.Println("\tExample")
	// 	fmt.Println("\t\tazbloblease acquire -accountname \"mystorageaccount\" -container \"azbloblease\" -blobname \"myblob\" -leaseduration 60 -resourcegroupname \"my-rg\" -subscriptionid \"11111111-1111-1111-1111-111111111111\"")
	// 	fmt.Println("")
	// 	fmt.Println("\tOutputs")
	// 	fmt.Println("\t\tstdout - json response after acquire process is executed")
	// 	fmt.Println("\t\tstderr - error messages")

	// 	fmt.Println("")
	// 	fmt.Println(fmt.Sprintf("%v - Renews a lease for # of iterations based on an interval between", renewCommand.Name()))
	// 	fmt.Println("")
	// 	renewCommand.PrintDefaults()
	// 	fmt.Println("")
	// 	fmt.Println("\tExample")
	// 	fmt.Println("\t\tazbloblease renew -accountname \"mystorageaccount\" -container \"azbloblease\" -blobname \"myblob\" -leaseid \"d3d63201-153b-453b-85ef-6c3bee3082f0\" -resourcegroupname \"my-rg\" -subscriptionid \"11111111-1111-1111-1111-111111111111\" -iterations 10 -waittimesec 30")
	// 	fmt.Println("")
	// 	fmt.Println("\tOutputs")
	// 	fmt.Println("\t\tstdout - json response after all renew iteration operations complete")
	// 	fmt.Println("\t\tstderr - diagnostic messages in every iteration and error messages")

	// 	fmt.Println("")
	// 	fmt.Println(fmt.Sprintf("%v - gets tool version", versionCommand.Name()))
	// 	fmt.Println("")
	// 	versionCommand.PrintDefaults()
	// 	fmt.Println("")
	// 	fmt.Println("\tExample")
	// 	fmt.Println("\t\tazbloblease version")
	// 	fmt.Println("")
	// 	fmt.Println("\tOutputs")
	// 	fmt.Println("\t\tstdout - tool version")

	// 	exitCode = config.ErrorCode("ErrInvalidArgument")
	// 	return
	// }

	// // Parsing flags based on subcommand
	// switch os.Args[1] {
	// case "version":
	// 	versionCommand.Parse(os.Args[2:])
	// case "createleaseblob":
	// 	createLeaseBlobCommand.Parse(os.Args[2:])
	// case "acquire":
	// 	acquireCommand.Parse(os.Args[2:])
	// case "renew":
	// 	renewCommand.Parse(os.Args[2:])
	// default:
	// 	flag.PrintDefaults()
	// 	exitCode = config.ErrorCode("ErrInvalidArgument")
	// 	return
	// }

	// // Executing chosen subcommand

	// // Version subcommand execution
	// if versionCommand.Parsed() {
	// 	fmt.Println(config.Version())
	// 	exitCode = 0
	// 	return
	// }

	// // CreateLeaseBlob subcommnad execution
	// if createLeaseBlobCommand.Parsed() {

	// 	// Validations
	// 	if *createLeaseBlobSubscriptionIDPtr == "" {
	// 		fmt.Println(createLeaseBlobCommand.Name())
	// 		createLeaseBlobCommand.PrintDefaults()
	// 		exitCode = config.ErrorCode("ErrInvalidArgumentMissingSubscriptionID")
	// 		return
	// 	}

	// 	if *createLeaseBlobResourceGroupNamePtr == "" {
	// 		fmt.Println(createLeaseBlobCommand.Name())
	// 		createLeaseBlobCommand.PrintDefaults()
	// 		exitCode = config.ErrorCode("ErrInvalidArgumentMissingResourceGroupName")
	// 		return
	// 	}

	// 	if *createLeaseBlobAccountNamePtr == "" {
	// 		fmt.Println(createLeaseBlobCommand.Name())
	// 		createLeaseBlobCommand.PrintDefaults()
	// 		exitCode = config.ErrorCode("ErrInvalidArgumentMissingAccountName")
	// 		return
	// 	}

	// 	if *createLeaseBlobBlobContainerPtr == "" {
	// 		fmt.Println(createLeaseBlobCommand.Name())
	// 		createLeaseBlobCommand.PrintDefaults()
	// 		exitCode = config.ErrorCode("ErrInvalidArgumentMissingContainer")
	// 		return
	// 	}

	// 	if strings.ToUpper(*createLeaseBlobEnvironmentPtr) != "AZUREPUBLICCLOUD" {
	// 		// Checks if valid cloud environment was passed
	// 		_, found := utils.FindInSlice(config.ValidEnvironments(), strings.ToUpper(*createLeaseBlobEnvironmentPtr))
	// 		if !found {
	// 			fmt.Println(createLeaseBlobCommand.Name())
	// 			createLeaseBlobCommand.PrintDefaults()
	// 			exitCode = config.ErrorCode("ErrInvalidCloudType")
	// 			return
	// 		}
	// 	}

	// 	// Run createLeaseBlob
	// 	createLeaseBlobResult := subcommands.CreateLeaseBlob(
	// 		cntx,
	// 		*createLeaseBlobSubscriptionIDPtr,
	// 		*createLeaseBlobResourceGroupNamePtr,
	// 		*createLeaseBlobAccountNamePtr,
	// 		strings.ToLower(*createLeaseBlobBlobContainerPtr),
	// 		*createLeaseBlobBlobBlobNamePtr,
	// 		strings.ToUpper(*createLeaseBlobEnvironmentPtr),
	// 	)

	// 	// Outputs json result in stdout
	// 	createLeaseBlobResult.Operation = to.StringPtr(createLeaseBlobCommand.Name())
	// 	utils.ConsoleOutput(
	// 		utils.BuildResultResponse(createLeaseBlobResult),
	// 		config.StdoutJSON(),
	// 	)
	// }

	// // Acquire subcommnad execution
	// if acquireCommand.Parsed() {

	// 	// Validations
	// 	if *acquireSubscriptionIDPtr == "" {
	// 		fmt.Println(acquireCommand.Name())
	// 		acquireCommand.PrintDefaults()
	// 		exitCode = config.ErrorCode("ErrInvalidArgumentMissingSubscriptionID")
	// 		return
	// 	}

	// 	if *acquireResourceGroupNamePtr == "" {
	// 		fmt.Println(acquireCommand.Name())
	// 		acquireCommand.PrintDefaults()
	// 		exitCode = config.ErrorCode("ErrInvalidArgumentMissingResourceGroupName")
	// 		return
	// 	}

	// 	if *acquireAccountNamePtr == "" {
	// 		fmt.Println(acquireCommand.Name())
	// 		acquireCommand.PrintDefaults()
	// 		exitCode = config.ErrorCode("ErrInvalidArgumentMissingAccountName")
	// 		return
	// 	}

	// 	if *acquireBlobContainerPtr == "" {
	// 		fmt.Println(acquireCommand.Name())
	// 		acquireCommand.PrintDefaults()
	// 		exitCode = config.ErrorCode("ErrInvalidArgumentMissingContainer")
	// 		return
	// 	}

	// 	if *acquireLeaseDurationPtr < 15 || *acquireLeaseDurationPtr > 60 {
	// 		fmt.Println(acquireCommand.Name())
	// 		acquireCommand.PrintDefaults()
	// 		exitCode = config.ErrorCode("ErrInvalidArgumentInvalidLeaseDuration")
	// 		return
	// 	}

	// 	if *acquireRetriesPtr < 1 {
	// 		fmt.Println(acquireCommand.Name())
	// 		acquireCommand.PrintDefaults()
	// 		exitCode = config.ErrorCode("ErrInvalidArgumentRetryCount")
	// 		return
	// 	}

	// 	if *acquireWaitTimeSecPtr < 0 || *acquireWaitTimeSecPtr > 59 {
	// 		fmt.Println(acquireCommand.Name())
	// 		acquireCommand.PrintDefaults()
	// 		exitCode = config.ErrorCode("ErrInvalidArgumentWaitTimeAcquire")
	// 		return
	// 	}

	// 	if strings.ToUpper(*acquireEnvironmentPtr) != "AZUREPUBLICCLOUD" {
	// 		// Checks if valid cloud environment was passed
	// 		_, found := utils.FindInSlice(config.ValidEnvironments(), strings.ToUpper(*acquireEnvironmentPtr))
	// 		if !found {
	// 			fmt.Println(acquireCommand.Name())
	// 			acquireCommand.PrintDefaults()
	// 			exitCode = config.ErrorCode("ErrInvalidCloudType")
	// 			return
	// 		}
	// 	}

	// 	// Run acquire
	// 	acquireResult := subcommands.AcquireLease(
	// 		cntx,
	// 		*acquireSubscriptionIDPtr,
	// 		*acquireResourceGroupNamePtr,
	// 		*acquireAccountNamePtr,
	// 		strings.ToLower(*acquireBlobContainerPtr),
	// 		*acquireBlobNamePtr,
	// 		strings.ToUpper(*acquireEnvironmentPtr),
	// 		*acquireLeaseDurationPtr,
	// 		*acquireRetriesPtr,
	// 		*acquireWaitTimeSecPtr,
	// 	)

	// 	// Outputs json result in stdout
	// 	acquireResult.Operation = to.StringPtr(acquireCommand.Name())
	// 	utils.ConsoleOutput(
	// 		utils.BuildResultResponse(acquireResult),
	// 		config.StdoutJSON(),
	// 	)
	// }

	// // Renew subcommnad execution
	// if renewCommand.Parsed() {

	// 	// Validations
	// 	if *renewSubscriptionIDPtr == "" {
	// 		fmt.Println(renewCommand.Name())
	// 		renewCommand.PrintDefaults()
	// 		exitCode = config.ErrorCode("ErrInvalidArgumentMissingSubscriptionID")
	// 		return
	// 	}

	// 	if *renewResourceGroupNamePtr == "" {
	// 		fmt.Println(renewCommand.Name())
	// 		renewCommand.PrintDefaults()
	// 		exitCode = config.ErrorCode("ErrInvalidArgumentMissingResourceGroupName")
	// 		return
	// 	}

	// 	if *renewAccountNamePtr == "" {
	// 		fmt.Println(renewCommand.Name())
	// 		renewCommand.PrintDefaults()
	// 		exitCode = config.ErrorCode("ErrInvalidArgumentMissingAccountName")
	// 		return
	// 	}

	// 	if *renewBlobContainerPtr == "" {
	// 		fmt.Println(renewCommand.Name())
	// 		renewCommand.PrintDefaults()
	// 		exitCode = config.ErrorCode("ErrInvalidArgumentMissingContainer")
	// 		return
	// 	}

	// 	if *renewLeaseIDPtr == "" {
	// 		fmt.Println(renewCommand.Name())
	// 		renewCommand.PrintDefaults()
	// 		exitCode = config.ErrorCode("ErrInvalidArgumentMissingLeaseID")
	// 		return
	// 	}

	// 	if *renewIterationsPtr < 1 {
	// 		fmt.Println(renewCommand.Name())
	// 		renewCommand.PrintDefaults()
	// 		exitCode = config.ErrorCode("ErrInvalidArgumentIterationsCount")
	// 		return
	// 	}

	// 	if *renewWaitTimeSecPtr < 1 || *renewWaitTimeSecPtr > 59 {
	// 		fmt.Println(renewCommand.Name())
	// 		renewCommand.PrintDefaults()
	// 		exitCode = config.ErrorCode("ErrInvalidArgumentWaitTime")
	// 		return
	// 	}

	// 	if strings.ToUpper(*renewEnvironmentPtr) != "AZUREPUBLICCLOUD" {
	// 		// Checks if valid cloud environment was passed
	// 		_, found := utils.FindInSlice(config.ValidEnvironments(), strings.ToUpper(*renewEnvironmentPtr))
	// 		if !found {
	// 			fmt.Println(renewCommand.Name())
	// 			renewCommand.PrintDefaults()
	// 			exitCode = config.ErrorCode("ErrInvalidCloudType")
	// 			return
	// 		}
	// 	}

	// 	// Run renew
	// 	renewResult := subcommands.RenewLease(
	// 		cntx,
	// 		*renewSubscriptionIDPtr,
	// 		*renewResourceGroupNamePtr,
	// 		*renewAccountNamePtr,
	// 		strings.ToLower(*renewBlobContainerPtr),
	// 		*renewBlobNamePtr,
	// 		*renewLeaseIDPtr,
	// 		strings.ToUpper(*renewEnvironmentPtr),
	// 		*renewIterationsPtr,
	// 		*renewWaitTimeSecPtr,
	// 	)

	// 	// Outputs result into stdout
	// 	renewResult.Operation = to.StringPtr(renewCommand.Name())
	// 	utils.ConsoleOutput(
	// 		utils.BuildResultResponse(renewResult),
	// 		config.StdoutJSON(),
	// 	)
	// }
}
