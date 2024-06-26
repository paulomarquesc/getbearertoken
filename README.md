# getbearertoken.go
Golang tool that authenticates against Entra ID using a certificate in pfx format or managed identity and generates a token file.

## Usage

```
Usage of ./getbearertoken:
  -applicationid string
        service principal's application id
  -certificate string
        full path to the certificate, pfx-formatted, containing the certificate and private key to be used in the authentication process, cannot be used with -usemanagedidentity argument
  -pfxpassword string
        optional, pfx file password, it defaults to empty string, cannot be used with -usemanagedidentity argument
  -tenantid string
        service principal's tenant id
  -tokenfileoutput string
        full filename of the generated token
  -usesniauth
        uses sn+i authentication method, cannot be used with -usemanagedidentity argument
  -version
        shows current tool version
  -usemanagedidentity
        use managed identities instead of service principal for authentication, cannot be used in combination of certificate related authentication arguments (-certificate, -pfxpassword, -usesniauth)
```

## Known Exit Error Codes

```golang
ERR_AUTH_CONFIG           = 2
ERR_AUTH_TOKEN            = 3
ERR_INVALID_ARGUMENT      = 4
ERR_CERTIFICATE_NOT_FOUND = 5
ERR_CERTIFICATE           = 6
ERR_ARGUMENTS             = 7
```

## Execution Example

```bash
APP_ID=<YOUR APP ID>
TENANT_ID=<YOUR AAD TENANT ID>

./getbearertoken -applicationid $APP_ID -certificate ~/cert1.pfx -tenantid $TENANT_ID -tokenfileoutput ~/token.json
```

## Screenshot
![output](./.media/screenshot.png)