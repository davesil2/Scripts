<#
.SYNOPSIS
Initialize connection to citrix cloud and obtain header for future requests

.DESCRIPTION
This function will call to Citrix Cloud REST API and obtain a token and generate appropriate headers for other function calls

.PARAMETER CloudURI
CloudURI is the URI that will be use for the FQDN of the call the citrix cloud.

    DEFAULT: api-us.cloud.com

    https://developer-docs.citrix.com/en-us/citrix-cloud/citrix-cloud-api-overview/get-started-with-citrix-cloud-apis

.PARAMETER ClientID
ClientID is the generated ID for the Service Principal or API Key Pair based on direction from the Citrix Developer Guid

.PARAMETER ClientSecret
ClientSecret is like the pass phrase associated with the ClientID, this should be protected

.PARAMETER CustomerID
CustomerID is the unique accounts.cloud.com ID provided by Citrix for your unique tenant space

.EXAMPLE
Calling the function with the specifice ClientID, ClientSecret and CustomerID will return headers to be used in future function calls

$Headers = Connect-CitrixRESTAPI `
    -ClientID       'abdf26c6-39b1-41cf-af29-b3dfc08c1580' `
    -ClientSecret   'asdf943sadfj342ad==' `
    -CustomerID     'u9tviazeowms'

    **NOTE: the headers variable would be used by other functions
#>
function Connect-CitrixRESTAPI {
    Param(
        [string]$CloudURI = 'api-us.cloud.com',
        [parameter(Mandatory=$true)]
        [string]$ClientID,
        [parameter(Mandatory=$true)]
        [string]$ClientSecret,
        [parameter(Mandatory=$true)]
        [string]$CustomerID,
        [ValidateScript(
            {$_ -in ([enum]::GetNames([net.securityprotocoltype]))},
            ErrorMessage = 'ERROR: TLS version must be supported on system (run [enum]::GetNames([net.securityprotocoltype]) for a valid list)'
        )]
        [string]$TLSVersion = 'Tls12'
    )

    # set TLS version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::"$TLSVersion"
    
    # generate uri for generating token
    [System.UriBuilder]$URI = ('https://{0}/cctrustoauth2/root/tokens/clients' -f $CloudURI)

    # generate body for call to generate token
    $tokenbody = @{
        grant_type      = "client_credentials"
        client_id       = $ClientID
        client_secret   = $ClientSecret
    }

    # generate splat parameters to send for token initialization
    $tokenparams = @{
        ErrorAction = 'SilentlyContinue'
        Method      = 'POST'
        Body        = $tokenbody
        Uri         = $URI.Uri
    }

    # execute request for token
    $_response = Invoke-RestMethod @tokenparams

    # generate headers from token response
    $_Headers = @{
        'Authorization'       = ("CWSAuth Bearer={0}" -f $_response.access_token)
        'Citrix-CustomerID'   = $CustomerID
        'Accept'              = 'application/json'
    }

    if ($_response.access_token) {
        # validate token with query about self
        [System.UriBuilder]$URI = ('https://{0}/cvadapis/me' -f $CloudURI)

        # generate splat values for query about self
        $validationparams = @{
            ContentType = 'application/json'
            UserAgent   = 'Mozilla/5.0'
            Headers     = $_Headers
            ErrorAction = 'SilentlyContinue'
            URI         = $URI.uri
        }
    
        # execute query about self
        $_response = Invoke-RestMethod @ValidationParams
        
        # add instance ID to headers
        if ($_Response) {
            $_Headers += @{
                'Citrix-InstanceID' = $_response.Customers.Sites.id
            }
        }
        
        # return headers if successful
        if ($_Headers) {
            return $_Headers
        } else {
            # throw error if token doesn't work with company
            throw 'Error Occured - unable to validate access, verify company info'
        }
    } else {
        # throw error if authentication failed
        throw 'Error Occured - unable to obtain token, verify credentials'
    }
    
}

<#
.SYNOPSIS
Obtain a list of Machine Catalogs from Citrix Cloud

.DESCRIPTION
Using headers generted from Connect-CitrixRESTAPI or manually, the function calls the the default FQDN api-us.cloud.com to get a list of machine catalogs present in the Citrix Cloud Console

.PARAMETER CloudURI
CloudURI is the URI that will be use for the FQDN of the call the citrix cloud.

    DEFAULT: api-us.cloud.com

    https://developer-docs.citrix.com/en-us/citrix-cloud/citrix-cloud-api-overview/get-started-with-citrix-cloud-apis

.PARAMETER Headers
Header information used to authenticate and authorize access into the cloud platform.  The header names below are required.

    Citrix-CustomerID
    CitrixInstanceID
    Authorization

.EXAMPLE
Calling to Citrix Cloud requires a valid headers output.  Then calling the Get-CitrixMachineCatalog with that information will provide a list of catalogs

$Headers = Connect-CitrixRESTAPI `
    -ClientID $env:clientid `
    -ClientSecret $env:clientsecret `
    -CustomerID $env:customerid

Get-CitrixMachineCatalog `
    -Headers $Headers

#>
function Get-CitrixMachineCatalog {
    Param(
        [string]$CloudURI = 'api-us.cloud.com',
        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,
        [ValidateScript(
            {$_ -in ([enum]::GetNames([net.securityprotocoltype]))},
            ErrorMessage = 'ERROR: TLS version must be supported on system (run [enum]::GetNames([net.securityprotocoltype]) for a valid list)'
        )]
        [string]$TLSVersion = 'Tls12'
    )

    # set TLS version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::"$TLSVersion"

    # build URI for use to access machine catalog
    [System.UriBuilder]$URI = ('https://{0}/cvad/manage/MachineCatalogs' -f $CloudURI)

    # build parameters for splat into invoke-restmethod
    $parameters = @{
        ContentType = 'application/json'
        UserAgent   = 'Mozilla/5.0'
        ErrorAction = 'silentlyContinue'
        Uri         = $URI.Uri
        Headers     = $Headers
    }

    # execute call to uri with Splat parameters
    $_response = Invoke-RestMethod @parameters

    if ($_response) {
        # return list of machine catalogs if the return is valid
        return $_response.items
    } else {
        # throw an error if no output is created
        throw 'ERROR: no response recieved, check header output, credentials and customerid'
    }
}