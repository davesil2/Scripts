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

function Get-CitrixHypervisors {
    Param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,
        [String]$HypervisorNameOrID,
        [string]$CloudURI = "api-us.cloud.com",
        [ValidateScript(
            {$_ -in ([enum]::GetNames([net.securityprotocoltype]))},
            ErrorMessage = 'ERROR: TLS version must be supported on system (run [enum]::GetNames([net.securityprotocoltype]) for a valid list)'
        )]
        [string]$TLSVersion = 'Tls12',
        [switch]$async
    )

    # set TLS version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::"$TLSVersion"

    # build URI for use to access machine catalog
    [System.UriBuilder]$URI = ('https://{0}/cvad/manage/hypervisors' -f $CloudURI)

    if ($HypervisorNameOrID) {
        $URI.Path += ('/{0}' -f $HypervisorNameOrID)
    }

    $URI.Query = ([System.Web.HttpUtility]::ParseQueryString('')['async'] = $async.tostring())

    # build parameters for splat into invoke-restmethod
    $parameters = @{
        Method      = 'GET'
        ContentType = 'application/json'
        UserAgent   = 'Mozilla/5.0'
        ErrorAction = 'silentlyContinue'
        Uri         = $URI.Uri
        Headers     = $Headers
    }

    $Hypervisors = Invoke-RestMethod @parameters

    if ($Hypervisors) {
        return $Hypervisors.Items
    } else {
        throw "ERROR: no data received, check headers"
    }
}

function Get-CitrixMachines {
    Param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,
        [Parameter(Mandatory=$false)]
        [string]$MachineNameOrID,
        [int]$limit = 249,
        [string]$CloudURI = "api-us.cloud.com",
        [ValidateScript(
            {$_ -in ([enum]::GetNames([net.securityprotocoltype]))},
            ErrorMessage = 'ERROR: TLS version must be supported on system (run [enum]::GetNames([net.securityprotocoltype]) for a valid list)'
        )]
        [string]$TLSVersion = 'Tls12',
        [switch]$async
    )

    # set TLS version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::"$TLSVersion"

    # build URI for use to access machine catalog
    [System.UriBuilder]$URI = ('https://{0}/cvad/manage/Machines' -f $CloudURI)

    if ($MachineNameOrID) {
        $URI.Path += ('/{0}' -f $MachineNameOrID)
    }

    # build parameters for splat into invoke-restmethod
    $parameters = @{
        Method      = 'GET'
        ContentType = 'application/json'
        UserAgent   = 'Mozilla/5.0'
        ErrorAction = 'silentlyContinue'
        Uri         = $URI.Uri
        Headers     = $Headers
    }

    $Result = Invoke-RestMethod @parameters

    if (($result.Items | measure-object).Count -gt 1) {
        $Machines = $Result.Items

        While ($Result.ContinuationToken -and $result.items.count -gt 0) {
            $URI.Query = ('?continuationToken={0}' -f $Result.continuationToken)
            $Parameters['Uri'] = $Uri.Uri
            $Result = Invoke-RestMethod @parameters
            $Machines += $result.items
        }
    } else {
        $Machines = $result
    }
    

    if ($Machines) {
        return $Machines
    } else {
        throw "[ERROR] - no data received, check headers"
    }
}

function Remove-CitrixMachine {
    Param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,
        [Parameter(Mandatory=$True)]
        [string]$MachineNameOrID,
        [string]$CloudURI = "api-us.cloud.com",
        [ValidateScript(
            {$_ -in ([enum]::GetNames([net.securityprotocoltype]))},
            ErrorMessage = 'ERROR: TLS version must be supported on system (run [enum]::GetNames([net.securityprotocoltype]) for a valid list)'
        )]
        [string]$TLSVersion = 'Tls12',
        [switch]$async
    )

    # set TLS version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::"$TLSVersion"

    # build URI for use to access machine catalog
    [System.UriBuilder]$URI = ('https://{0}/cvad/manage/Machines/{1}' -f $CloudURI,$MachineNameOrID)

    $URI.Query = ([System.Web.HttpUtility]::ParseQueryString('')['async'] = $async.tostring())

    # build parameters for splat into invoke-restmethod
    $parameters = @{
        Method      = 'DELETE'
        ContentType = 'application/json'
        UserAgent   = 'Mozilla/5.0'
        ErrorAction = 'silentlyContinue'
        Uri         = $URI.Uri
        Headers     = $Headers
    }

    $Result = Invoke-RestMethod @parameters

    if ($Result) {
        return $Result
    } else {
        throw ('[ERROR] - a problem occured deleting the machine')
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
function Get-CitrixMachineCatalogs {
    Param(
        [string]$CloudURI = 'api-us.cloud.com',
        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,
        [ValidateScript(
            {$_ -in ([enum]::GetNames([net.securityprotocoltype]))},
            ErrorMessage = 'ERROR: TLS version must be supported on system (run [enum]::GetNames([net.securityprotocoltype]) for a valid list)'
        )]
        [string]$TLSVersion = 'Tls12',
        [switch]$Async
    )

    # set TLS version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::"$TLSVersion"

    # build URI for use to access machine catalog
    [System.UriBuilder]$URI = ('https://{0}/cvad/manage/MachineCatalogs' -f $CloudURI)

    $URI.Query = ([System.Web.HttpUtility]::ParseQueryString('')['async'] = $async.tostring())

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

function Add-CitrixMachineCatalogMachine {
    Param(
        [string]$CloudURI = 'api-us.cloud.com',
        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,
        [Parameter(Mandatory=$true, HelpMessage='Domain Computer value domain\computer or SID')]
        [String]$MachineNameOrID,
        [Parameter(Mandatory=$true, HelpMessage='Catalog name or unique ID')]
        [String]$CatalogNameOrID,
        [Parameter(Mandatory=$true, HelpMessage='VM Unique ID')]
        [String]$HostedMachineID,
        [Parameter(Mandatory=$true, HelpMessage='Hypervisor Connection Name')]
        [String]$HypervisorConnection,
        [Parameter(Mandatory=$true, HelpMessage='Single or Multiple Users')]
        [String[]]$AssignedUsers,
        [ValidateScript(
            {$_ -in ([enum]::GetNames([net.securityprotocoltype]))},
            ErrorMessage = 'ERROR: TLS version must be supported on system (run [enum]::GetNames([net.securityprotocoltype]) for a valid list)'
        )]
        [string]$TLSVersion = 'Tls12',
        [switch]$async
    )

    # set TLS version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::"$TLSVersion"

    # build URI for use to access machine catalog
    [System.UriBuilder]$URI = ('https://{0}/cvad/manage/MachineCatalogs/{1}/Machines' -f $CloudURI,$CatalogNameOrID)

    # configure async query value
    $Query = [System.Web.HttpUtility]::ParseQueryString('')
    $Query.Add('async',$async.tostring())
    $URI.Query = $Query.ToString()
 
    # configure settings to send for body
    $Body = @{
        MachineName             = $MachineNameOrID
        AssignedUsers           = $AssignedUsers
        HostedMachineId         = $HostedMachineID
        HypervisorConnection    = $HypervisorConnection
    }

    # build parameters for splat into invoke-restmethod
    $parameters = @{
        ContentType = 'application/json'
        UserAgent   = 'Mozilla/5.0'
        ErrorAction = 'silentlyContinue'
        Uri         = $URI.Uri
        Headers     = $Headers
        Method      = 'POST'
        Body        = ($Body | ConvertTo-Json)
    }

    Write-Verbose ('[INFO] - URI [{0}]' -f $uri.Uri)

    $result = Invoke-RestMethod @parameters

    if ($result) {
        return $result
    }
}

function Remove-CitrixMachineCatalogMachine {
    Param(
        [Parameter(Mandatory=$true)]
        [String]$MachineCatalogNameOrID,
        [Parameter(Mandatory=$true)]
        [String]$MachineNameOrID,
        [string]$CloudURI = 'api-us.cloud.com',
        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,
        [ValidateScript(
            {$_ -in ([enum]::GetNames([net.securityprotocoltype]))},
            ErrorMessage = 'ERROR: TLS version must be supported on system (run [enum]::GetNames([net.securityprotocoltype]) for a valid list)'
        )]
        [string]$TLSVersion = 'Tls12',
        [switch]$Async
    )

    # set TLS version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::"$TLSVersion"

    # build URI for use to access machine catalog
    [System.UriBuilder]$URI = ('https://{0}/cvad/manage/MachineCatalogs/{1}/Machines/{2}' -f $CloudURI,$MachineCatalogNameOrID,$MachineNameOrID)

    # configure async query value
    $Query = [System.Web.HttpUtility]::ParseQueryString('')
    $Query.Add('async',$async.tostring())
    $URI.Query = $Query.ToString()

    $Parameters = @{
        Method      = 'DELETE'
        URI         = $URI.Uri
        Headers     = $Headers
        ContentType = 'application/json'
        UserAgent   = 'Mozilla/5.0'
        ErrorAction = 'silentlyContinue'
    }

    $Result = Invoke-RestMethod @Parameters

    if ($Result) {
        return $Result
    } else {
        throw '[ERROR] - '
    }
}

function Get-CitrixMachineCatalogMachines {
    Param(

    )
}

function Get-CitrixDeliveryGroups {
    Param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,
        [string]$CloudURI = "api-us.cloud.com",
        [ValidateScript(
            {$_ -in ([enum]::GetNames([net.securityprotocoltype]))},
            ErrorMessage = 'ERROR: TLS version must be supported on system (run [enum]::GetNames([net.securityprotocoltype]) for a valid list)'
        )]
        [string]$TLSVersion = 'Tls12',
        [switch]$async
    )

    # set TLS version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::"$TLSVersion"

    # build URI for use to access machine catalog
    [System.UriBuilder]$URI = ('https://{0}/cvad/manage/DeliveryGroups' -f $CloudURI,$DeliveryGroup,$Machine)
    
    $URI.Query = ([System.Web.HttpUtility]::ParseQueryString('')['async'] = $async.tostring())

    # build parameters for splat into invoke-restmethod
    $parameters = @{
        Method      = 'GET'
        ContentType = 'application/json'
        UserAgent   = 'Mozilla/5.0'
        ErrorAction = 'silentlyContinue'
        Uri         = $URI.Uri
        Headers     = $Headers
    }

    $DeliveryGroups = Invoke-RestMethod @parameters

    if ($DeliveryGroups) {
        return $DeliveryGroups.Items
    } else {
        throw "ERROR: no data received, check headers"
    }
}

<#
.SYNOPSIS

.DESCRIPTION

.EXAMPLE

.PARAMETER CloudURI

.PARAMETER Headers

.PARAMETER DeliveryGroupNameOrID

.PARAMETER MachineNameOrID

.PARAMETER CatalogNameOrID

.PARAMETER TLSVersion

.PARAMETER async

#>
function Add-CitrixDeliveryGroupMachine {
    Param(
        [String]$CloudURI = 'api-us.cloud.com',    
        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,    
        [Parameter(Mandatory=$true)]
        [String]$DeliveryGroupNameOrID,
        [Parameter(Mandatory=$true)]
        [String]$MachineNameOrID,
        [Parameter(Mandatory=$true)]
        [String]$CatalogNameOrID,
        [ValidateScript(
            {$_ -in ([enum]::GetNames([net.securityprotocoltype]))},
            ErrorMessage = 'ERROR: TLS version must be supported on system (run [enum]::GetNames([net.securityprotocoltype]) for a valid list)'
        )]
        [string]$TLSVersion = 'Tls12',
        [switch]$async
    )

    # set TLS version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::"$TLSVersion"

    # build URI for use to access machine catalog
    [System.UriBuilder]$URI = ('https://{0}/cvad/manage/DeliveryGroups/{1}/Machines/{2}' -f $CloudURI,$DeliveryGroupNameOrID,$MachineNameOrID)

    # configure async query value
    $Query = [System.Web.HttpUtility]::ParseQueryString('')
    $Query.Add('async',$async.tostring())
    $URI.Query = $Query.ToString()

    $body = @{
        AssignedMachinesToUsers = @(@{Machine = $MachineNameOrID})
        MachineCatalog          = $CatalogNameOrID
        Count                   = $MachineNameOrID.Count
    }

    $parameters = @{
        Method      = 'POST'
        Headers     = $headers
        ContentType = 'applicaiton/json'
        URI         = $uri.Uri
        Erroraction = 'silentlyContinue'
        Body        = ($body | ConvertTo-Json)
    }

    $response = Invoke-RestMethod @Parameters

    if ($Response) {
        return $repsponse
    }
}

function Remove-CitrixDeliveryGroupMachine {
    Param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,
        [Parameter(Mandatory=$true)]
        [string]$MachineNameOrID,
        [Parameter(Mandatory=$true)]
        [string]$DeliveryGroupNameOrId,
        [string]$CloudURI = "api-us.cloud.com",
        [ValidateScript(
            {$_ -in ([enum]::GetNames([net.securityprotocoltype]))},
            ErrorMessage = 'ERROR: TLS version must be supported on system (run [enum]::GetNames([net.securityprotocoltype]) for a valid list)'
        )]
        [string]$TLSVersion = 'Tls12',
        [switch]$async
    )

    # set TLS version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::"$TLSVersion"

    # build URI for use to access machine catalog
    [System.UriBuilder]$URI = ('https://{0}/cvad/manage/DeliveryGroups/{1}/Machines/{2}' -f $CloudURI,$DeliveryGroupNameOrId,$MachineNameOrId)

    # configure async query value
    $Query = [System.Web.HttpUtility]::ParseQueryString('')
    $Query.Add('async',$async.tostring())
    $URI.Query = $Query.ToString()

    $parameters = @{
        Method      = 'DELETE'
        ContentType = 'application/json'
        UserAgent   = 'Mozilla/5.0'
        ErrorAction = 'silentlyContinue'
        Uri         = $URI.Uri
        Headers     = $Headers
    }

    Invoke-RestMethod @parameters
}

<#
.SYNOPSIS

.DESCRIPTION

.EXAMPLE

.PARAMETER Headers

.PARAMETER CloudURI

.PARAMETER HypervisorNameOrID

.PARAMETER Children

.PARAMETER TLSVersion

.PARAMETER
#>
function Get-CitrixHypervisorResources {
    Param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,
        [string]$CloudURI = "api-us.cloud.com",
        [string]$HypervisorNameOrID,
        [ValidateScript(
            {$_ -in ([enum]::GetNames([net.securityprotocoltype]))},
            ErrorMessage = 'ERROR: TLS version must be supported on system (run [enum]::GetNames([net.securityprotocoltype]) for a valid list)'
        )]
        [string]$TLSVersion = 'Tls12',
        [switch]$async
    )

    [System.UriBuilder]$URI = ('https://{0}/cvad/manage/hypervisors/{1}/allResources' -f $CloudURI,$HypervisorNameOrID)

    $Query = [System.Web.HttpUtility]::ParseQueryString('')
    $Query.Add('async',$async.tostring())
    $Query.Add('children',$children)

    $URI.Query = $Query.ToString()

    $parameters = @{
        Method      = 'GET'
        URI         = $URI.Uri
        Header      = $Headers
        ErrorAction = 'SilentlyContinue'
    }

    $result = Invoke-RestMethod @Parameters

    if ($result) {
        return $result
    }
}