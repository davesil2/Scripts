
function Connect-CitrixRESTAPI {
    <#
    .SYNOPSIS
    Initialize connection to Citrix Cloud and obtain headers for API calls.

    .DESCRIPTION
    Requests an OAuth client credentials token from Citrix Cloud and returns
    a headers hashtable suitable for subsequent CVAD management API calls.

    .PARAMETER CloudURI
    CloudURI is the URI that will be use for the FQDN of the call the citrix cloud.

        DEFAULT: api.cloud.com

        https://developer-docs.citrix.com/en-us/citrix-cloud/citrix-cloud-api-overview/get-started-with-citrix-cloud-apis

    .PARAMETER ClientID
    OAuth client ID / service principal identifier.

    .PARAMETER ClientSecret
    OAuth client secret for the client ID. Protect this value.

    .PARAMETER CustomerID
    Citrix CustomerID (tenant ID) used in Citrix Cloud API requests.

    .PARAMETER TLSVersion
    TLS protocol to use for HTTPS requests (default: Tls12).

    .EXAMPLE
    Calling the function with the specifice ClientID, ClientSecret and CustomerID will return headers to be used in future function calls

    $Headers = Connect-CitrixRESTAPI `
        -ClientID       'abdf26c6-39b1-41cf-af29-b3dfc08c1580' `
        -ClientSecret   'asdf943sadfj342ad==' `
        -CustomerID     'u9tviazeowms'

    #>
    Param(
        [string]$CloudURI = 'api.cloud.com',
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
    <#
    .SYNOPSIS
    Get-CitrixHypervisors - Retrieve hypervisor definitions from CVAD management API.

    .DESCRIPTION
    Returns one or more hypervisors. If a name or ID is supplied the specific
    hypervisor will be returned. Supports async queries for long-running calls.

    .PARAMETER Headers
    A headers hashtable produced by `Connect-CitrixRESTAPI` containing Authorization and CustomerID.

    .PARAMETER HypervisorNameOrID
    Optional hypervisor name or ID to retrieve a single entry.

    .PARAMETER CloudURI
    FQDN for Citrix Cloud API (default: api.cloud.com).

    .PARAMETER TLSVersion
    TLS protocol to use for HTTPS requests (default: Tls12).

    .EXAMPLE
    $headers = Connect-CitrixRESTAPI -ClientID 'abdf26c6-39b1-41cf-af29-b3dfc08c1580' `
        -ClientSecret 'asdf943sadfj342ad==' `     
        -CustomerID 'u9tviazeowms'

    Get-CitrixHypervisors -Headers $Headers

    #>
    Param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,
        [String]$HypervisorNameOrID,
        [string]$CloudURI = "api.cloud.com",
        [ValidateScript(
            {$_ -in ([enum]::GetNames([net.securityprotocoltype]))},
            ErrorMessage = 'ERROR: TLS version must be supported on system (run [enum]::GetNames([net.securityprotocoltype]) for a valid list)'
        )]
        [string]$TLSVersion = 'Tls12'
    )

    # set TLS version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::"$TLSVersion"

    # build URI for use to access machine catalog
    [System.UriBuilder]$URI = ('https://{0}/cvad/manage/hypervisors' -f $CloudURI)

    if ($HypervisorNameOrID) {
        $URI.Path += ('/{0}' -f $HypervisorNameOrID.Replace('\','|'))
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

    $response = Invoke-RestMethod @parameters

    if ($response) {
        return $response.Items
    } else {
        throw "ERROR: no data received, check headers"
    }
}

function Get-CitrixMachines {
    <#
    .SYNOPSIS
    Get-CitrixMachines - Retrieve machines from CVAD management API.

    .DESCRIPTION
    Returns machine objects from the CVAD `Machines` endpoint. Handles continuation
    tokens for paging when multiple pages of machines are returned.

    For multiple machines - docmentation for api call below
    https://developer-docs.citrix.com/en-us/citrix-daas-service-apis/citrix-daas-rest-apis/apis/#/Machines-APIs/Machines-GetMachines

    For single machine - documentation for api call below
    https://developer-docs.citrix.com/en-us/citrix-daas-service-apis/citrix-daas-rest-apis/apis/#/Machines-APIs/Machines-GetMachine

    .PARAMETER Headers
    Headers hashtable from `Connect-CitrixRESTAPI`.

    .PARAMETER MachineNameOrID
    Optional machine name or ID to fetch a single machine.

    .PARAMETER limit
    Maximum number of items to request per page (when supported by API).

    .PARAMETER CloudURI
    FQDN for Citrix Cloud API (default: api.cloud.com).

    .PARAMETER TLSVersion
    TLS protocol to use for HTTPS requests (default: Tls12).  [enum]::GetNames([net.securityprotocoltype]) for valid options.

    .EXAMPLE
    $headers = Connect-CitrixRESTAPI `
    -ClientID 'abdf26c6-39b1-41cf-af29-b3dfc08c1580' `
        -ClientSecret 'asdf943sadfj342ad==' `  
        -CustomerID 'u9tviazeowms'

    Get-CitrixMachines -Headers $Headers

    .EXAMPLE
    $headers = Connect-CitrixRESTAPI `
        -ClientID 'abdf26c6-39b1-41cf-af29-b3dfc08c1580' `
        -ClientSecret 'asdf943sadfj342ad==' `  
        -CustomerID 'u9tviazeowms'

    Get-CitrixMachines -Headers $Headers -MachineNameOrID 'domain\machine01'

    #>
    Param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,
        [Parameter(Mandatory=$false)]
        [string]$MachineNameOrID,
        [Validateset('SingleSession','MultiSession')]
        [string]$SessionSupport,
        [boolean]$Configured,
        [string[]]$Fields,
        [ValidateRange(1,1000)]
        [int]$limit = 249,
        [string]$CloudURI = "api.cloud.com",
        [ValidateScript(
            {$_ -in ([enum]::GetNames([net.securityprotocoltype]))},
            ErrorMessage = 'ERROR: TLS version must be supported on system (run [enum]::GetNames([net.securityprotocoltype]) for a valid list)'
        )]
        [string]$TLSVersion = 'Tls12'
    )

    # set TLS version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::"$TLSVersion"

    # build URI for use to access machine catalog
    [System.UriBuilder]$URI = ('https://{0}/cvad/manage/Machines' -f $CloudURI)

    $Query = [System.Web.HttpUtility]::ParseQueryString('')

    if ($MachineNameOrID) {
        $URI.Path += ('/{0}' -f $MachineNameOrID.Replace('\','|'))
    } else {    
        if ($configured) { 
            $query.Add('configured', $configured)
        }
        if ($sessionSupport) {
            $query.Add('sessionSupport', $sessionSupport)
        }
        if ($limit) {
            $query.Add('limit', $limit)
        }
    }
    if ($fields) {
        $query.Add('fields', ($fields -join ','))
    }
    if ($query.ToString()) {
        $URI.Query = $query.ToString()
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

    $MachineList = @()
    While ($parameters.Uri){
        $response = Invoke-RestMethod @parameters

        if ($Response.Items) {
            $MachineList += $Response.Items
        }
        if ($MachineNameOrID -and $Response) {
            # if a specific machine was requested and a response is received, return the response (even if continuation token is present, as it would be unexpected in this scenario)
            $MachineList += $response
        }
        if ($response.continuationToken) {
            $Query = [System.Web.HttpUtility]::ParseQueryString($uri.Query)
            $Query.Add('continuationToken', $response.continuationToken)
            $parameters.Uri = $URI.Uri
        } else {
            $parameters.Uri = $null
        }
    }

    if ($MachineList) {
        return $MachineList
    } else {
        throw "[ERROR] - no data received, check headers"
    }
}

function Remove-CitrixMachine {
    <#
    .SYNOPSIS
    Remove-CitrixMachine - Delete a machine from CVAD.

    .DESCRIPTION
    Deletes the specified machine by name or ID using the CVAD `Machines` DELETE endpoint.

    .PARAMETER Headers
    Headers hashtable from `Connect-CitrixRESTAPI`.

    .PARAMETER MachineNameOrID
    Machine name or ID to delete.

    .PARAMETER CloudURI
    FQDN for Citrix Cloud API.
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,

        [Parameter(Mandatory=$True)]
        [string]$MachineNameOrID,

        [string]$CloudURI = "api.cloud.com",

        [ValidateScript(
            {$_ -in ([enum]::GetNames([net.securityprotocoltype]))},
            ErrorMessage = 'ERROR: TLS version must be supported on system (run [enum]::GetNames([net.securityprotocoltype]) for a valid list)'
        )]
        [string]$TLSVersion = 'Tls12'
    )

    # set TLS version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::"$TLSVersion"

    # build URI for use to access machine catalog
    [System.UriBuilder]$URI = ('https://{0}/cvad/manage/Machines/{1}' -f $CloudURI,$MachineNameOrID.Replace('\','|'))
    
    # build parameters for splat into invoke-restmethod
    $parameters = @{
        Method      = 'DELETE'
        ContentType = 'application/json'
        UserAgent   = 'Mozilla/5.0'
        ErrorAction = 'silentlyContinue'
        Uri         = $URI.Uri.ToString()
        Headers     = $Headers
    }

    $response = Invoke-RestMethod @parameters

    if ($response) {
        return $false
    } else {
        return $true
    }
}

function Get-CitrixMachineCatalogs {
    <#
    .SYNOPSIS
    Get-CitrixMachineCatalogs - List machine catalogs in CVAD.

    .DESCRIPTION
    Retrieves Machine Catalogs via the CVAD management API and returns the
    collection of catalogs for the tenant.

    .PARAMETER CloudURI
    FQDN for Citrix Cloud API.

    .PARAMETER Headers
    Headers hashtable from `Connect-CitrixRESTAPI`.
    #>
    Param(
        [string]$CloudURI = 'api.cloud.com',
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
    $response = Invoke-RestMethod @parameters

    if ($response) {
        # return list of machine catalogs if the return is valid
        return $response.items
    } else {
        # throw an error if no output is created
        throw 'ERROR: no response recieved, check header output, credentials and customerid'
    }
}

function Add-CitrixMachineCatalogMachine {
    <#
    .SYNOPSIS
    Add-CitrixMachineCatalogMachine - Add a machine to a machine catalog.

    .DESCRIPTION
    Adds an existing VM/computer to a Machine Catalog. Requires the hosted machine
    ID and hypervisor connection name for placement.

    .PARAMETER CatalogNameOrID
    Target machine catalog name or unique ID.

    .PARAMETER MachineNameOrID
    Domain computer name or SID for the machine to add.

    .PARAMETER HostedMachineID
    Provider/Hypervisor unique ID for the VM.

    .PARAMETER HypervisorConnection
    Name of the hypervisor connection to use.

    .PARAMETER AssignedUsers
    Array of users to assign to the machine (if applicable).
    #>
    Param(
        [string]$CloudURI = 'api.cloud.com',
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

    $response = Invoke-RestMethod @parameters

    if ($response) {
        return $response
    }
}

function Remove-CitrixMachineCatalogMachine {
    <#
    .SYNOPSIS
    Remove-CitrixMachineCatalogMachine - Remove a machine from a machine catalog.

    .DESCRIPTION
    Deletes a machine entry from a Machine Catalog using the CVAD management API.

    .PARAMETER MachineCatalogNameOrID
    Catalog name or ID containing the machine.

    .PARAMETER MachineNameOrID
    Machine name or ID to remove from the catalog.
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [String]$MachineCatalogNameOrID,
        [Parameter(Mandatory=$true)]
        [String]$MachineNameOrID,
        [string]$CloudURI = 'api.cloud.com',
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
    if ($async) {
        $Query.Add('async',$async.tostring())
    }
    if ($query.ToString()) {
        $URI.Query = $Query.ToString()
    }

    $Parameters = @{
        Method      = 'DELETE'
        URI         = $URI.Uri
        Headers     = $Headers
        ContentType = 'application/json'
        UserAgent   = 'Mozilla/5.0'
        ErrorAction = 'silentlyContinue'
    }

    $response = Invoke-RestMethod @Parameters

    if ($response) {
        return $response
    } else {
        throw '[ERROR] - '
    }
}

function Get-CitrixDeliveryGroups {
    <#
    .SYNOPSIS
    Get-CitrixDeliveryGroups - Retrieve delivery groups for the tenant.

    .DESCRIPTION
    Returns delivery groups (collections of machines and published resources) from
    the CVAD management API. Supports async queries.

    .PARAMETER Headers
    Headers hashtable from `Connect-CitrixRESTAPI`.

    .PARAMETER CloudURI
    FQDN for Citrix Cloud API (default: api.cloud.com).
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,
        [string]$CloudURI = "api.cloud.com",
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
    
    if ($async) {
        $URI.Query = ([System.Web.HttpUtility]::ParseQueryString('')['async'] = $async.tostring())
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

    $response = Invoke-RestMethod @parameters

    if ($response) {
        return $response.Items
    } else {
        throw "ERROR: no data received, check headers"
    }
}

function Add-CitrixDeliveryGroupMachine {
    <#
    .SYNOPSIS
    Add-CitrixDeliveryGroupMachine - Add machine(s) to a delivery group.

    .DESCRIPTION
    Assign machines from a machine catalog to a Delivery Group. Supports control
    over whether a detailed response is required and asynchronous processing.

    .PARAMETER DeliveryGroupNameOrID
    Target delivery group name or unique ID.

    .PARAMETER MachineNameOrID
    Machine name(s) or ID(s) to assign to the delivery group.

    .PARAMETER CatalogNameOrID
    Machine catalog name or ID containing the machines.
    #>
    Param(
        [String]$CloudURI = 'api.cloud.com',    
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
        [switch]$DetailResponseRequired,
        [switch]$async
    )

    # set TLS version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::"$TLSVersion"

    # build URI for use to access machine catalog
    [System.UriBuilder]$URI = ('https://{0}/cvad/manage/DeliveryGroups/{1}/Machines' -f $CloudURI,$DeliveryGroupNameOrID)

    # configure async query value
    $Query = [System.Web.HttpUtility]::ParseQueryString('')
    if ($Async) {
        $Query.Add('async',$async.tostring())
    }
    if ($detailResponseRequired) {
        $Query.Add('detailResponseRequired',$DetailResponseRequired.ToString())
    }
    if ($query.ToString()) {
        $URI.Query = $Query.ToString()
    }

    $body = @{
        AssignedMachinesToUsers = @(@{Machine = $MachineNameOrID})
        MachineCatalog          = $CatalogNameOrID
        Count                   = $MachineNameOrID.Count
    }

    $parameters = @{
        Method      = 'POST'
        Headers     = $headers
        ContentType = 'application/json'
        URI         = $uri.Uri
        Erroraction = 'silentlyContinue'
        Body        = ($body | ConvertTo-Json -Depth 10)
    }

    Write-Verbose ('[INFO] - URL used is [{0}]' -f $URI.Uri)

    $response = Invoke-RestMethod @Parameters

    if ($Response) {
        return $response
    }
}

function Remove-CitrixDeliveryGroupMachine {
    <#
    .SYNOPSIS
    Remove-CitrixDeliveryGroupMachine - Remove a machine from a delivery group.

    .DESCRIPTION
    Deletes the specified machine from a Delivery Group via the CVAD management API.

    .PARAMETER Headers
    Headers hashtable from `Connect-CitrixRESTAPI`.

    .PARAMETER MachineNameOrID
    Machine name or ID to remove.

    .PARAMETER DeliveryGroupNameOrId
    Delivery group name or ID.
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,
        [Parameter(Mandatory=$true)]
        [string]$MachineNameOrID,
        [Parameter(Mandatory=$true)]
        [string]$DeliveryGroupNameOrId,
        [string]$CloudURI = "api.cloud.com",
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
    [System.UriBuilder]$URI = ('https://{0}/cvad/manage/DeliveryGroups/{1}/Machines/{2}' -f $CloudURI,$DeliveryGroupNameOrId,$MachineNameOrID)

    # configure async query value
    if ($async) {
        $Query = [System.Web.HttpUtility]::ParseQueryString('')
        $Query.Add('async',$async.tostring())
        $URI.Query = $Query.ToString()
    }
    
    $parameters = @{
        Method      = 'DELETE'
        ContentType = 'application/json'
        UserAgent   = 'Mozilla/5.0'
        ErrorAction = 'silentlyContinue'
        Uri         = $URI.Uri.ToString()
        Headers     = $Headers
    }

    try {
        Invoke-RestMethod @parameters
        return $true
    } catch {
        throw ("error occured: {0}" -f $error.exception)
    }
}

function Get-CitrixDeliveryGroupMachines {
    <#
    .SYNOPSIS
    Get-CitrixDeliveryGroupMachines - List machines assigned to a delivery group.

    .DESCRIPTION
    Retrieves machines associated with a Delivery Group. Supports limit and async
    options and will return paged results when supported by the API.

    .PARAMETER DeliveryGroupNameOrID
    Delivery group name or ID to list machines for.

    .PARAMETER Headers
    Headers hashtable from `Connect-CitrixRESTAPI`.
    #>
    param(
        [String]$CloudURI = 'api.cloud.com',    
        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,    
        [Parameter(Mandatory=$true)]
        [String]$DeliveryGroupNameOrID,    
        [ValidateScript(
            {$_ -in ([enum]::GetNames([net.securityprotocoltype]))},
            ErrorMessage = 'ERROR: TLS version must be supported on system (run [enum]::GetNames([net.securityprotocoltype]) for a valid list)'
        )]
        [string]$TLSVersion = 'Tls12',
        [int]$limit,
        [switch]$async
    )

    # set TLS version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::"$TLSVersion"

    # build URI for use to access machine catalog
    [System.UriBuilder]$URI = ('https://{0}/cvad/manage/DeliveryGroups/{1}/Machines' -f $CloudURI,$DeliveryGroupNameOrID)

    # configure async query value
    $Query = [System.Web.HttpUtility]::ParseQueryString('')
    if ($async) {
        $Query.Add('async',$async.tostring())
    }
    if ($limit) {
        $Query.Add('limit',$limit)
    }
    if ($query.ToString()){
        $URI.Query = $Query.ToString()
    }
    
    $parameters = @{
        Method      = 'GET'
        Headers     = $headers
        ContentType = 'application/json'
        URI         = $uri.Uri.tostring()
        Erroraction = 'silentlyContinue'
    }

    Write-Verbose ('[INFO] - URL used is [{0}]' -f $URI.Uri)

    $response = Invoke-RestMethod @Parameters

    if ($Response) {
        return $Response.items
    }
}

function Get-CitrixHypervisorResources {
    <#
    .SYNOPSIS
    Get-CitrixHypervisorResources - Retrieve resources for a hypervisor.

    .DESCRIPTION
    Returns resources under a hypervisor (hosts, VMs, datastores, etc.) and may
    accept a `children` parameter to include nested resources.

    .PARAMETER Headers
    Headers hashtable from `Connect-CitrixRESTAPI`.

    .PARAMETER HypervisorNameOrID
    Hypervisor name or ID to query.

    .PARAMETER children
    Number of children levels to include (provider-specific semantics).
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,
        [string]$CloudURI = "api.cloud.com",
        [string]$HypervisorNameOrID,
        [String]$children = 0,
        [ValidateScript(
            {$_ -in ([enum]::GetNames([net.securityprotocoltype]))},
            ErrorMessage = 'ERROR: TLS version must be supported on system (run [enum]::GetNames([net.securityprotocoltype]) for a valid list)'
        )]
        [string]$TLSVersion = 'Tls12',
        [switch]$async
    )

    [System.UriBuilder]$URI = ('https://{0}/cvad/manage/hypervisors/{1}/allResources' -f $CloudURI,$HypervisorNameOrID)

    $Query = [System.Web.HttpUtility]::ParseQueryString('')
    if ($async) {
        $Query.Add('async',$async.tostring())
    }
    $Query.Add('children',$children)

    $URI.Query = $Query.ToString()

    $parameters = @{
        Method      = 'GET'
        URI         = $URI.Uri
        Header      = $Headers
        ErrorAction = 'SilentlyContinue'
    }

    $response = Invoke-RestMethod @Parameters

    if ($response) {
        return $response
    }
}