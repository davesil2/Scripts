# Get PowerBI Events
<#
.SYNOPSIS
This function assists in obtaining the Bearer token when using a clientid and secret for a tenant
.DESCRIPTION
Specific to PowerBI context/scope, this function helps to obtain a Bearer token for use in headers for calls to the PowerBI API
.PARAMETER tenantid
The tenantid is required.  This can be found in the Entra portal overview home page
.PARAMETER ClientID
The ClientID is the Application/ObjectID of the Application Registration created to have access to the PowerBI environment
.PARAMETER ClientSecret
The ClientSecret is a pass phrase assigned to the ClientID.
.EXAMPLE
$TenantID = 'c2a99db9-4869-4713-a89c-927114fa8ddf'
$ClientID = 'bb646feb-6c90-4e26-9860-6983dd53da97'
$ClientSecret = '<some auto generated password from entra app registration>'

$Token = Get-PowerBIAuthToken -TenandID $TenandID -ClientID $ClientID -ClientSecret $ClientSecret

##NOTE: The token return includes multiple values (expires_in, expires_on, resource, etc.).  The primary value to use is the "access_token" value in the table.

#>
function Get-PowerBIAuthToken {
    Param(
        [Parameter(Mandatory=$true)]
        $TenantID,
        [Parameter(Mandatory=$true)]
        $ClientID,
        [Parameter(Mandatory=$true)]
        $ClientSecret
    )

    [System.UriBuilder]$URI = ('https://login.microsoftonline.com/{0}/oauth2/token' -f $tenantid)

    $Body = @{
        client_id       = $ClientID
        client_secret   = $ClientSecret
        resource        = 'https://analysis.windows.net/powerbi/api'
        scope           = 'https://analysis.windows.net/powerbi/api/.default'
        grant_type      = 'client_credentials'
    }

    $paramters = @{
        URI         = $URI.Uri
        Method      = 'Post'
        Body        = $Body
        ContentType = 'application/x-www-form-urlencoded'
        ErrorAction = 'silentlyContinue'
    }

    $response = Invoke-RestMethod @paramters

    if ($response) {
        return $response
    }
}

<#
.SYNOPSIS
This function allows you to use the REST API to obtain PowerBI Activity Events
.DESCRIPTION
Using native PowerShell libraries (no dependency on windows libraries) calling the Rest API for PowerBI Activity Events.  This does require an access token for authorization
.PARAMETER AccessToken
Required Bearer token to access the REST API interface
.PARAMETER StartDate
Optional value for the start point of logging data to identify the year, month and date in [DateTime] format.  Time data is ignored.
.PARAMETER endDate
Optional value for the end point of logging data to identify the year, month and date in [DateTime] format.  Time data is ignored.
.EXAMPLE
$Token = Get-PowerBIAuthToken -TenantID '<tenant id>' -ClientID '<app object id>' -ClientSecret '<pass phrase>'
Get-PowerBIActivityEvents -AccessToken $Token.Access_token
#>
function Get-PowerBIActivityEvents {
    Param (
        [Parameter(Mandatory=$true)]
        [String]$AccessToken,
        [datetime]$StartDate = (Get-Date),
        [datetime]$EndDate = (Get-Date)
    )

    [uribuilder]$URI = ("https://api.powerbi.com/v1.0/myorg/admin/activityevents?startDateTime='{0}T00:00:00Z'&endDateTime='{0}T23:59:59Z'" -f $StartDate.ToString('yyyy-MM-dd'),$endDate.ToString('yyyy-MM-dd'))

    $headers = @{
        Authorization   = ('Bearer {0}' -f $AccessToken.Trim())
        contentType     = 'application/json'
        Accept          = ''
    }

    $parameters = @{
        Method      = 'Get'
        Uri         = $uri.Uri
        Headers     = $headers
    }

    $response = Invoke-RestMethod @parameters

    $Output = @()
    $Output += $Response.activityEventEntities

    While ($response.continuationuri -and $response.activityEventEntities.count -gt 0) {
        $parameters['Uri'] = $response.continuationUri
        $response = Invoke-RestMethod @parameters
        $Output += $response.activityEventEntities
    }

    if ($Output) {
        return $Output
    }
}

$Token = Get-PowerBIAuthToken -tenantid $env:BerlinTenantId -ClientID $env:PowerBIClientID -ClientSecret $env:PowerBIClientSecret
$Results = Get-PowerBIActivityEvents -AccessToken $Token.access_token

$results