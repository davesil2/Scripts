<#
.SYNOPSIS

Provides output of Users from BambooHR REST API

.DESCRIPTION

Using BambooHR's provide developer API, this function allows a quick query against the specific BambooHR Domain when used with the API Key.  The function allows customization of output based on desired results

.PARAMETER CompanyDomain

This is the domain provided by BambooHR for your unique instance. Typically this would be the company name in the first part of the url <company>.bamboohr.com

.PARAMETER OnlyCurrent

This parameter will ensure only current users are returned in the output.

.PARAMETER Fields

This is an array list of the fields that should be returned as part of the query.  The default list includes:

    "firstname",
    "lastname",
    "id",
    "employeenumber",
    "preferredname",
    "customPreferredLastName",
    "workemail",
    "employmentHistoryStatus",
    "jobtitle",
    "supervisoremail",
    "department",
    "division",
    "manager",
    "location",
    "hiredate",
    "workPhone",
    "mobilePhone",
    "country",
    "customBusinessUnitCode",
    "status",
    "customPositionID",
    "customFunction",
    "Exempt",
    "terminationDate"

BambooHR provides a list of valid values - https://documentation.bamboohr.com/docs/list-of-field-names

.PARAMETER APIKey

This is the API Key generated under the user account or in the admin portal for access to data.

.EXAMPLE

Get-BambooHRUsers -CompanyDomain companydomain -APIKey 123456678900

# Returns the users from the BambooHR company company.bamboohr.com with the APIKey

#>
function Get-BambooHRUsers {
    Param(
        [Parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true
        )]
        [Alias("Domain")]
        [string]$CompanyDomain,
        [switch]$OnlyCurrent,
        [string[]]$Fields = ("firstname","lastname","id","employeenumber","preferredname","customPreferredLastName","workemail","employmentHistoryStatus","jobtitle","supervisoremail","department","division","manager","location","hiredate","workPhone","mobilePhone","country","customBusinessUnitCode","status","customPositionID","customFunction","Exempt","terminationDate"),
        [Parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true
        )]
        [string]$APIKey
    )

    # Build URL String
    [System.UriBuilder]$URI = ("https://api.bamboohr.com/api/gateway.php/{0}/v1/reports/custom?format=csv&onlyCurrent={1}" -f $CompanyDomain,$OnlyCurrent.IsPresent.ToString().tolower())

    # Build body for fields to return
    $Body = [pscustomobject]@{fields=$fields} | ConvertTo-Json

    # build header information
    $Headers = @{
        "content-type"  = "application/json"
        "authorization" = ("Basic {0}" -f [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($APIKey)`:x")))
    }

    # build web request
    $Splat = @{
        Uri         = $URI.uri
        Method      = 'Post'
        Headers     = $Headers
        ContentType = 'application/json'
        Body        = $Body
        Verbose     = $false
    }

    # execute web request
    $response = Invoke-RestMethod @Splat -ErrorAction SilentlyContinue

    if ($response) {
        Return ($response | ConvertFrom-Csv)
    } else {
        throw 'Either no results returned or access denied!'
    }
}

<#
.SYNOPSIS
This function uses BambooHR API to retrieve the users thumbnail photo profile picture.

.DESCRIPTION

.EXAMPLE

Get-BambooHRUserPhoto -CompanyDomain "domain" -APIKey "012345678900" -EmployeeID '3391'

# Returns the user photo thumbnail from the BambooHR company company.bamboohr.com with the APIKey

.PARAMETER CompanyDomain

This is the domain provided by BambooHR for your unique instance. Typically this would be the company name in the first part of the url <company>.bamboohr.com

.PARAMETER EmployeeID

this parameter should provide the EmployeeID or EEID of a single user

.PARAMETER APIKey

This is the API Key generated under the user account or in the admin portal for access to data.

#>
function Get-BambooHRUserPhoto {
    Param(
        [parameter(Mandatory=$true)]
        [Alias("Domain")]
        [String]$CompanyDomain,
        [Alias("EEID")]
        [String]$EmployeeID,
        [String]$APIKey
    )

    # Build URL String
    [System.UriBuilder]$URI = ("https://api.bamboohr.com/api/gateway.php/{0}/v1/employees/{1}/photo/small" -f $CompanyDomain,$EmployeeID)

    # build header information
    $Headers = @{
        'content-type'  = 'application/json'
        'authorization' = ("Basic {0}" -f [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($APIKey)`:x")))
    }

    # build web request
    $Splat = @{
        ErrorAction     = 'SilentlyContinue'
        Method          = 'Get'
        Uri             = $URI.Uri
        Headers         = $Headers
    }

    # execute web request
    try {
        $response = Invoke-WebRequest @Splat
    } catch {}
    
    # return content if it exists
    if ($response.Content) {
        return @{PhotoThumbprint = $response.Content}
    } else {
        throw 'Either no results returned or access denied'
    }
}

<#
.SYNOPSIS

This function retrieves the list of fields, their alias and type from BambooHR

.DESCRIPTION

.EXAMPLE

Get-BambooHRFieldsList -CompanyDomain "companydomain" -APIKey "1234123454325432"

# Returns fields and alias from the BambooHR instance

.PARAMETER CompanyDomain

This is the domain provided by BambooHR for your unique instance. Typically this would be the company name in the first part of the url <company>.bamboohr.com

.PARAMETER APIKey

This is the API Key generated under the user account or in the admin portal for access to data.

#>
function Get-BambooHRFieldsList {
    param(
        [parameter(Mandatory=$true)]
        [Alias("Domain")]
        [string]$CompanyDomain,
        [string]$APIKey
    )

    # Build URL String
    [system.Uribuilder]$URI = ('https://{0}.bamboohr.com/api/v1/meta/tables' -f $CompanyDomain)

    # build header information
    $Headers = @{
        accept          = 'application/json'
        'content-type'  = 'application/json'
        'authorization' = ("Basic {0}" -f [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($APIKey)`:x")))
    }

    # build web request
    $Splat = @{
        ErrorAction     = 'SilentlyContinue'
        Method          = 'Get'
        Uri             = $URI.Uri
        Headers         = $Headers
    }

    # execute web request
    try {
        $response = Invoke-WebRequest @Splat
    } catch {}
    
    # return content if it exists
    if ($response.Content) {
        return ($response.Content | ConvertFrom-Json)
    } else {
        throw 'Either no results returned or access denied'
    }
}