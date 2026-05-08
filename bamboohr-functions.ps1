<#
.SYNOPSIS
Retrieves BambooHR employee records using the BambooHR custom reports API.

.DESCRIPTION
Uses BambooHR's REST API to request a custom report in CSV format and returns parsed user records. The function supports a default set of fields and optional filtering for current employees only.

.PARAMETER CompanyDomain
The BambooHR company domain for your instance, e.g. the first part of <company>.bamboohr.com.

.PARAMETER OnlyCurrent
Switch to return only active/current employees.

.PARAMETER Fields
An array of BambooHR field names to include in the report. The default values include the most common user profile fields.

.PARAMETER APIKey
The BambooHR API key used for Basic authentication. The API key is encoded and sent as the request username with a placeholder password.

.EXAMPLE
Get-BambooHRUsers -CompanyDomain "companydomain" -APIKey "123456678900"

.EXAMPLE
Get-BambooHRUsers -CompanyDomain "companydomain" -APIKey "123456678900" -OnlyCurrent

.NOTES
Requires BambooHR API access and valid field names for the custom report.
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
Retrieves the small profile photo thumbnail for a BambooHR employee.

.DESCRIPTION
Calls the BambooHR employee photo endpoint and returns the photo content from the small thumbnail image.

.PARAMETER CompanyDomain
The BambooHR company domain for your instance, e.g. <company>.bamboohr.com.

.PARAMETER EmployeeID
The BambooHR employee ID (EEID) for the user whose photo should be retrieved.

.PARAMETER APIKey
The BambooHR API key used for Basic authentication.

.EXAMPLE
Get-BambooHRUserPhoto -CompanyDomain "domain" -APIKey "012345678900" -EmployeeID "3391"

.NOTES
This function returns a hashtable containing the photo content under the PhotoThumbprint key.
#>
function Get-BambooHRUserPhoto {
    Param(
        [parameter(Mandatory=$true)]
        [Alias("Domain")]
        [String]$CompanyDomain,
        [parameter(Mandatory=$true)]
        [Alias("EEID")]
        [String]$EmployeeID,
        [parameter(Mandatory=$true)]
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
Retrieves BambooHR metadata tables and field definitions.

.DESCRIPTION
Uses the BambooHR metadata API to return tables and field definitions for the specified company domain.

.PARAMETER CompanyDomain
The BambooHR company domain for your instance, e.g. <company>.bamboohr.com.

.PARAMETER APIKey
The BambooHR API key used for Basic authentication.

.EXAMPLE
Get-BambooHRTablesList -CompanyDomain "companydomain" -APIKey "1234123454325432"

.NOTES
This function returns metadata for BambooHR tables and fields.
#>
function Get-BambooHRTablesList {
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

<#
.SYNOPSIS
Retrieves the list of available BambooHR fields for the company.

.DESCRIPTION
Uses the BambooHR metadata API to return field definitions that can be used in custom reports and API queries.

.PARAMETER CompanyDomain
The BambooHR company domain for your instance, e.g. <company>.bamboohr.com.

.PARAMETER APIKey
The BambooHR API key used for Basic authentication.

.EXAMPLE
Get-BambooHRFieldsList -CompanyDomain "companydomain" -APIKey "1234123454325432"

.NOTES
Field names returned by this function can be used in the Fields parameter of Get-BambooHRUsers.
#>
function Get-BambooHRFieldsList {
    param(
        [parameter(Mandatory=$true)]
        [Alias("Domain")]
        [string]$CompanyDomain,
        [parameter(Mandatory=$true)]
        [string]$APIKey
    )

    # Build URL String
    [system.Uribuilder]$URI = ('https://{0}.bamboohr.com/api/v1/meta/fields' -f $CompanyDomain)

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