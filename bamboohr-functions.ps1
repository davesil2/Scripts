function Get-BambooHRUsers {
    <#
    .SYNOPSIS
    Retrieves BambooHR employee records using the BambooHR custom reports API.

    .DESCRIPTION
    Uses BambooHR's REST API to request a custom report in CSV format and returns parsed user records.
    The function supports a default set of fields and optional filtering for current employees only.

    REFERENCE: https://documentation.bamboohr.com/reference/request-custom-report

    .PARAMETER CompanyDomain
    The BambooHR company domain for your instance, e.g. the first part of <company>.bamboohr.com.

    .PARAMETER OnlyCurrent
    Switch to return only active/current employees.

    .PARAMETER Fields
    An array of BambooHR field names to include in the report. This defaults to a common set of profile fields.

    .PARAMETER APIKey
    The BambooHR API key used for Basic authentication.

    .EXAMPLE
    Get-BambooHRUsers -CompanyDomain "companydomain" -APIKey "123456678900"

    .EXAMPLE
    Get-BambooHRUsers -CompanyDomain "companydomain" -APIKey "123456678900" -OnlyCurrent

    .NOTES
    Requires BambooHR API access and valid field names for the custom report.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias("Domain")]
        [string]$CompanyDomain,

        [switch]$OnlyCurrent,

        [string[]]$Fields = (
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
        ),

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$APIKey
    )

    # Build the request URI for the BambooHR custom report endpoint.
    # Note: the custom reports API returns CSV when requested via `format=csv`.
    [System.UriBuilder]$URI = ("https://{0}.bamboohr.com/api/v1/reports/custom?format=csv&onlyCurrent={1}" -f $CompanyDomain, $OnlyCurrent.IsPresent.ToString().ToLower())

    # Build the JSON body containing the requested fields. BambooHR expects
    # the `fields` array in the request body for custom report requests.
    $Body = @{ fields = $Fields } | ConvertTo-Json

    # Basic auth header using API key as username with an 'x' password.
    $Headers = @{
        'Content-Type'  = 'application/json'
        'Authorization' = ("Basic {0}" -f [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($APIKey)`:x")))
    }

    # Use splatting for clearer Invoke-WebRequest call.
    $Splat = @{
        Uri         = $URI.Uri
        Method      = 'POST'
        Headers     = $Headers
        ContentType = 'application/json'
        Body        = $Body
        ErrorAction = 'SilentlyContinue'
    }

    try {
        $response = Invoke-WebRequest @Splat
    } catch {}

    # If we got CSV content back, parse and return it; otherwise raise.
    if ($response -and $response.Content) {
        return $response.Content | ConvertFrom-Csv
    } else {
        throw 'Either no results returned or access denied.'
    }
}

function Get-BambooHRUser {
    param(
        [Parameter(Mandatory=$true)]
        [Alias("Domain")]
        [string]$CompanyDomain,

        [Parameter(Mandatory=$true)]
        [Alias("EEID")]
        [string]$EmployeeID,

        [string[]]$fields,

        [Parameter(Mandatory=$true)]
        [string]$APIKey
    )

    [System.UriBuilder]$URI = ("https://{0}.bamboohr.com/api/v1/employees/{1}" -f $CompanyDomain, $EmployeeID)

    # Add the API version query parameter
    $Query = [System.Web.HttpUtility]::ParseQueryString('')
    $query.Add('fields', ($fields -join ','))
    $uri.Query = $query.ToString()

    $headers = @{
        'Accept'        = 'application/json'
        'Content-Type'  = 'application/json'
        'Authorization' = ("Basic {0}" -f [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($APIKey)`:x")))
    }

    $parameters = @{
        Uri         = $URI.Uri
        Method      = 'GET'
        Headers     = $headers
        ErrorAction = 'SilentlyContinue'
    }

    $response = Invoke-WebRequest @parameters

    return ($response.Content | ConvertFrom-Json)
}

function Get-BambooHRUserTableData {
    param(
        [Parameter(Mandatory=$true)]
        [Alias("Domain")]
        [string]$CompanyDomain,

        [Parameter(Mandatory=$true)]
        [Alias("EEID")]
        [string]$EmployeeID,

        [string]$TableName,

        [Parameter(Mandatory=$true)]
        [string]$APIKey
    )

    [System.UriBuilder]$URI = ("https://{0}.bamboohr.com/api/v1/employees/{1}/tables/{2}" -f $CompanyDomain, $EmployeeID, $TableName)

    $headers = @{
        'Accept'        = 'application/json'
        'Content-Type'  = 'application/json'
        'Authorization' = ("Basic {0}" -f [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($APIKey)`:x")))
    }

    $parameters = @{
        Uri         = $URI.Uri
        Method      = 'GET'
        Headers     = $headers
        ErrorAction = 'SilentlyContinue'
    }

    $response = Invoke-WebRequest @parameters

    if ($response.Content) {
        return ($response.Content | ConvertFrom-Json)
    } else {
        throw 'Either no results returned or access denied.'
    }
}

function Get-BambooHRUserPhoto {
    <#
    .SYNOPSIS
    Retrieves the small profile photo thumbnail for a BambooHR employee.

    .DESCRIPTION
    Calls the BambooHR employee photo endpoint and returns the raw thumbnail content.

    REFERENCE: https://documentation.bamboohr.com/reference/get-employee-photo

    .PARAMETER CompanyDomain
    The BambooHR company domain for your instance, e.g. <company>.bamboohr.com.

    .PARAMETER EmployeeID
    The BambooHR employee ID (EEID) for the user whose photo should be retrieved.

    .PARAMETER APIKey
    The BambooHR API key used for Basic authentication.

    .EXAMPLE
    Get-BambooHRUserPhoto -CompanyDomain "domain" -APIKey "012345678900" -EmployeeID "3391"

    .NOTES
    Returns a hashtable with a PhotoThumbprint key containing the thumbnail bytes.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Alias("Domain")]
        [string]$CompanyDomain,

        [Parameter(Mandatory=$true)]
        [Alias("EEID")]
        [string]$EmployeeID,

        [ValidateSet("small", "medium", "large","xs","tiny","original")]
        [string]$PhotoSize = "small",

        [Parameter(Mandatory=$true)]
        [string]$APIKey
    )

    # Build the photo endpoint URI. Sizes supported are validated by the
    # parameter's ValidateSet above.
    [System.UriBuilder]$URI = ("https://{0}.bamboohr.com/api/v1/employees/{1}/photo/{2}" -f $CompanyDomain, $EmployeeID, $PhotoSize)

    # Use Basic auth header; photo endpoint returns binary content for images.
    $Headers = @{
        'Content-Type'  = 'application/json'
        'Authorization' = ("Basic {0}" -f [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($APIKey)`:x")))
    }

    $Splat = @{
        ErrorAction = 'SilentlyContinue'
        Method      = 'GET'
        Uri         = $URI.Uri
        Headers     = $Headers
    }

    try {
        $response = Invoke-WebRequest @Splat
    } catch {}

    # Return the raw bytes as the PhotoThumbprint so callers can save or
    # convert them as needed. If there's no content, raise an error.
    if ($response -and $response.Content) {
        return @{ PhotoThumbprint = $response.Content }
    } else {
        throw 'Either no results returned or access denied.'
    }
}

function Get-BambooHRTableFields {
    <#
    .SYNOPSIS
    Retrieves BambooHR metadata tables and field definitions.

    REFERENCE: https://documentation.bamboohr.com/reference/list-tabular-fields

    .DESCRIPTION
    Uses the BambooHR metadata API to return tables and field definitions for the specified company domain.

    .PARAMETER CompanyDomain
    The BambooHR company domain for your instance, e.g. <company>.bamboohr.com.

    .PARAMETER APIKey
    The BambooHR API key used for Basic authentication.

    .EXAMPLE
    Get-BambooHRTablesList -CompanyDomain "companydomain" -APIKey "1234123454325432"

    .NOTES
    Returns metadata for BambooHR tables and fields.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Alias("Domain")]
        [string]$CompanyDomain,

        [Parameter(Mandatory=$true)]
        [string]$APIKey
    )

    [System.UriBuilder]$URI = ('https://{0}.bamboohr.com/api/v1/meta/tables' -f $CompanyDomain)

    $Headers = @{
        'Accept'        = 'application/json'
        'Content-Type'  = 'application/json'
        'Authorization' = ("Basic {0}" -f [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($APIKey)`:x")))
    }

    $WebRequest = @{
        Uri         = $URI.Uri
        Method      = 'GET'
        Headers     = $Headers
        ErrorAction = 'Stop'
    }

    $response = Invoke-WebRequest @WebRequest

    if ($response -and $response.Content) {
        return ($response.content | ConvertFrom-Json)
    } else {
        throw "BambooHR request failed: No content returned from metadata endpoint."
    }
}

function Get-BambooHRFieldsList {
    <#
    .SYNOPSIS
    Retrieves the list of available BambooHR fields for the company.

    REFERENCE: https://documentation.bamboohr.com/reference/list-fields

    .DESCRIPTION
    Uses the BambooHR metadata API to return field definitions that can be used in custom reports and API queries.

    .PARAMETER CompanyDomain
    The BambooHR company domain for your instance, e.g. <company>.bamboohr.com.

    .PARAMETER APIKey
    The BambooHR API key used for Basic authentication.

    .EXAMPLE
    Get-BambooHRFieldsList -CompanyDomain "companydomain" -APIKey "1234123454325432"

    .NOTES
    Field names returned by this function can be used in Get-BambooHRUsers.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Alias("Domain")]
        [string]$CompanyDomain,

        [Parameter(Mandatory=$true)]
        [string]$APIKey
    )

    [System.UriBuilder]$URI = ('https://{0}.bamboohr.com/api/v1/meta/fields' -f $CompanyDomain)

    $Headers = @{
        'Accept'        = 'application/json'
        'Content-Type'  = 'application/json'
        'Authorization' = ("Basic {0}" -f [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($APIKey)`:x")))
    }

    $WebRequest = @{
        Uri         = $URI.Uri
        Method      = 'GET'
        Headers     = $Headers
        ErrorAction = 'Stop'
    }

    # Fixed a typo here: use $response (not $respsonse) and return parsed JSON.
    $response = Invoke-WebRequest @WebRequest

    if ($response -and $response.Content) {
        return ($response.Content | ConvertFrom-Json)
    } else {
        throw "BambooHR request failed: No content returned from fields endpoint."
    }
}

function Get-BambooHRDataSets {
    <#
    .SYNOPSIS
    Retrieves the list of available BambooHR v1.2 datasets for a company domain.

    .DESCRIPTION
    Calls the BambooHR v1.2 datasets endpoint and returns the dataset
    definitions available for the configured company domain. The function
    uses Basic authentication with an API key and returns the parsed JSON
    response's `datasets` property.

    REFERENCE: https://documentation.bamboohr.com/reference/list-datasets-v1

    .PARAMETER CompanyDomain
    The BambooHR company domain (the first segment of <company>.bamboohr.com).

    .PARAMETER APIKey
    The BambooHR API key used as the username in Basic authentication.

    .EXAMPLE
    Get-BambooHRDataSets -CompanyDomain "companydomain" -APIKey "0123456789abcdef"

    .NOTES
    The function expects the v1_2 datasets endpoint to return a JSON
    structure containing a `datasets` property. Network or auth failures
    will throw exceptions.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Alias("Domain")]
        [string]$CompanyDomain,

        [Parameter(Mandatory=$true)]
        [string]$APIKey
    )

    [System.UriBuilder]$URI = ('https://{0}.bamboohr.com/api/v1_2/datasets' -f $CompanyDomain)
    $Headers = @{
        Accept        = 'application/json'
        'Content-Type' = 'application/json'
        Authorization = ("Basic {0}" -f [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($APIKey)`:x")))
    }

    $WebRequest = @{
        # Use the properly-cased URI variable here for clarity.
        URI         = $URI.Uri
        Method      = "GET"
        Headers     = $Headers
        ErrorAction = 'SilentlyContinue'
    }

    $response = Invoke-WebRequest @WebRequest

    if ($response) {
        return ($response.Content | ConvertFrom-Json).datasets
    } else {
        throw "BambooHR request failed: No content returned from datasets endpoint."
    }
}

function Get-BambooHRDataSetFields {
    <#
    .SYNOPSIS
    Retrieves fields for a BambooHR dataset.

    .DESCRIPTION
    Uses the BambooHR v1.2 dataset fields endpoint to return a dataset's field definitions.

    REFERENCE: https://documentation.bamboohr.com/reference/get-fields-from-dataset-v1-2

    .PARAMETER CompanyDomain
    The BambooHR company domain for your instance.

    .PARAMETER DataSetName
    The dataset name to inspect.

    .PARAMETER APIKey
    The BambooHR API key used for Basic authentication.

    .EXAMPLE
    Get-BambooHRDataSetFields -CompanyDomain "companydomain" -DataSetName "employee" -APIKey "1234123454325432"
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Alias("Domain")]
        [string]$CompanyDomain,

        [Parameter(Mandatory=$true)]
        [string]$DataSetName,

        [Parameter(Mandatory=$true)]
        [string]$APIKey
    )

    [System.UriBuilder]$URI = ('https://{0}.bamboohr.com/api/v1_2/datasets/{1}/fields' -f $CompanyDomain, $DataSetName)

    $Headers = @{
        'Accept'        = 'application/json'
        'Content-Type'  = 'application/json'
        'Authorization' = ("Basic {0}" -f [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($APIKey)`:x")))
    }

    $WebRequest = @{
        Uri         = $URI.Uri
        Method      = 'GET'
        Headers     = $Headers
        ErrorAction = 'stop'
    }

    $results = @()
    while ($WebRequest.Uri) {
        try {
            # Ensure we convert the raw response content to JSON first.
            $response = (Invoke-WebRequest @WebRequest).Content | ConvertFrom-Json
        } catch {
            throw "BambooHR request failed: $($_.Exception.Message)"
        }

        # Accumulate fields and follow pagination if present.
        $results += $response.fields 
        $WebRequest.Uri = $response.pagination.next_page 
    }

    if ($results) { 
        return $results 
    } else {
        throw 'Either no results returned or access denied.'
    }
}

function Get-BambooHRDataSetData {
    <#
    .SYNOPSIS
    Retrieves BambooHR dataset data.

    .DESCRIPTION
    Uses the BambooHR v2 dataset data endpoint and supports pagination via next links.

    .PARAMETER CompanyDomain
    The BambooHR company domain for your instance.

    .PARAMETER DataSetName
    The dataset name to retrieve.

    .PARAMETER Fields
    The list of dataset fields to return.

    .PARAMETER PageSize
    The number of rows per page.

    .PARAMETER Filter
    An optional filter expression to apply to the dataset.

    .PARAMETER APIKey
    The BambooHR API key used for Basic authentication.

    .EXAMPLE
    $fields = Get-BambooHRDataSetFields -Companydomain "companydomain" -DataSetName "employees" | Where-Object {$_.ParentName -in ('Job Information','Personal','Employment Status','Default Status')}
    Get-BambooHRDataSetData -CompanyDomain "companydomain" -DataSetName "employees" -Fields $fields.Name

    .EXAMPLE
    Get-BambooHRDataSetData -CompanyDomain "companydomain" -DataSetName "employees" -Fields @('eeid','firstName') -APIKey "1234123454325432"

    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Alias("Domain")]
        [string]$CompanyDomain,

        [Parameter(Mandatory=$true)]
        [string]$DataSetName,

        [Parameter(Mandatory=$true)]
        [string[]]$Fields,

        [int]
        $PageSize = 100,

        [string]
        $Filter,

        [Parameter(Mandatory=$true)]
        [string]$APIKey
    )

    [System.UriBuilder]$URI = ('https://{0}.bamboohr.com/api/v2/datasets/{1}/data' -f $CompanyDomain, $DataSetName)
    $Headers = @{
        'Accept'        = 'application/problem+json'
        'Content-Type'  = 'application/json'
        'Authorization' = ("Basic {0}" -f [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($APIKey)`:x")))
    }

    $Body = @{
        pageSize = $PageSize
        fields   = $Fields
    }

    if ($Filter) {
        $Body.filter = $Filter
    }

    $WebRequest = @{
        URI         = $URI.Uri
        Method      = 'POST'
        Headers     = $Headers
        Body        = ($Body | ConvertTo-Json -Depth 10)
        ErrorAction = 'Stop'
    }

    $results = @()
    while ($WebRequest.URI) {
        try {
            $response = Invoke-WebRequest @WebRequest | convertfrom-json
        } catch {
            throw "BambooHR request failed: $($_.Exception.Message)"
        }

        if ($response.data) {
            $results += $response.data.fields
        }

        $WebRequest.URI = $response.links.next
    }

    if ($results) { 
        return $results 
    } else {
        throw 'Either no results returned or access denied.'
    }
}
