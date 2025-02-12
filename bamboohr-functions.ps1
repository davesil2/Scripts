<#
    .SYNOPSIS

    Provides output of Users from BambooHR REST API

    .DESCRIPTION

    Using BambooHR's provide developer API, this function allows a quick query against the specific BambooHR Domain when used with the API Key.  The function allows customization of output based on desired results

    .PARAMETER Domain

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

    Get-BambooHRUsers -Domain companydomain -APIKey 123456678900

    # Returns the users from the BambooHR company company.bamboohr.com with the APIKey

#>
function Get-BambooHRUsers {
    Param(
        [Parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true
        )]
        [string]$Domain,
        [switch]$OnlyCurrent,
        [string[]]$Fields = ("firstname","lastname","id","employeenumber","preferredname","customPreferredLastName","workemail","employmentHistoryStatus","jobtitle","supervisoremail","department","division","manager","location","hiredate","workPhone","mobilePhone","country","customBusinessUnitCode","status","customPositionID","customFunction","Exempt","terminationDate"),
        [Parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true
        )]
        [string]$APIKey
    )

    [System.UriBuilder]$URI = ("https://api.bamboohr.com/api/gateway.php/{0}/v1/reports/custom?format=csv&onlyCurrent={1}" -f $Domain,$OnlyCurrent.IsPresent.ToString().tolower())

    $Body = [pscustomobject]@{fields=$fields} | ConvertTo-Json

    $Headers = @{
        "content-type"  = "application/json"
        "authorization" = ("Basic {0}" -f [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($APIKey)`:x")))
    }

    $Splat = @{
        Uri         = $URI.uri
        Method      = 'Post'
        Headers     = $Headers
        ContentType = 'application/json'
        Body        = $Body
        Verbose     = $false
    }

    $Result = Invoke-RestMethod @Splat -ErrorAction SilentlyContinue

    if ($result) {
        Return ($result | ConvertFrom-Csv)
    } else {
        throw 'Either no results returned or access denied!'
    }
}