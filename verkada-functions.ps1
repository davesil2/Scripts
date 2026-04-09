
<#
.SYNOPSIS
    Retrieves an authentication token from the Verkada API.

.DESCRIPTION
    This function makes a POST request to the Verkada token endpoint using the provided API key to obtain an authentication token required for other API calls.

.PARAMETER APIKey
    The API key for authenticating with the Verkada API.

.EXAMPLE
    $token = Get-VerkadaToken -APIKey "your-api-key-here"
    This example retrieves a token using the specified API key.

.OUTPUTS
    System.Management.Automation.PSObject
    Returns a JSON object containing the authentication token and related information.
#>
function Get-VerkadaToken {
    Param(
        [string]$APIKey
    )

    # Build the URI for the token endpoint
    [URIBuilder]$URI = 'https://api.verkada.com/token'

    # Set the request headers including the API key for authentication
    $Header = @{
        'accept'    = 'application/json'
        'x-api-key' = $APIKey
    }

    # Prepare the parameters for the web request
    $Parameters = @{
        'Method'        = 'Post'
        'URI'           = $URI.Uri
        'Headers'       = $Header
    }
    
    # Make the POST request to obtain the token
    $Response = Invoke-WebRequest @Parameters

    # Parse and return the JSON response containing the token
    return $Response.Content | ConvertFrom-Json
}

<#
.SYNOPSIS
    Retrieves audit logs from the Verkada API.

.DESCRIPTION
    This function queries the Verkada audit log API to retrieve security and activity logs. It supports filtering by time range, pagination, and can retrieve all records if specified.

.PARAMETER FQDN
    The fully qualified domain name of the Verkada API endpoint. Defaults to 'api.verkada.com'.

.PARAMETER Token
    The authentication token obtained from Get-VerkadaToken.

.PARAMETER StartTime
    The start time for filtering audit logs (datetime object).

.PARAMETER EndTime
    The end time for filtering audit logs (datetime object).

.PARAMETER UseProcessedTimestamp
    Switch to use processed timestamp instead of raw timestamp.

.PARAMETER PageSize
    The number of records to retrieve per page.

.PARAMETER AllRecords
    Switch to retrieve all available records across multiple pages.

.EXAMPLE
    $logs = Get-VerkadaAuditLog -Token $token -StartTime (Get-Date).AddDays(-1) -EndTime (Get-Date)
    This example retrieves audit logs from the last 24 hours.

.EXAMPLE
    $allLogs = Get-VerkadaAuditLog -Token $token -AllRecords
    This example retrieves all available audit logs.

.OUTPUTS
    System.Object[]
    Returns an array of audit log objects.
#>
function Get-VerkadaAuditLog {
    param(
        [String]$FQDN = 'api.verkada.com',
        [string]$Token,
        [datetime]$StartTime,
        [datetime]$EndTime,
        [Switch]$UseProcessedTimestamp,
        [int]$PageSize,
        [Switch]$AllRecords
    )

    # Build the base URI for the audit log endpoint using the provided FQDN
    [URIBuilder]$URI = ("https://$FQDN/core/v1/audit_log")

    # Initialize an empty query string to build the request parameters
    $Query = [System.Web.HttpUtility]::ParseQueryString('')
    
    # Add start and end time filters if both are provided, converting to Unix timestamp
    if ($StartTime -and $EndTime) {
        $Query.Add('start_time',([DateTimeOffset]::new($StartTime).ToUnixTimeSeconds()))
        $Query.Add('end_time',([DateTimeOffset]::new($EndTime).ToUnixTimeSeconds()))
    }
    
    # Add the processed timestamp flag
    $Query.Add('user_processed_timestamp',$UseProcessedTimestamp.IsPresent)
    
    # Add page size if specified
    if ($PageSize) {
        $Query.Add('page_size',$PageSize)
    }
    
    # Apply the query string to the URI
    $URI.Query = $Query.ToString()

    # Set the request headers including the authentication token
    $header = @{
        'accept'            = 'application/json'
        'x-verkada-auth'    = $Token
    }

    # Prepare the parameters for the GET request
    $Parameters = @{
        'Method'        = 'Get'
        'URI'           = $URI.Uri
        'Headers'       = $header
    }

    # Initialize an array to collect all audit log results
    $Results = @()
    
    # Make the initial request and add the first page of results
    $Response = Invoke-WebRequest @Parameters
    $Results += ($Response.Content | ConvertFrom-Json).audit_logs

    # If AllRecords is specified and there are more pages, continue fetching
    While ($AllRecords -and ($Response.Content | convertfrom-json).next_page_token) {
        # Update the query with the next page token for pagination
        $Query.Set('page_token',($Response.Content | ConvertFrom-Json).next_page_token)
        $URI.Query = $Query.ToString()
        $Parameters.URI = $URI.Uri
        
        # Make the next page request
        $Response = Invoke-WebRequest @Parameters
        $Results += ($Response.Content | ConvertFrom-Json).audit_logs
    }
    
    # Return the collected audit log results
    return $Results
}