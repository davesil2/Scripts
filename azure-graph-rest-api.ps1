function ConvertTo-Base64Url {
    <#
    .SYNOPSIS
        Converts a byte array to Base64Url encoded string.

    .DESCRIPTION
        This helper function converts binary data to Base64Url format, which is used in JWT creation.
        Base64Url encoding is similar to Base64 but uses URL-safe characters (- and _) instead of (+ and /),
        and omits padding characters (=).

    .PARAMETER bytes
        The byte array to encode.

    .EXAMPLE
        $encoded = ConvertTo-Base64Url -bytes ([Text.Encoding]::UTF8.GetBytes("Hello World"))

    .OUTPUTS
        System.String. The Base64Url encoded string.
    #>
    param (
        [byte[]]$bytes
    )

    # Convert to Base64, remove padding, and replace URL-unsafe characters
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}

function Get-GraphAPIToken {
    <#
    .SYNOPSIS
        Retrieves an access token for Azure APIs using OAuth2 client credentials flow with multiple authentication methods.

    .DESCRIPTION
        This function authenticates with Azure Active Directory using a service principal and supports three authentication methods:
        1. Client Secret: Traditional client secret authentication
        2. Certificate Thumbprint: Uses a certificate from the local machine certificate store
        3. PEM Certificate File: Uses a certificate from a PEM file on disk

        For certificate-based authentication, the function creates a JWT (JSON Web Token) signed with the certificate's private key
        and uses OAuth2 client assertion flow. The token can be used for subsequent API calls to Azure services.

    .PARAMETER tenantId
        The Azure AD tenant ID where the service principal is registered.

    .PARAMETER clientId
        The client ID (application ID) of the Azure AD service principal.

    .PARAMETER clientSecret
        The client secret of the Azure AD service principal. Required when using client secret authentication.

    .PARAMETER certThumbprint
        The thumbprint of the certificate in the LocalMachine\My certificate store. Required when using certificate thumbprint authentication.

    .PARAMETER certPath
        The file path to a PEM certificate file. Required when using PEM certificate file authentication.

    .PARAMETER scopes
        The OAuth2 scopes to request. Defaults to Azure Management API scope if not specified.

    .EXAMPLE
        # Client Secret Authentication
        $token = Get-GraphAPIToken -tenantId "12345678-1234-1234-1234-123456789012" -clientId "87654321-4321-4321-4321-210987654321" -clientSecret "mySecret"

    .EXAMPLE
        # Certificate Thumbprint Authentication
        $token = Get-GraphAPIToken -tenantId "12345678-1234-1234-1234-123456789012" -clientId "87654321-4321-4321-4321-210987654321" -certThumbprint "ABC123DEF456"

    .EXAMPLE
        # PEM Certificate File Authentication
        $token = Get-GraphAPIToken -tenantId "12345678-1234-1234-1234-123456789012" -clientId "87654321-4321-4321-4321-210987654321" -certPath "C:\certs\myapp.pem"

    .OUTPUTS
        System.String. The access token for Azure API calls.

    .NOTES
        Certificate-based authentication requires the certificate to have a private key and be configured for the service principal in Azure AD.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$tenantId,
        [Parameter(Mandatory=$true)]
        [string]$clientId,
        [Parameter(Mandatory=$true,ParameterSetName='Secret')]
        [string]$clientSecret,
        [Parameter(Mandatory=$false,ParameterSetName='Thumbprint')]
        [string]$certThumbprint,
        [Parameter(Mandatory=$false,ParameterSetName='PemCert')]
        [string]$certPath,
        [Parameter(Mandatory=$false)]
        [string]$scopes
    )

    # Build the token endpoint URL for the specified tenant
    [System.UriBuilder]$URI = ('https://login.microsoftonline.com/{0}/oauth2/v2.0/token' -f $tenantId)

    # Initialize the OAuth2 request body with common parameters
    $body = @{
        grant_type    = "client_credentials"
        client_id     = $clientId
        scope         = $scopes
    }

    # Set default scope if not provided
    if ([string]::IsNullOrEmpty($scopes)) {
        $body.scope = "https://management.azure.com/.default"
    }

    # Add client secret to body if using secret-based authentication
    if ($PSCmdlet.ParameterSetName -eq 'Secret') {
        $body += @{client_secret = $clientSecret}
    }

    # Handle certificate thumbprint authentication - load cert from Windows certificate store
    if ($PSCmdlet.ParameterSetName -eq 'Thumbprint') {
        # Retrieve certificate from local machine store using thumbprint
        $cert = Get-ChildItem -Path cert:\LocalMachine\My\$certThumbprint
        if (-not $cert) {
            throw "Certificate with thumbprint $certThumbprint not found in LocalMachine\My store"
        }
    }

    # Handle PEM certificate file authentication - load cert from file system
    if ($PSCmdlet.ParameterSetName -eq 'PemCert') {
        # Validate certificate file exists
        if (-not (Test-Path $certPath)) {
            throw "Certificate file not found at path $certPath"
        }
        try {
            # Load certificate from PEM file
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile($certPath)
        } catch {
            throw "Failed to load certificate from path $certPath`: $_"
        }
    }

    # Process certificate-based authentication (both thumbprint and PEM methods)
    if ($PSCmdlet.ParameterSetName -in ('PemCert','Thumbprint')) {
        # Ensure certificate has a private key for signing
        if (-not $cert.HasPrivateKey) {
            throw "Certificate must have a private key to be used for authentication"
        }

        # Set JWT timing values (token valid for 5 minutes)
        $now = [DateTime]::UtcNow
        $nbf = [System.DateTimeOffset]$now  # Not Before time
        $exp = [System.DateTimeOffset]$now.AddMinutes(5)  # Expiration time

        # Create JWT header with certificate thumbprint for key identification
        $jwtHeader = @{
            alg = "RS256"        # RSA signature with SHA-256
            typ = "JWT"          # JSON Web Token type
            x5t = [Convert]::ToBase64String($cert.GetCertHash())  # Certificate thumbprint
        }

        # Create JWT payload with OAuth2 client assertion claims
        $jwtPayload = @{
            aud = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"  # Audience (token endpoint)
            iss = $clientId        # Issuer (client ID)
            sub = $clientId        # Subject (client ID)
            jti = [Guid]::NewGuid().ToString()  # JWT ID (unique identifier)
            nbf = $nbf.ToUnixTimeSeconds()       # Not Before (Unix timestamp)
            exp = $exp.ToUnixTimeSeconds()       # Expiration (Unix timestamp)
        }

        # Encode header and payload to Base64Url format
        $headerEncoded = ConvertTo-Base64Url -bytes ([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $jwtHeader -Compress)))
        $payloadEncoded = ConvertTo-Base64Url -bytes ([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $jwtPayload -Compress)))

        # Combine header and payload for signing
        $jwtToSign = "$headerEncoded.$payloadEncoded"

        # Sign the JWT using the certificate's private key with RSA-SHA256
        $signatureBytes = $cert.privatekey.SignData([Text.Encoding]::UTF8.GetBytes($jwtToSign), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $signatureEncoded = ConvertTo-Base64Url -bytes $signatureBytes

        # Create the complete signed JWT
        $jwtSigned = "$jwtToSign.$signatureEncoded"

        # Add client assertion parameters to OAuth2 request body
        $body += @{client_assertion         = $jwtSigned}
        $body += @{client_assertion_type    = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}
    }

    # Configure parameters for the REST API call to get access token
    $parameters = @{
        Method  = 'POST'
        Uri     = $URI.Uri
        Body    = $body
    }

    # Debug output - display request body (remove in production or make conditional)
    # Uncomment the next line for debugging
    # Write-Host ($body | ConvertTo-Json -Depth 10)

    # Make the OAuth2 token request
    try {
        $response = Invoke-RestMethod @parameters -ContentType 'application/x-www-form-urlencoded'
    } catch {
        throw "Failed to acquire access token: $($_.Exception.Message)"
    }

    # Return the access token if authentication was successful
    if ($response -and $response.access_token) {
        return $response.access_token
    } else {
        throw "Authentication failed: No access token received in response"
    }
}

function Get-GraphAzureManagementGroups {
    <#
    .SYNOPSIS
        Retrieves a list of Azure management groups.

    .DESCRIPTION
        This function queries the Azure Management API to get all management groups
        accessible to the authenticated service principal. Management groups provide
        a way to manage access, policies, and compliance across multiple subscriptions.

    .PARAMETER accessToken
        The Azure access token obtained from Get-GraphAPIToken.

    .PARAMETER apiVersion
        The API version to use for the request. Defaults to '2020-05-01'.

    .EXAMPLE
        $token = Get-GraphAPIToken -tenantId "12345678-1234-1234-1234-123456789012" -clientId "87654321-4321-4321-4321-210987654321" -clientSecret "mySecret"
        $mgmtGroups = Get-GraphAzureManagementGroups -accessToken $token

    .OUTPUTS
        System.Object[]. Array of management group objects.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$accessToken,
        [string]$apiVersion = '2020-05-01'
    )

    # Build the URI for the management groups endpoint
    [System.UriBuilder]$URI = 'https://management.azure.com/providers/Microsoft.Management/managementGroups'

    # Add the API version query parameter
    $Query = [System.Web.HttpUtility]::ParseQueryString('')
    $query.Add('api-version', $apiVersion)
    $uri.Query = $query.ToString()

    # Set up authorization headers
    $headers = @{
        Authorization = "Bearer $accessToken"
        "Content-Type" = "application/json"
    }

    # Configure parameters for the REST API call
    $parameters = @{
        Method  = 'GET'
        Uri     = $URI.Uri
        Headers = $headers
    }

    # Make the API call to retrieve management groups
    $response = Invoke-RestMethod @parameters

    # Return the management groups if the response was successful
    if ($response) {
        return $response.value
    }
}

function Get-GraphAzureCosts {
    <#
    .SYNOPSIS
        Retrieves Azure cost and usage data for a specified scope.

    .DESCRIPTION
        This function queries the Azure Cost Management API to get detailed cost and usage
        information for a given scope (subscription, resource group, etc.). It supports
        various grouping dimensions, time periods, and cost types to provide flexible
        cost analysis capabilities.

    .PARAMETER ScopeId
        The Azure scope for which to retrieve costs (e.g., 'subscriptions/12345678-1234-1234-1234-123456789012').

    .PARAMETER accessToken
        The Azure access token obtained from Get-GraphAPIToken.

    .PARAMETER apiVersion
        The API version to use for the request. Defaults to '2023-09-01'.

    .PARAMETER StartDate
        The start date for the cost query (as a DateTime object).

    .PARAMETER EndDate
        The end date for the cost query (as a DateTime object).

    .PARAMETER Granularity
        The time granularity for grouping costs. Valid values: None, Daily, Hourly. Defaults to 'None'.

    .PARAMETER CostType
        The type of cost to retrieve. Valid values: ActualCost, AmortizedCost. Defaults to 'ActualCost'.

    .PARAMETER ExcludeTags
        Switch to exclude resource tags from the results.

    .PARAMETER Grouping
        Array of dimensions to group the results by. Valid values: SubscriptionId, SubscriptionName,
        ResourceGroupName, ResourceType, ResourceLocation, ResourceId, PublisherType.
        Defaults to all except PublisherType.

    .EXAMPLE
        $token = Get-GraphAPIToken -tenantId "12345678-1234-1234-1234-123456789012" -clientId "87654321-4321-4321-4321-210987654321" -clientSecret "mySecret"
        $costs = Get-GraphAzureCosts -ScopeId "subscriptions/12345678-1234-1234-1234-123456789012" -accessToken $token -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date)

    .EXAMPLE
        # Get daily costs grouped by resource type and location
        $costs = Get-GraphAzureCosts -ScopeId "subscriptions/12345678-1234-1234-1234-123456789012" -accessToken $token -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -Granularity Daily -Grouping @('ResourceType', 'ResourceLocation')

    .OUTPUTS
        System.Management.Automation.PSCustomObject[]. Array of cost data objects.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [String]$ScopeId,
        [Parameter(Mandatory=$true)]
        [string]$accessToken,
        [string]$apiVersion = '2023-09-01',
        [datetime]$StartDate,
        [datetime]$EndDate,
        [ValidateSet('None','Daily','Hourly')]
        [string]$Granularity = 'None',
        [ValidateSet('ActualCost','AmortizedCost')]
        [string]$CostType = 'ActualCost',
        [switch]$ExcludeTags,
        [ValidateSet('SubscriptionId','SubscriptionName','ResourceGroupName','ResourceType','ResourceLocation','ResourceId','PublisherType')]
        [string[]]$Grouping = @('SubscriptionId','SubscriptionName','ResourceGroupName','ResourceType','ResourceLocation','ResourceId')
    )

    # Validate date parameters
    if (-not $StartDate -or -not $EndDate) {
        throw "StartDate and EndDate parameters are required"
    }

    if ($StartDate -gt $EndDate) {
        throw "StartDate cannot be after EndDate"
    }

    # Build the URI for the Cost Management query endpoint
    [System.UriBuilder]$uri = "https://management.azure.com/$ScopeId/providers/Microsoft.CostManagement/query"

    # Add the API version query parameter
    $Query = [System.Web.HttpUtility]::ParseQueryString('')
    $query.Add('api-version', $apiVersion)
    $uri.Query = $query.ToString()

    # Set up authorization headers
    $headers = @{
        Authorization = "Bearer $accessToken"
        "Content-Type" = "application/json"
    }

    # Build the request body with cost query parameters
    $Body = @{
        type       = $CostType
        timeframe  = 'Custom'
        timePeriod = @{
            from = ($StartDate.ToString("yyyy-MM-ddT00:00:00Z"))
            to   = ($EndDate.ToString("yyyy-MM-ddT23:59:59Z"))
        }
        dataset    = @{
            granularity = $Granularity
            aggregation = @{
                totalCost = @{
                    name     = 'Cost'
                    function = "Sum"
                }
            }
            grouping    = @()
        }
    }
                totalCost = @{
                    name     = 'Cost'
                    function = "Sum"
                }
            }
            grouping = @()
        }
    }

    # Include tags in the dataset unless explicitly excluded
    if (-Not $ExcludeTags) {
        $body.dataset += @{include = @("Tags")}
    }

    # Add grouping dimensions to the dataset
    foreach ($group in $Grouping) {
        $Body.dataset.grouping += @{type = "Dimension"; name = $group}
    }

    # Configure parameters for the REST API call
    $parameters = @{
        Method  = 'POST'
        Uri     = $uri.Uri
        Headers = $headers
        Body    = ($Body | ConvertTo-Json -Depth 10)
    }

    # Initialize output array and handle pagination
    $Output = @()
    while ($parameters.uri) {
        # Make the API call
        $response = Invoke-RestMethod @parameters

        # Extract column definitions and row data
        $columns = $response.properties.columns
        $rows    = $response.properties.rows

        # Convert each row to a custom object
        $Output += foreach ($row in $rows) {
            $obj = @{}
            for ($i = 0; $i -lt $columns.Count; $i++) {
                $obj[$columns[$i].name] = $row[$i]
            }
            [PSCustomObject]$obj
        }

        # Check for next page in pagination
        $parameters.uri = $response.properties.nextLink
    }

    # Return the cost data if any was retrieved
    if ($Output) {
        return $Output
    }
}