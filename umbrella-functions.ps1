function Get-UmbrellaToken {
    Param(
        [String]$URI = 'api.umbrella.com',
        [Parameter(Mandatory=$true)]
        [String]$Key,
        [Parameter(Mandatory=$true)]
        [String]$Secret
    )

    [System.UriBuilder]$URI = ('https://{0}/auth/v2/token' -f $URI)

    $headers = @{
        'Content-Type'  = 'applicaiton/x-www-form-urlencoded'
        'Authorization' = ('Basic {0}' -f ([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($key + ":" + $Secret))))
        'grant_type' = 'client_credentials'
    }

    $Parameters = @{
        'Method'        = 'GET'
        'URI'           = $URI.uri
        'Headers'       = $headers
        'ErrorAction'   = 'SilentlyContinue'
    }

    $BearerToken = Invoke-RestMethod @Parameters
    
    if ($BearerToken) {
        return $BearerToken
    } else {
        throw "ERROR - There was a problem authenticating, please verify your key and secret"
    }
}

function Get-UmbrellaAdminUsers {
    Param(
        $URI = 'api.umbrella.com',
        [Parameter(Mandatory=$true)]
        $Token
    )

    [System.UriBuilder]$URI = ('https://{0}/admin/v2/users' -f $URI)

    $Headers = @{
        'Accept' = 'application/json'
        'Authorization' = ('Bearer {0}' -f $token.access_token)
    }

    $Parameters = @{
        'Method'        = 'GET'
        'URI'           = $uri.Uri
        'Header'        = $Headers
        'ErrorAction'   = 'SilentlyContinue'
    }

    $Users = Invoke-RestMethod @Parameters

    if ($Users) {
        return $Users
    } else {
        throw 'ERROR - check the token, it may be expired or invalid.'
    }
}

function Get-UmbrellaAdminRoles {
    Param(
        $URI = 'api.umbrella.com',
        $token
    )

    [System.UriBuilder]$URI = ('https://{0}/admin/v2/roles' -f $URI)

    $Headers = @{
        'Accept' = 'application/json'
        'Authorization' = ('Bearer {0}' -f $token.access_token)
    }

    $Parameters = @{
        'Method'        = 'GET'
        'URI'           = $uri.Uri
        'Header'        = $Headers
        'ErrorAction'   = 'SilentlyContinue'
    }

    $Roles = Invoke-RestMethod @Parameters

    if ($Roles) {
        return $Roles
    } else {
        throw 'ERROR - check the token, it may be invalid or expired!'
    }
}

function New-UmbrellaAdminUser {
    Param(
        [String]$URI = 'api.umbrella.com',
        [Parameter(Mandatory=$true)]
        $Token,
        [Parameter(Mandatory=$true)]
        [String]$email,
        [int]$roleid = 2,
        [String]$TimeZone = 'America/Chicago',
        [String]$FirstName,
        [String]$LastName
    )

    [System.UriBuilder]$URI = ('https://{0}/admin/v2/users' -f $URI)

    $Headers = @{
        'Accept' = 'application/json'
        'Authorization' = ('Bearer {0}' -f $token.access_token)
    }

    $Body = @{
        'email'     = $email
        'roleId'    = $roleid
    }

    if ($firstname) {
        $Body += @{'firstname' = $FirstName}
    }
    if ($LastName) {
        $Body += @{'lastname'  = $LastName}
    }
    if ($TimeZone) {
        $Body += @{'timezone'  = $TimeZone}
    }

    $Parameters = @{
        'URI'           = $URI.Uri
        'Method'        = 'POST'
        'Header'        = $Headers
        'Body'          = $Body
        'ErrorAction'   = 'SilentlyContinue'
    }

    try {
        $Result = Invoke-RestMethod @Parameters 
    } catch {
        $body.Remove('timezone')
        $body.remove('lastname')
        $body.remove('firstname')

        $Parameters['Body'] = $body
        $Result = Invoke-RestMethod @Parameters 
    }
    

    return $result
}

function Remove-UmbrellaAdminUser {
    Param(
        $URI = 'api.umbrella.com',
        [Parameter(Mandatory=$true)]
        $Token,
        [Parameter(Mandatory=$true)]
        $UserID
    )

    [System.UriBuilder]$URI = ('https://{0}/admin/v2/users/{1}' -f $URI,$UserID)

    $Headers = @{
        'Accept' = 'application/json'
        'Authorization' = ('Bearer {0}' -f $token.access_token)
    }

    $Parameters = @{
        'URI'           = $URI.Uri
        'Method'        = 'DELETE'
        'Header'        = $Headers
        'ErrorAction'   = 'SilentlyContinue'
    }

    $Result = Invoke-RestMethod @Parameters

    return $result
}

function Get-UmbrellaDeploymentNetworks {
    Param(
        [String]$URI = 'api.umbrella.com',
        $Token
    )

    [System.UriBuilder]$URI = ('https://{0}/deployments/v2/networks' -f $URI)

    $Headers = @{
        'Accept' = 'application/json'
        'Authorization' = ('Bearer {0}' -f $token.access_token)
    }

    $Parameters = @{
        'Method'        = 'GET'
        'URI'           = $uri.Uri
        'Header'        = $Headers
        'ErrorAction'   = 'SilentlyContinue'
    }

    try {
        $networks = Invoke-RestMethod @Parameters
    } catch {

    }

    if ($networks) {
        return $networks
    } else {
        throw 'ERROR - check the token, it may be invalid or expired!'
    }
}

function Get-UmbrellaDeploymentInternalNetworks {
    Param(
        [String]$URI = 'api.umbrella.com',
        $Token
    )

    [System.UriBuilder]$URI = ('https://{0}/deployments/v2/internalnetworks' -f $URI)

    $Headers = @{
        'Accept' = 'application/json'
        'Authorization' = ('Bearer {0}' -f $token.access_token)
    }

    $Parameters = @{
        'Method'        = 'GET'
        'URI'           = $uri.Uri
        'Header'        = $Headers
        'ErrorAction'   = 'SilentlyContinue'
    }

    try {
        $networks = Invoke-RestMethod @Parameters
    } catch {

    }

    if ($networks) {
        return $networks
    } else {
        throw 'ERROR - check the token, it may be invalid or expired!'
    }
}