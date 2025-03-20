# TruHu Functions/Updates
function Get-TruHutoken {
    Param(
        [String]$FQDN = 'api.truhu.com',
        [String]$UserName,
        [String]$Password,
        [String]$GrantType = 'password',
        [ValidateScript(
            {$_ -in ([enum]::GetNames([net.securityprotocoltype]))},
            ErrorMessage = 'ERROR: TLS version must be supported on system (run [enum]::GetNames([net.securityprotocoltype]) for a valid list)'
        )]
        [string]$TLSVersion = 'Tls12'
    )

    # set TLS version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::"$TLSVersion"
    
    # generate uri for generating token
    [System.UriBuilder]$URI = ('https://{0}/token' -f $FQDN)

    $tokenbody = @{
        username        = $UserName
        password        = $Password
        'Grant_Type'    = $GrantType
    }

    $headers = @{
        Accept = 'application/json'
    }

    $Parameters = @{
        Method  = 'POST'
        URI     = $URI.Uri
        Body    = $tokenbody
        Header  = $headers
    }

    $token = Invoke-RestMethod @Parameters

    if ($token) {
        return $token
    } else {
        throw '[ERROR] - '
    }
}

function Get-TruHuEmployees {
    Param(
        [String]$FQDN = 'api.truhu.com',
        [String]$CompanyID,
        $APIToken,
        [ValidateScript(
            {$_ -in ([enum]::GetNames([net.securityprotocoltype]))},
            ErrorMessage = 'ERROR: TLS version must be supported on system (run [enum]::GetNames([net.securityprotocoltype]) for a valid list)'
        )]
        [string]$TLSVersion = 'Tls12'
    )

    # set TLS version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::"$TLSVersion"
    
    # generate uri for generating token
    [System.UriBuilder]$URI = ('https://{0}/Census' -f $FQDN)

    $Headers = @{
        Authorization   = ('Bearer {0}' -f $APIToken.access_token)
        Accept          = 'application/json'
    }

    $query = [System.Web.HttpUtility]::ParseQueryString('')
    $query.add('guid',$companyid)
    $URI.Query = $Query.ToString()

    $Parameters = @{
        Method = 'GET'
        Header = $Headers
        URI = $URI.Uri
    }

    $Employees = Invoke-RestMethod @Parameters

    if ($Employees) {
        return $Employees
    } else {
        throw '[ERROR] - '
    }
}

function Update-TruHuEmployees {
    Param(
        [String]$FQDN = 'api.truhu.com',
        $APIToken,
        $Census
    )

    # set TLS version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::"$TLSVersion"
    
    # generate uri for generating token
    [System.UriBuilder]$URI = ('https://{0}/Census/Update' -f $FQDN)

    $Headers = @{
        Authorization   = ('Bearer {0}' -f $APIToken.access_token)
        Accept          = 'application/json'
    }

    $Body = @{
        cencus = $Census
    }

    $Parameters = @{
        Method      = 'POST'
        Header      = $Headers
        URI         = $URI.Uri
        Body        = (convertto-json $body -depth 10)
        ContentType = 'application/json'
        ErrorAction = 'silentlyContinue'
    }

    $Result = Invoke-RestMethod @Parameters -verbose

    if ($Result) {
        return $Result
    } else {
        $parameters
        throw '[ERROR] - '
    }
}
