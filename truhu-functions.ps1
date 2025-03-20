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
        Method      = 'POST'
        URI         = $URI.Uri
        Body        = $tokenbody
        Header      = $headers
        ErrorAction = 'silentlyContinue'
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
        Method      = 'GET'
        Header      = $Headers
        URI         = $URI.Uri
        ErrorAction = 'silentlyContinue'
        ContentType = 'application/json'
    }

    $Employees = Invoke-RestMethod @Parameters

    if ($Employees) {
        return $Employees
    } else {
        throw '[ERROR] - '
    }
}

function Add-TruHuEmployee {
    Param(
        [Parameter(Mandatory=$true)]
        $APIToken,
        [Parameter(Mandatory=$false)]
        [String]$FQDN = 'api.truhu.com',
        [Parameter(Mandatory=$true)]
        [String]$CompanyID,
        [Parameter(Mandatory=$true)]
        [String]$FirstName,
        [Parameter(Mandatory=$true)]
        [String]$LastName,
        [Parameter(Mandatory=$false)]
        [String]$MiddleInitial,
        [Parameter(Mandatory=$true)]
        [String]$EmailAddress,
        [Parameter(Mandatory=$true)]
        [String]$CellPhone,
        [Parameter(Mandatory=$false)]
        [String[]]$Locations = @(),
        [Parameter(Mandatory=$false)]
        [String[]]$Departments = @(),
        [Parameter(Mandatory=$false)]
        [String]$Classification,
        [Parameter(Mandatory=$false)]
        [String]$Status,
        [Parameter(Mandatory=$false)]
        [String]$JobTitle,
        [Parameter(Mandatory=$false)]
        [String]$Language,
        [Parameter(Mandatory=$false)]
        [String]$EmployeeId,
        [Parameter(Mandatory=$false)]
        [String]$TimeZone,
        [Parameter(Mandatory=$false)]
        [hashtable]$ManagerDetails = @{EmailAddress=$null},
        [Parameter(Mandatory=$false)]
        [String]$DateOfHire,
        [Parameter(Mandatory=$false)]
        [hashtable]$TerminationDetails = @{Date=$null;Type=$null},
        [Parameter(Mandatory=$false)]
        [String]$DateOfBirth,
        [Parameter(Mandatory=$false)]
        [String]$Gender,
        [Parameter(Mandatory=$false)]
        [String]$Ethnicity,
        [Parameter(Mandatory=$false)]
        [string]$RemoteID,
        [Parameter(Mandatory=$false)]
        [hashtable]$Address = @{address1='';city='';state='';zip=''},
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

    if (-Not $RemoteID) {
        $RemoteID = $EmailAddress
    }

    $Employee = @{
        FirstName = $FirstName
        LastName = $LastName
        MiddleInitial = $MiddleInitial
        EmailAddress = $EmailAddress
        CellPhone = $CellPhone
        Locations = $Locations
        Departments = $Departments
        Classification = $Classification
        Status = $Status
        JobTitle = $JobTitle
        Language = $Language
        EmployeeId = $EmployeeId
        TimeZone = $TimeZone
        ManagerDetails = $ManagerDetails
        DateOfHire = $DateOfHire
        TerminationDetails = $TerminationDetails
        DateOfBirth = $DateOfBirth
        Gender = $Gender
        Ethnicity = $Ethnicity
        Address = $Address
        remoteID = $remoteID
    }

    $Census = Get-TruHuEmployees `
        -FQDN $FQDN `
        -CompanyID $CompanyID `
        -APIToken $APIToken

    $Census.Employees += $Employee
    $census.ExternalSystem = 1

    $parameters = @{
        Method      = 'POST'
        Header      = $Headers
        URI         = $URI.Uri
        Body        = (convertto-json $Census -depth 10)
        ContentType = 'application/json'
        ErrorAction = 'silentlyContinue'
    }

    $Result = Invoke-RestMethod @Parameters

    if ($Result) {
        return $Result
    } else {
        $parameters
        throw '[ERROR] - '
    }
}

function Update-TruHuEmployees {
    Param(
        [String]$FQDN = 'api.truhu.com',
        $APIToken,
        $Census,
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

    $Parameters = @{
        Method      = 'POST'
        Header      = $Headers
        URI         = $URI.Uri
        Body        = (convertto-json $Census -depth 10)
        ContentType = 'application/json'
        ErrorAction = 'silentlyContinue'
    }

    $Result = Invoke-RestMethod @Parameters

    if ($Result) {
        return $Result
    } else {
        $parameters
        throw '[ERROR] - '
    }
}

function Clear-TruHuEmployees {
    Param(
        [Parameter(Mandatory=$true)]
        $CompanyID,
        [Parameter(Mandatory=$true)]
        $APIToken,
        [Parameter(Mandatory=$false)]
        $FQDN = 'api.truhu.com',
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

    $query = [System.Web.HttpUtility]::ParseQueryString('')
    $query.add('guid',$companyid)
    $URI.Query = $Query.ToString()

    $Headers = @{
        Authorization   = ('Bearer {0}' -f $APIToken.access_token)
        Accept          = 'application/json'
    }

    $Parameters = @{
        Method      = 'DELETE'
        Header      = $Headers
        URI         = $URI.Uri
        ContentType = 'application/json'
        ErrorAction = 'silentlyContinue'
    }

    $Result = Invoke-RestMethod @Parameters

    if ($Result) {
        return $Result
    } else {
        $parameters
        throw '[ERROR] - '
    }
}
