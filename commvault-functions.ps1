# Commvault API Functions
function New-CommVaultAPIToken {
    Param(
        [String]$FQDN,
        [String]$Username,
        [String]$password,
        [string]$CommServer,
        [string]$Domain,
        [switch]$ignoreCertErrors
    )

    [System.UriBuilder]$URI = ('https://{0}/webconsole/api/login' -f $FQDN)

    $Body = @{
        username    = $Username
        password    = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($password)"))
    }
    if ($CommServer) {
        $body += @{
            commserver = $CommServer
        }
    }
    if ($Domain) {
        $Body += @{
            domain = $Domain
        }
    }

    $Headers = @{
        accept = 'application/json'
    }

    $Parameters = @{
        URI                     = $URI.Uri
        Method                  = 'Post'
        Body                    = (ConvertTo-Json $Body)
        ContentType             = 'application/json'
        ErrorAction             = 'silentlyContinue'
        Headers                 = $Headers
    }

    if ($PSVersionTable.PSEdition -eq 'Core') {
        $Parameters += @{SkipCertificateCheck    = $ignoreCertErrors.ToBool()}
    } else {
        Invoke-Expression -Command 'class TrustAllCertsPolicy : System.Net.ICertificatePolicy {
            [bool] CheckValidationResult (
                [System.Net.ServicePoint]$srvPoint,
                [System.Security.Cryptography.X509Certificates.X509Certificate]$certificate,
                [System.Net.WebRequest]$request,
                [int]$certificateProblem
            ) {
                return $true
            }
        }
    
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName TrustAllCertsPolicy'
    }

    $result = Invoke-RestMethod @Parameters

    if ($result) {
        return $result
    } else {
        throw '[ERROR] - problem logging in with username, password and fqdn'
    }
}

function Get-CommVaultTapeStorageSystems {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$FQDN,
        [Parameter(Mandatory=$true)]
        [string]$APIToken,
        [Parameter(Mandatory=$true)]
        [switch]$ignoreCertErrors
    )

    [System.UriBuilder]$URI = ('https://{0}/webconsole/api/v4/Storage/Tape' -f $FQDN) 

    $Headers = @{
        accept = 'application/json'
        authorization = $APIToken
    }

    $Parameters = @{
        SkipCertificateCheck    = $ignoreCertErrors
        Method                  = 'Get'
        URI                     = $uri.Uri
        ErrorAction             = 'silentlycontinue'
        Headers                 = $Headers
    }

    $result = Invoke-RestMethod @Parameters

    if ($result) {
        return $result
    } else {
        throw '[ERROR] - error getting data'
    }
}

function Get-CommVaultTapeMediaSummary {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$FQDN,
        [Parameter(Mandatory=$true)]
        [string]$APIToken,
        [Parameter(Mandatory=$false)]
        [switch]$ignoreCertErrors,
        [Parameter(Mandatory=$true)]
        [string]$LibraryID
    )

    [System.UriBuilder]$URI = ('https://{0}/webconsole/api/v4/Storage/Tape/{1}/Media' -f $FQDN,$LibraryID) 

    $Headers = @{
        accept = 'application/json'
        authorization = $APIToken
    }

    $Parameters = @{
        SkipCertificateCheck    = $ignoreCertErrors
        Method                  = 'Get'
        URI                     = $uri.Uri
        ErrorAction             = 'silentlycontinue'
        Headers                 = $Headers
    }

    $result = Invoke-RestMethod @Parameters

    if ($result) {
        return $result
    } else {
        throw '[ERROR] - error getting data'
    }
}

function Get-CommVaultTapeLocations {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$FQDN,
        [Parameter(Mandatory=$true)]
        [string]$APIToken,
        [Parameter(Mandatory=$false)]
        [switch]$ignoreCertErrors
    )

    [System.UriBuilder]$URI = ('https://{0}/webconsole/api/v4/Storage/Tape/Locations' -f $FQDN) 

    $Headers = @{
        accept = 'application/json'
        authorization = $APIToken
    }

    $Parameters = @{
        SkipCertificateCheck    = $ignoreCertErrors
        Method                  = 'Get'
        URI                     = $uri.Uri
        ErrorAction             = 'silentlycontinue'
        Headers                 = $Headers
    }

    $result = Invoke-RestMethod @Parameters

    if ($result) {
        return $result
    } else {
        throw '[ERROR] - error getting data'
    }
}

function Get-CommVaultReportOutput {
    Param(
        [Parameter(Mandatory=$true)]
        $APIToken,
        [Parameter(Mandatory=$true)]
        [String]$ReportID,
        [Parameter(Mandatory=$true)]
        [String]$FQDN,
        [Parameter(Mandatory=$false)]
        [String]$QueryString,
        [Parameter(Mandatory=$false)]
        [switch]$ignoreCertErrors,
        [String]$TLSVersion = 'TLS12'
    )

    # set TLS version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::"$TLSVersion"
    
    # generate uri for generating token
    [System.UriBuilder]$URI = ('https://{0}/commandcenter/api/cr/reportsplusengine/datasets/{1}/data/' -f $FQDN,$ReportID)

    $URI.Query = $QueryString

    write-host $uri.uri

    $Headers = @{
        authtoken   = $APIToken
        accept      = 'application/json'
    }

    $Parameters = @{
        SkipCertificateCheck    = $ignoreCertErrors.ToBool()
        Method                  = 'Post'
        URI                     = $uri.Uri
        ErrorAction             = 'silentlycontinue'
        Headers                 = $Headers
    }

    $Result = Invoke-RestMethod @Parameters
    
    if ($Result) {
        return $Result
    }
}