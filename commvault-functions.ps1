# Commvault API Functions
function New-CommVaultAPIToken {
    Param(
        [Parameter(Mandatory=$true)]
        [String]$FQDN,
        [Parameter(Mandatory=$true)]
        [String]$Username,
        [Parameter(Mandatory=$true)]
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

    $response = Invoke-RestMethod @Parameters

    if ($response) {
        return $response.token
    } else {
        throw '[ERROR] - problem logging in with username, password and fqdn'
    }
}

function Get-CommVaultReportOutput {
    Param(
        [Parameter(Mandatory=$true)]
        [String]$Token,
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

    $Headers = @{
        authtoken   = $APIToken
        accept      = 'application/json'
    }

    $Parameters = @{
        Method                  = 'Post'
        URI                     = $uri.Uri
        ErrorAction             = 'silentlycontinue'
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

    $response = Invoke-RestMethod @Parameters
    
    if ($response) {
        return $response
    }
}

function Get-CommVaultLibraries {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$FQDN,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [Parameter(Mandatory=$false)]
        [switch]$ignoreCertErrors
    )

    [System.UriBuilder]$URI = ('https://{0}/webconsole/api/Library' -f $FQDN) 

    $Headers = @{
        accept          = 'application/json'
        authorization   = $Token
    }

    $Parameters = @{
        Method          = 'Get'
        URI             = $uri.Uri
        ErrorAction     = 'silentlycontinue'
        Headers         = $Headers
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

    $response = Invoke-RestMethod @parameters
    
    if ($Response) {
        return $response.response.entityinfo
    }
}

function Get-CommvaultTapeLocations{
    param(
        [Parameter(Mandatory=$true)]
        [String]$FQDN,
        [Parameter(Mandatory=$true)]
        [String]$Token,
        [Parameter(Mandatory=$true)]
        [String]$LibraryID,
        [switch]$ignoreCertErrors
    )

    [System.UriBuilder]$URI = ('https://{0}/webconsole/api/LibraryOperations' -f $FQDN)

    $Headers = @{
        accept          = 'application/json'
        authorization   = $Token
        'content-type'  = 'application/xml'
    }

    $body = ('<TMMsg_LibraryOperationRequest LibraryId="{0}" libraryOperationType="{1}"/>' -f $LibraryId,23)

    $Parameters = @{
        Method                  = 'POST'
        URI                     = $uri.Uri
        ErrorAction             = 'silentlycontinue'
        Headers                 = $Headers
        Body                    = $body
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

    $response = Invoke-RestMethod @parameters

    if ($response) {
        return $response.exportOptions.exportLocations
    }
}

function Get-CommvaultTapeDetails{
    param(
        [Parameter(Mandatory=$true)]
        [String]$FQDN,
        [Parameter(Mandatory=$true)]
        [String]$Token,
        [Parameter(Mandatory=$true)]
        [String]$LibraryID,
        [switch]$ignoreCertErrors
    )

    [System.UriBuilder]$URI = ('https://{0}/webconsole/api/LibraryOperations' -f $FQDN)

    $Headers = @{
        accept          = 'application/json'
        authorization   = $Token
        'content-type'  = 'application/xml'
    }

    $body = ('<TMMsg_LibraryOperationRequest LibraryId="{0}" libraryOperationType="{1}"/>' -f $LibraryId,23)

    $Parameters = @{
        Method                  = 'POST'
        URI                     = $uri.Uri
        ErrorAction             = 'silentlycontinue'
        Headers                 = $Headers
        Body                    = $body
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

    write-verbose ($parameters | convertto-json -depth 5)

    $response = Invoke-RestMethod @parameters

    if ($response) {
        return $response.exportOptions.mediaDetails | select-object mediaId,barCode,@{name='lastwritetime';e={[System.DateTimeOffset]::FromUnixTimeSeconds($_.lastwritetime).DateTime}},sizeOfStoredData,@{name='retainDataUntil';e={[System.DateTimeOffset]::FromUnixTimeSeconds($_.retainDataUntil).DateTime}},status,Location,@{name='storagePolicy';e={$_.storagePolicy.name}},@{Name='StoragePolicyCopy';E={$_.storagepolicycopy.name}},@{n='mediagroup';e={$_.mediagroup.name}}
    }
}

function Export-CommvaultTapeToSite {
    param(
        [Parameter(Mandatory=$true)]
        [String]$FQDN,
        [Parameter(Mandatory=$true)]
        [String]$Token,
        [Parameter(Mandatory=$true)]
        [String]$LibraryID,
        [Parameter(Mandatory=$true)]
        [String]$MediaID,
        [Parameter(Mandatory=$true)]
        [String]$MediaLocationName,
        [switch]$ignoreCertErrors
    )

    [System.UriBuilder]$URI = ('https://{0}/webconsole/api/LibraryOperations' -f $FQDN) 

    $Headers = @{
        accept          = 'application/json'
        authorization   = $APIToken
        'content-type'  = 'application/xml'
    }

    $body = ('<TMMsg_LibraryOperationRequest LibraryId="{0}" libraryOperationType="24"><exportOptions><mediaDetails mediaId="{1}"/><exportLocations name="{2}"/></exportOptions></TMMsg_LibraryOperationRequest>' -f $LibraryID,$MediaID,$MediaLocationName)

    $Parameters = @{
        Method                  = 'POST'
        URI                     = $uri.Uri
        ErrorAction             = 'silentlycontinue'
        Headers                 = $Headers
        Body                    = $body
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

    $response = Invoke-RestMethod @Parameters

    if ($response) {
        return $response
    }
}