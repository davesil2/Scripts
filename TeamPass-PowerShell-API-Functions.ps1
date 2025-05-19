
#Region Helper Functions
function Get-EncodedBase64String {
    Param(
        [string]$Inbound
    )
    
    Return ([System.Convert]::toBase64String([System.Text.Encoding]::UTF8.getbytes(($Inbound))))
}

function Get-DecodedBase64String {
    Param(
        [string]$Inbound
    )

    Return ([system.text.encoding]::UTF8.GetString([system.convert]::FromBase64String($Inbound)))
}
#EndRegion

# Teampass functions
function New-TeampassPassword {
    Param(
        [string]$TeampassFQDN,
        [string]$TeampassAPIKey,
        [int]$PasswordLength = 24,
        [switch]$PasswordSecure,
        [switch]$PasswordNumerals,
        [switch]$PasswordCapitals,
        [switch]$PasswordAmbiguous,
        [switch]$PasswordSymbols,
        [switch]$OutBase64String
    )
    $URIString = "https://$TeampassFQDN/api/index.php/new_password/$PasswordLength;"
    
    if ($PasswordSecure) {$URIString += "1;"} else {$URIString += "0;"}
    if ($PasswordNumerals) {$URIString += "1;"} else {$URIString += "0;"}
    if ($PasswordCapitals) {$URIString += "1;"} else {$URIString += "0;"}
    if ($PasswordAmbiguous) {$URIString += "1;"} else {$URIString += "0;"}
    if ($PasswordSymbols) {$URIString += "1;"} else {$URIString += "0;"}
    if ($OutBase64String) {$URIString += "1"} else {$URIString += "0"}
    
    [System.Uribuilder]$URI = $URIString + "?apikey=$TeampassAPIKey"

    write-host $uri.uri

    $Response = Invoke-RestMethod `
        -Method Get `
        -Uri $URI.Uri `
        -ContentType 'application/json'

    return $Response
}

function New-TeampassItem {
    Param(
        [string]$TeampassFQDN,
        [string]$TeampassAPIKey,
        [string]$Label,
        [string]$description,
        [string]$encodedPassword,
        [string]$FolderID,
        [string]$login,
        [string]$email,
        [string]$URL,
        [string]$Tags
    )
    
    $EncodedLabel = Get-EncodedBase64String $Label
    if ($Description) {$EncodedDescription = Get-EncodedBase64String $description} else {$EncodedDescription = $null}
    $EncodedFolderID = Get-EncodedBase64String $FolderID
    if ($Login) {$EncodedLogin = Get-EncodedBase64String $Login} else {$EncodedLogin = $null}
    if ($Email) {$EncodedEmail = Get-EncodedBase64String $Email} else {$EncodedEmail = $null}
    if ($URL) {$EncodedURL = Get-EncodedBase64String $URL} else {$EncodedURL = $null}
    if ($Tags) {$EncodedTags = Get-EncodedBase64String $Tags} else {$EncodedTags = $null}
    
    [System.UriBuilder]$URI = ("https://$TeampassFQDN/api/index.php/add/item/{0};{1};{2};{3};{4};{5};{6};{7};{8}?apikey={9}" -f $EncodedLabel,$encodedPassword,$EncodedDescription,$EncodedFolderID,$EncodedLogin,$EncodedEmail,$EncodedURL,$EncodedTags,0,$TeampassAPIKey)

    $Response = Invoke-RestMethod `
        -Method Get `
        -URI $URI.Uri

    Return $Response
}

function Find-TeamPassItem {
    Param(
        [string]$TeampassFQDN,
        [string]$TeampassAPIKey,
        [string]$SearchString
    )

    $FolderID = ((0..999) -join ';')

    $EncodedSearchString = Get-EncodedBase64String $SearchString

    [System.UriBuilder]$URI = ("https://$TeampassFQDN/api/index.php/find/item/{0}/{1}?apikey={2}" -f $FolderID,$SearchString,$TeampassAPIKey)

    return (Invoke-RestMethod `
        -Method Get `
        -URI $URI.Uri)

}

function Get-TeamPassFolder {
    Param(
        [string]$TeampassFQDN,
        [string]$TeampassAPIKey,
        [string]$FolderID = '0'
    )

    [System.UriBuilder]$URI = ("https://$TeampassFQDN/api/index.php/read/folder/{0}?apikey={1}" -f $FolderID,$TeampassAPIKey)
    
    return (Invoke-RestMethod `
        -Method Get `
        -URI $URI.Uri)
}

<#
.SYNOPSIS

.DESCRIPTION

.EXAMPLE

.PARAMETER TeampassFQDN

.PARAMETER APIKey

.PARAMETER ItemID

#>
function Get-TeampassItem {
    Param(
        [parameter(Mandatory=$true)]
        [string]$TeampassFQDN,
        [parameter(Mandatory=$true)]
        [string]$APIKey,
        [parameter(Mandatory=$true)]
        [string]$ItemID
    )

    [System.UriBuilder]$URI = ('https://{0}/api/index.php/read/items/{1}?apikey={2}' -f $TeampassFQDN,$ItemID,$APIKey)

    $parameters = @{
        Method      = 'GET'
        URI         = $URI.Uri
        ErrorAction = 'silentlyContinue'
        ContentType = 'application/json'
        Verbose     = $false
    }

    $result = Invoke-RestMethod @parameters

    if ($result) {
        return $result
    }
}