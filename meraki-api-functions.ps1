## Meraki APIs
# https://developer.cisco.com/meraki/api-v1/introduction/

#region Helpers 
function NetworkHelper {
    [cmdletbinding()]
    param(
        $NetworkId,
        [ValidateSet('netflow','settings','snmp','alerts/settings','alerts/history')]
        $NetworkCommand,
        $Token
    )

    [System.UriBuilder]$URI = ('https://api.meraki.com/api/v1/networks/{0}/{1}' -f $NetworkId,$NetworkCommand)

    $Headers = @{
        Authorization = "Bearer $Token"
    }

    $RequestParameters = @{
        Method      = 'GET'
        Header      = $Headers
        URI         = $Uri.Uri
    }

    write-verbose $uri.uri

    $response = Invoke-WebRequest @RequestParameters

    if ($response.content) {
        return ($response.content | convertfrom-json)
    }
}
#endRegion

function Get-MerakiOrganizations {
    [cmdletbinding()]
    param(
        $Token
    )

    [System.UriBuilder]$URI = ('https://api.meraki.com/api/v1/organizations')

    $Headers = @{
        Authorization = "Bearer $Token"
    }

    $RequestParameters = @{
        Method      = 'GET'
        Header      = $Headers
        URI         = $Uri.Uri
    }

    write-verbose $uri.uri

    $response = Invoke-WebRequest @RequestParameters

    return ($response.content | convertfrom-json)
}

function Get-MerakiDevices {
    [cmdletbinding()]
    param(
        $OrganizationId,
        [ValidateSet("appliance", "camera", "campusGateway", "cellularGateway", "secureConnect", "sensor", "switch", "systemsManager", "wireless", "wirelessController")]
        [String[]]$ProductTypes,
        $Token
    )

    [System.UriBuilder]$URI = ('https://api.meraki.com/api/v1/organizations/{0}/inventory/devices' -f $OrganizationId)

    # Initialize an empty query string to build the request parameters
    $Query = [System.Web.HttpUtility]::ParseQueryString('')
    
    # Add start and end time filters if both are provided, converting to Unix timestamp
    foreach ($productType in $ProductTypes) {
        $query.Add('productTypes[]',$productType)
    }

    if ($Query.Tostring()) {
        $URI.query = $query.tostring()
    }

    $Headers = @{
        Authorization = "Bearer $Token"
    }

    $RequestParameters = @{
        Method      = 'GET'
        Header      = $Headers
        URI         = $Uri.Uri
    }

    write-verbose $uri.uri

    $response = Invoke-WebRequest @RequestParameters

    return ($response.content | convertfrom-json)
}

function Get-MerakiNetworks {
    [cmdletbinding()]
    param(
        $OrganizationId,
        [ValidateSet("appliance", "camera", "campusGateway", "cellularGateway", "secureConnect", "sensor", "switch", "systemsManager", "wireless", "wirelessController")]
        [String[]]$ProductTypes,
        $Token
    )

    [System.UriBuilder]$URI = ('https://api.meraki.com/api/v1/organizations/{0}/networks' -f $OrganizationId)

    # Initialize an empty query string to build the request parameters
    $Query = [System.Web.HttpUtility]::ParseQueryString('')
    
    # Add start and end time filters if both are provided, converting to Unix timestamp
    foreach ($productType in $ProductTypes) {
        $query.Add('productTypes[]',$productType)
    }

    if ($Query.Tostring()) {
        $URI.query = $query.tostring()
    }

    $Headers = @{
        Authorization = "Bearer $Token"
    }

    $RequestParameters = @{
        Method      = 'GET'
        Header      = $Headers
        URI         = $Uri.Uri
    }

    write-verbose $uri.uri

    $response = Invoke-WebRequest @RequestParameters

    return ($response.content | convertfrom-json)
}

function Get-MerakiNetwork {
    [cmdletbinding()]
    param(
        $OrganizationId,
        $NetworkId,
        $Token
    )

    [System.UriBuilder]$URI = ('https://api.meraki.com/api/v1/organizations/{0}/networks/{1}' -f $OrganizationId,$NetworkId)

    $Headers = @{
        Authorization = "Bearer $Token"
    }

    $RequestParameters = @{
        Method      = 'GET'
        Header      = $Headers
        URI         = $Uri.Uri
    }

    write-verbose $uri.uri

    $response = Invoke-WebRequest @RequestParameters

    return ($response.content | convertfrom-json)
}

function Get-MerakiNetworkFlow {
    [cmdletbinding()]
    param(
        $NetworkId,
        $Token
    )

    return (NetworkHelper -NetworkId $NetworkId -Token $Token -NetworkCommand netflow)
}

function Get-MerakiNetworkSettings {
    [cmdletbinding()]
    param(
        $NetworkId,
        $Token
    )

    return (NetworkHelper -NetworkId $NetworkId -Token $Token -NetworkCommand settings)
}

function Get-MerakiNetworkSNMP {
    [cmdletbinding()]
    param(
        $NetworkId,
        $Token
    )

    return (NetworkHelper -NetworkId $NetworkId -Token $Token -NetworkCommand snmp)
}

function Get-MerakiNetworkAlerts {
    [cmdletbinding()]
    param(
        $NetworkId,
        $Token
    )

    return (NetworkHelper -NetworkId $NetworkId -Token $Token -NetworkCommand alerts/settings)
}

function Get-MerakiNetworkAlertsHistory {
    [cmdletbinding()]
    param(
        $NetworkId,
        $Token
    )

    return (NetworkHelper -NetworkId $NetworkId -Token $Token -NetworkCommand alerts/history)
}

function Get-MerakiDeviceManagementInterface {
    [cmdletbinding()]
    param(
        $Token,
        $DeviceSerialNumber
    )

    [System.UriBuilder]$URI = ('https://api.meraki.com/api/v1/devices/{0}/managementInterface' -f $DeviceSerialNumber)

    $Headers = @{
        Authorization = "Bearer $Token"
    }

    $RequestParameters = @{
        Method      = 'GET'
        Header      = $Headers
        URI         = $Uri.Uri
    }

    write-host $uri.uri

    $response = Invoke-WebRequest @RequestParameters

    return ($response.content | convertfrom-json)
}

function Get-MerakiOrganizationPolicyObjects {
    [cmdletbinding()]
    param(
        $OrganizationId,
        $token
    )

    [System.UriBuilder]$URI = ('https://api.meraki.com/api/v1/organizations/{0}/policyObjects' -f $OrganizationId)

    $Headers = @{
        Authorization = "Bearer $Token"
    }

    $RequestParameters = @{
        Method      = 'GET'
        Header      = $Headers
        URI         = $Uri.Uri
    }

    write-verbose $uri.uri

    $response = Invoke-WebRequest @RequestParameters

    return ($response.content | convertfrom-json)
}