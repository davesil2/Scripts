#Region Helper Functions
function Set-TLSValidationBypass {
    if ($PSEdition -eq 'Desktop') {
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

        return $true
    } else {
        return $false
    }
}

function Invoke-OrionAPIQuery {
    param(
        [String]$OrionServer,
        [String]$OrionAPIPort,
        [pscredential]$SWISCredentials,
        [String]$Query
    )

    [System.UriBuilder]$URI = "https://$OrionServer`:$OrionAPIPort/Solarwinds/InformationService/v3/Json/Query?query=$Query"

    $Splat = @{
        Method = 'Get'
        URI = $URI.Uri
        Headers = @{
            Authorization = ("Basic {0}" -f [system.convert]::ToBase64String([text.encoding]::UTF8.GetBytes($SWISCredentials.username + ":" + $SWISCredentials.GetNetworkCredential().password)))
        }
        Verbose = $False
    }

    if (-Not (Set-TLSValidationBypass)) {
        #Add Skip Certificate Check to REST Variables
        $Splat += @{SkipCertificateCheck = $true}
    }

    $Response = Invoke-RestMethod @Splat

    return ($Response.Results)
}
#EndRegion

function Get-EntityFields {
    Param(
        [String]$OrionServer,
        [Int]$OrionAPIPort = 17774,
        [pscredential]$SWISCredentials,
        [String]$EntityName = 'Orion.Nodes'
    )

    #Build Query
    $Query = ("Select Name,Type,IsMetric,Units,MaxValue,MinValue,Values,IsNavigable,IsKey,IsNullable,IsInherited,IsInjected,IsSortable,GroupBy,FilterBy,CanCreate,CanRead,CanUpdate,Events,Summary,IsObsolete,ObsolescenceReason,IsInternal,EntityName,DisplayName,Description,InstanceType,Uri,InstanceSiteId from metadata.property where entityname='{0}'" -f $EntityName)

    $Response = Invoke-OrionAPIQuery `
        -OrionServer $OrionServer `
        -OrionAPIPort $OrionAPIPort `
        -SWISCredentials $SWISCredentials `
        -Query $Query `
        -ErrorAction SilentlyContinue

    Return $Response
}

Function Get-OrionNode {
    param(
        [String]$OrionServer,
        [Int]$OrionAPIPort = 17778,
        [pscredential]$SWISCredentials,
        [String]$HostName,
        [String]$IPAddress,
        [String]$NodeID,
        [String]$NodeURI,
        [switch]$ALL,
        [String[]]$Fields = @('NodeID','uri','caption')
    )

    $Query = ("Select {0} from Orion.Nodes" -f ($Fields -Join ','))

    if (-Not $ALL) {
        if ($HostName) {
            $Query += (" where Nodes.Caption='{0}'" -f $HostName)
        } elseif ($IPAddress) {
            $Query += (" where Nodes.IPAddress='{0}'" -f $IPAddress)
        } elseif ($NodeID) {
            $Query += (" where Nodes.NodeID='{0}'" -f $NodeID)
        } elseif ($NodeURI) {
            $Query += (" where Nodes.uri='{0}'" -f $NodeURI)
        } else {
            $Query = $null
        }
    }
    
    if ($Query) {
        $Response = Invoke-OrionAPIQuery `
            -OrionServer $OrionServer `
            -OrionAPIPort $OrionAPIPort `
            -SWISCredentials $SWISCredentials `
            -Query $Query `
            -ErrorAction SilentlyContinue

        Return $Response
    } else {
        Write-Error ("Invalid Query created [HOSTNAME: {0}] or [IPADDRESS: {1}]" -f $Hostname,$IPAddress)
    }
}

Function Get-OrionContainer {
    param(
        [String]$OrionServer,
        [Int]$OrionAPIPort = 17774,
        [pscredential]$SWISCredentials,
        [String]$ContainerName,
        [switch]$ALL,
        [String[]]$Fields = @('ContainerID','DisplayName','Description','Status','StatusDescription','uri')
    )

    $Query = ("Select {0} from Orion.Container" -f ($Fields -Join ','))

    if (-Not $ALL) {
        if ($ContainerName) {
            $Query += (" where Container.Name='{0}'" -f $ContainerName)
        } else {
            $Query = $null
        }
    }

    if ($Query) {
        $Response = Invoke-OrionAPIQuery `
            -OrionServer $OrionServer `
            -OrionAPIPort $OrionAPIPort `
            -SWISCredentials $SWISCredentials `
            -Query $Query `
            -ErrorAction SilentlyContinue

        Return $Response
    } else {
        Write-Error ("Invalid Query created [HOSTNAME: {0}] or [IPADDRESS: {1}]" -f $Hostname,$IPAddress)
    }
}

function Get-OrionContainerMembers {
    param(
        [String]$OrionServer,
        [Int]$OrionAPIPort = 17774,
        [pscredential]$SWISCredentials,
        [String]$ContainerName,
        [String]$ContainerId,
        [switch]$ALL,
        [String[]]$Fields = @('ContainerID','MemberPrimaryID','MemberEntityType','DisplayName','Description','MemberUri','uri')
    )

    $Query = ("Select {0} from Orion.ContainerMembers" -f ($Fields -Join ','))

    if (-Not $ALL) {
        if ($ContainerName) {
            $Query += (" where ContainerMembers.Name='{0}'" -f $ContainerName)
        } elseif ($ContainerId) {
            $Query += (" where ContainerMembers.ContainerID='{0}'" -f $ContainerId)
        }else {
            $Query = $null
        }
    }

    if ($Query) {
        $Response = Invoke-OrionAPIQuery `
            -OrionServer $OrionServer `
            -OrionAPIPort $OrionAPIPort `
            -SWISCredentials $SWISCredentials `
            -Query $Query `
            -ErrorAction SilentlyContinue

        Return $Response
    } else {
        Write-Error ("Invalid Query created [HOSTNAME: {0}] or [IPADDRESS: {1}]" -f $Hostname,$IPAddress)
    }
}

function Disable-OrionNodeAlerts {
    param(
        [String]$OrionServer,
        [Int]$OrionAPIPort = 17778,
        [pscredential]$SWISCredentials,
        [String[]]$HostURIs,
        [datetime]$BeginDate = (Get-Date),
        [datetime]$EndDate = (Get-Date).AddHours(4)
    )

    [System.UriBuilder]$URI = "https://$OrionServer`:$OrionAPIPort/Solarwinds/InformationService/v3/Json/Invoke/Orion.AlertSuppression/SuppressAlerts"

    $Body = [pscustomobject]@{
        entityUris = $HostURIs
        suppressFrom = ($BeginDate).ToUniversalTime()
        suppressUntil = ($EndDate).AddHours(1).ToUniversalTime()
    }

    $Headers = @{
        Authorization = ("Basic {0}" -f [system.convert]::ToBase64String([text.encoding]::UTF8.GetBytes($SWISCredentials.username + ":" + $SWISCredentials.GetNetworkCredential().password)))
    }

    $Splat = @{
        Method = 'Post'
        URI = $URI.Uri
        Credential = $SWISCredentials
        Headers = $Headers
        Verbose = $False
        Body = ($Body | ConvertTo-Json)
    }

    if (-Not (Set-TLSValidationBypass)) {
        #Add Skip Certificate Check to REST Variables
        $Splat += @{SkipCertificateCheck = $true}
    }

    $Response = Invoke-RestMethod @Splat

    Return $Response
}

function Find-OrionNodeInterfaces {
    Param(
        [String]$OrionServer,
        [Int]$OrionAPIPort = 17778,
        [pscredential]$SWISCredentials,
        [Int]$NodeID
    )

    [System.UriBuilder]$URI = "https://$OrionServer`:$OrionAPIPort/SolarWinds/InformationService/v3/Json/Invoke/Orion.NPM.Interfaces/DiscoverInterfacesOnNode"

    $Body = [pscustomobject]@{
        nodeId = $NodeID
    }

    $Splat = @{
        Method = 'Post'
        URI = $URI.Uri
        Credential = $SWISCredentials
        Headers = $Headers
        Verbose = $False
        Body = ($Body | ConvertTo-Json)
    }

    if (-Not (Set-TLSValidationBypass)) {
        #Add Skip Certificate Check to REST Variables
        $Splat += @{SkipCertificateCheck = $true}
    }

    $Response = Invoke-RestMethod @Splat

    return $Response.DiscoveredInterfaces | Where-Object {$_.InterfaceID -eq '0'}
}

function Add-OrionNodeInterfaces {
    Param(
        [String]$OrionServer,
        [Int]$OrionAPIPort = 17778,
        [pscredential]$SWISCredentials,
        [Int]$NodeID,
        [String[]]$Interfaces
    )

    [System.UriBuilder]$URI = "https://$OrionServer`:$OrionAPIPort/SolarWinds/InformationService/v3/Json/Invoke/Orion.NPM.Interfaces/AddInterfacesOnNode"

    $body = [pscustomobject]@{
        NodeID = $NodeID
        interfacesToAdd = $Interfaces
        pollers = 'AddDefaultPollers'
    }

    $Splat = @{
        Method = 'Post'
        URI = $URI.Uri
        Credential = $SWISCredentials
        Headers = $Headers
        Verbose = $False
        Body = ($Body | ConvertTo-Json)
        ContentType = 'applicaton/json'
    }

    if (-Not (Set-TLSValidationBypass)) {
        #Add Skip Certificate Check to REST Variables
        $Splat += @{SkipCertificateCheck = $true}
    }

    $Response = Invoke-RestMethod @Splant

    return $Response.DiscoveredInterfaces
}

function Get-OrionCredential {
    Param(
        [String]$OrionServer,
        [String]$OrionAPIPort = 17774,
        [pscredential]$SWISCredentials
    )

    $Query = "SELECT TOP 1000 ID, Name, Description, CredentialType, CredentialOwner, DisplayName, InstanceType, Uri, InstanceSiteId FROM Orion.Credential"
    
    $Response = Invoke-OrionAPIQuery `
        -OrionServer $OrionServer `
        -OrionAPIPort $OrionAPIPort `
        -SWISCredentials $SWISCredentials `
        -Query $Query `
        -ErrorAction SilentlyContinue

    return ($Response)
}

function Add-OrionNode {
    Param(
        [String]$OrionServer,
        [Int]$OrionAPIPort = 17778,
        [pscredential]$SWISCredentials,
        [Int]$PollerID,
        [String]$IPAddress,
        [Parameter(Mandatory)]
        [ValidateSet('WMI','SNMP')]
        [String]$MonitoringType = 'WMI',
        [Parameter(Mandatory)]
        [String]$NodeName
    )

    [System.UriBuilder]$URI = "https://$OrionServer`:$OrionAPIPort/Solarwinds/InformationService/v3/Json/Create/Orion.Nodes"

    $Body = [pscustomObject]@{
        EngineID = $PollerID
        IPAddress = $IPAddress
        ObjectSubType = $MonitoringType
        IsServer = '1'
        Caption = $NodeName
    }

    $Splat = @{
        Method = 'Post'
        URI = $URI.Uri
        Credential = $SWISCredentials
        Headers = $Headers
        Verbose = $False
        Body = ($Body | ConvertTo-Json)
        ContetType = 'application/json'
    }

    if (-Not (Set-TLSValidationBypass)) {
        #Add Skip Certificate Check to REST Variables
        $Splat += @{SkipCertificateCheck = $true}
    }

    $response = Invoke-RestMethod @Splat

    Return $Response
}

function Set-OrionNodeWMICredentials {
    Param(
        [String]$OrionServer,
        [Int]$OrionAPIPort = 17778,
        [pscredential]$SWISCredentials,
        [Int]$NodeID,
        [Int]$WMICredentialID
    )

    [System.URIBuilder]$URI = "https://$OrionServer`:$OrionAPIPort/SolarWinds/InformationService/v3/Json/Create/Orion.NodeSettings"

    $Body = [pscustomobject]@{
        NodeID = $NodeID
        SettingName = 'WMICredential'
        SettingValue = $WMICredentialID
    }

    $Splat = @{
        Method = 'Post'
        URI = $URI.Uri
        Credential = $SWISCredentials
        Headers = $Headers
        Verbose = $False
        Body = ($Body | ConvertTo-Json)
        ContentType = 'application/json'
    }

    if (-Not (Set-TLSValidationBypass)) {
        #Add Skip Certificate Check to REST Variables
        $Splat += @{SkipCertificateCheck = $true}
    }

    $response = Invoke-RestMethod @Splat

    Return $response
}

function Set-OrionNodePolling {
    param(
        [String]$OrionServer,
        [Int]$OrionAPIPort = 17778,
        [pscredential]$SWISCredentials,
        [validateset("N.Status.ICMP.Native","N.ResponseTime.ICMP.Native","N.Details.WMI.Vista","N.Uptime.WMI.XP","N.Cpu.WMI.Windows","N.Memory.WMI.Windows","N.AssetInventory.Wmi.Generic")]
        $PollingTypes = ("N.Status.ICMP.Native","N.ResponseTime.ICMP.Native","N.Details.WMI.Vista","N.Uptime.WMI.XP","N.Cpu.WMI.Windows","N.Memory.WMI.Windows","N.AssetInventory.Wmi.Generic"),
        $NodeID
    )

    [System.UriBuilder]$URI = "https://$OrionServer`:$OrionAPIPort/Solarwinds/InformationService/v3/Json/Create/Orion.Pollers"

    foreach ($PollingType in $PollingTypes) {
        $Body = [pscustomobject]@{
            NetObject = "N:$NodeID"
            NetObjectType = "N"
            NetObjectID = $NodeID
            PollerType = $PollingType
        }

        $Splat = @{
            Method = 'Post'
            URI = $URI.Uri
            Credential = $SWISCredentials
            Headers = $Headers
            Verbose = $False
            Body = ($Body | ConvertTo-Json)
            ContentType = 'application/json'
        }
    
        if (-Not (Set-TLSValidationBypass)) {
            #Add Skip Certificate Check to REST Variables
            $Splat += @{SkipCertificateCheck = $true}
        }

        Invoke-RestMethod @Splat
    }
}

function Get-OrionNodeSettings {
    param(
        [String]$OrionServer,
        [Int]$OrionAPIPort = 17778,
        [pscredential]$SWISCredentials,
        [Int]$NodeID
    )

    $Query = "SELECT NodeID, SettingName, SettingValue, NodeSettingID FROM Orion.NodeSettings where NodeID = '$NodeID'"
    
    $Response = Invoke-OrionAPIQuery `
        -OrionServer $OrionServer `
        -OrionAPIPort $OrionAPIPort `
        -SWISCredentials $SWISCredentials `
        -Query $Query `
        -ErrorAction SilentlyContinue
    
    return $Response
}

function Get-OrionPollers {
    param(
        [String]$OrionServer,
        [Int]$OrionAPIPort = 17778,
        [pscredential]$SWISCredentials,
        [Int]$NodeID
    )

    $Query = "SELECT PollerID, PollerType, NetObject, NetObjectType, NetObjectID, Enabled FROM Orion.Pollers WHERE NetObjectID = '$NodeID'"

    [System.UriBuilder]$URI = "https://$OrionServer`:$OrionAPIPort/Solarwinds/InformationService/v3/Json/Query?query=$Query"

    $Splat = @{
        Method = 'Get'
        URI = $URI.Uri
        Credential = $SWISCredentials
        Headers = $Headers
        Verbose = $False
    }

    if (-Not (Set-TLSValidationBypass)) {
        #Add Skip Certificate Check to REST Variables
        $Splat += @{SkipCertificateCheck = $true}
    }

    $Response = Invoke-RestMethod @Splat

    return ($Response.Results)
}

function Get-OrionPollingEngines {
    param(
        [String]$OrionServer,
        [Int]$OrionAPIPort = 17778,
        [pscredential]$SWISCredentials
    )

    $Query = "SELECT EngineID, ServerName, IP, ServerType, PrimaryServers, KeepAlive, FailOverActive, SysLogKeepAlive, TrapsKeepAlive, Restart, Elements, Nodes, Interfaces, Volumes, Pollers, MaxPollsPerSecond, MaxStatPollsPerSecond, NodePollInterval, InterfacePollInterval, VolumePollInterval, NodeStatPollInterval, InterfaceStatPollInterval, VolumeStatPollInterval, LicensedElements, SerialNumber, LicenseKey, StartTime, CompanyName, CustomerID, Evaluation, EvalDaysLeft, PackageName, EngineVersion, WindowsVersion, ServicePack, AvgCPUUtil, MemoryUtil, PollingCompletion, StatPollInterval, BusinessLayerPort, FIPSModeEnabled, MinutesSinceKeepAlive, MinutesSinceFailOverActive, MinutesSinceSysLogKeepAlive, MinutesSinceTrapsKeepAlive, MinutesSinceRestart, MinutesSinceStartTime, DisplayName, MasterEngineID, IsFree FROM Orion.Engines"

    $response = Invoke-OrionAPIQuery `
        -OrionServer $OrionServer `
        -OrionAPIPort $OrionAPIPort `
        -SWISCredentials $SWISCredentials `
        -Query $Query `
        -ErrorAction SilentlyContinue

    return ($Response)
}

function Start-OrionNodeResourceList {
    param(
        [String]$OrionServer,
        [string]$OrionAPIPort = 17778,
        [pscredential]$SWISCredentials,
        [String]$NodeID
    )

    [System.UriBuilder]$URI = "https://$OrionServer`:$OrionAPIPort/Solarwinds/InformationService/v3/Json/Invoke/Orion.Nodes/ScheduleListResources"

    $body = [pscustomobject]@{
        NodeID = $NodeID
    }

    $Splat = @{
        Method = 'Post'
        URI = $URI.Uri
        Credential = $SWISCredentials
        Headers = $Headers
        Verbose = $False
        Body = ($Body | ConvertTo-Json)
        ContentType = 'application/json'
    }

    if (-Not (Set-TLSValidationBypass)) {
        #Add Skip Certificate Check to REST Variables
        $Splat += @{SkipCertificateCheck = $true}
    }

    $Response = Invoke-RestMethod @Splat
    
    Return $Response
}

function Get-OrionNodeResourceDiscoveryStatus {
    param(
        [string]$OrionServer,
        [string]$OrionAPIPort = 17778,
        [pscredential]$SWISCredentials,
        [string]$NodeID,
        [string]$JobID
    )

    [System.UriBuilder]$URI = "https://$OrionServer`:$OrionAPIPort/Solarwinds/InformationService/v3/Json/Invoke/Orion.Nodes/GetScheduledListResourcesStatus"

    $body = [pscustomobject]@{
        NodeID = $NodeID
        JobID = $JobID
    }

    $Splat = @{
        Method = 'Post'
        URI = $URI.Uri
        Credential = $SWISCredentials
        Headers = $Headers
        Verbose = $False
        Body = ($Body | ConvertTo-Json)
        ContentType = 'application/json'
    }

    if (-Not (Set-TLSValidationBypass)) {
        #Add Skip Certificate Check to REST Variables
        $Splat += @{SkipCertificateCheck = $true}
    }

    $Response = Invoke-RestMethod @Splat
    
    Return $Response
}

function Import-OrionNodeResourceResult {
    param(
        [string]$OrionServer,
        [String]$OrionAPIPort = 17778,
        [pscredential]$SWISCredentials,
        [String]$NodeID,
        [String]$JobID
    )

    [System.UriBuilder]$URI = "https://$OrionServer`:$OrionAPIPort/Solarwinds/InformationService/v3/Json/Invoke/Orion.Nodes/ImportListResourcesResult"

    $body = [pscustomobject]@{
        NodeID = $NodeID
        JobID = $JobID
    }

    $Splat = @{
        Method = 'Post'
        URI = $URI.Uri
        Credential = $SWISCredentials
        Headers = $Headers
        Verbose = $False
        Body = ($Body | ConvertTo-Json)
        ContentType = 'application/json'
    }

    if (-Not (Set-TLSValidationBypass)) {
        #Add Skip Certificate Check to REST Variables
        $Splat += @{SkipCertificateCheck = $true}
    }

    $Response = Invoke-RestMethod @Splat
    
    Return $Response
}

function Get-OrionNodeVolumes {
    param(
        [String]$OrionServer,
        [String]$OrionAPIPort = 17778,
        [pscredential]$SWISCredentials,
        [String]$NodeID
    )

    $Query = ("SELECT NodeID, URI, Status, StatusLED, VolumeID, Icon, Index, Caption, PollInterval, StatCollection, RediscoveryInterval, StatusIcon, Type, Size, Responding, FullName, LastSync, VolumePercentUsed, VolumeAllocationFailuresThisHour, VolumeIndex, VolumeTypeID, VolumeType, VolumeDescription, VolumeSize, VolumeSpaceUsed, VolumeAllocationFailuresToday, VolumeResponding, VolumeSpaceAvailable, VolumeTypeIcon, OrionIdPrefix, OrionIdColumn, DiskQueueLength, DiskTransfer, DiskReads, DiskWrites, DisplayName, TotalDiskIOPS, VolumePercentAvailable, MinutesSinceLastSync, DetailsUrl, SkippedPollingCycles, VolumeSpaceAvailableExp, NextPoll, NextRediscovery, DeviceId, DiskSerialNumber, InterfaceType, SCSITargetId, SCSILunId, SCSIPortId, SCSIControllerId, SCSIPortOffset FROM Orion.Volumes WHERE NodeID = '{0}'" -f $NodeID)

    $Response = Invoke-OrionAPIQuery `
        -OrionServer $OrionServer `
        -OrionAPIPort $OrionAPIPort `
        -SWISCredentials $SWISCredentials `
        -Query $Query `
        -ErrorAction SilentlyContinue

    Return $Response
}

function Start-OrionNodePolling {
    param(
        [String]$OrionServer,
        [Int]$OrionAPIPort = 17774,
        [pscredential]$SWISCredentials,
        [String]$NodeID
    )

    [System.UriBuilder]$URI = "https://$OrionServer`:$OrionAPIPort/Solarwinds/InformationService/v3/Json/Invoke/Orion.Nodes/PollNow"

    $Body = [pscustomobject]@{
        netObjectId = "N:$NodeID"
    }

    $Splat = @{
        Method = 'Post'
        URI = $URI.Uri
        Credential = $SWISCredentials
        Headers = $Headers
        Verbose = $False
        Body = ($Body | ConvertTo-Json)
        ContentType = 'application/json'
    }

    if (-Not (Set-TLSValidationBypass)) {
        #Add Skip Certificate Check to REST Variables
        $Splat += @{SkipCertificateCheck = $true}
    }

    $Response = Invoke-RestMethod @Splat

    Return $Response
}

function Remove-OrionNodeVolume {
    param(
        [String]$OrionServer,
        [Int]$OrionAPIPort = 17778,
        [pscredential]$SWISCredentials,
        [String]$VolumeSWISUri
    )

    [System.UriBuilder]$URI = "https://$OrionServer`:$OrionAPIPort/Solarwinds/InformationService/v3/Json/$volumeswisuri"

    $Splat = @{
        Method = 'Delete'
        URI = $URI.Uri
        Credential = $SWISCredentials
        Headers = $Headers
        Verbose = $False
        Body = ($Body | ConvertTo-Json)
        ContentType = 'application/json'
    }

    if (-Not (Set-TLSValidationBypass)) {
        #Add Skip Certificate Check to REST Variables
        $Splat += @{SkipCertificateCheck = $true}
    }

    $Response = Invoke-RestMethod `
        -Method Delete `
        -URI $URI.Uri `
        -SkipCertificateCheck `
        -Credential $SWISCredentials `
        -ContentType 'application/json' `
        -Headers @{
            Authorization = ("Basic {0}" -f [system.convert]::ToBase64String([text.encoding]::UTF8.GetBytes($SWISCredentials.username + ":" + $SWISCredentials.GetNetworkCredential().password)))
        }

    return $Response
}

function Get-OrionNodeCustomProperties {
    param(
        [String]$OrionServer,
        [String]$OrionAPIPort = 17774,
        [pscredential]$SWISCredentials,
        [String]$NodeID
    )

    $Query = "SELECT NodeID, Address, AssetTag, BusinessUnit, City, Comments, Country, DevicePOrV, DeviceType, Environment, GroupSiteCode, InServiceDate, Latitude, LegacyCompanyName, Longitude, PONumber, PostalCode, PurchaseDate, PurchasePrice, Region, SerialNumber, SiteCode, SLA, State, ZipCode FROM Orion.NodesCustomProperties WHERE NodeID = '$NodeID'"

    $Response = Invoke-OrionAPIQuery `
        -OrionServer $OrionServer `
        -OrionAPIPort $OrionAPIPort `
        -SWISCredentials $SWISCredentials `
        -Query $Query `
        -ErrorAction SilentlyContinue

    return $Response
}

function Get-OrionNodeChildStatusDetail {
    param(
        [String]$OrionServer,
        [String]$OrionAPIPort = 17774,
        [pscredential]$SWISCredentials,
        [String]$NodeID
    )

    $Query = "SELECT NodeID, Name, EntityType, Status, StatusIcon, DetailsUrl, StatusRanking FROM Orion.NodeChildStatusDetail WHERE NodeID = '$NodeID'"

    $Response = Invoke-OrionAPIQuery `
        -OrionServer $OrionServer `
        -OrionAPIPort $OrionAPIPort `
        -SWISCredentials $SWISCredentials `
        -Query $Query `
        -ErrorAction SilentlyContinue

    return $Response
}