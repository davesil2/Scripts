<#
    10.7.2019 - DHS - Initial Commit with limited testing/validation

    Functions intended to be used in conjuction to create new VMs.

        1.) New-VMfromTemplate
        2.) Add-VMtoDomain
        3.) Add-DisktoVM

    New-VMfromTemplate
        * Use Help for Examples and Pre-Req's

    Add-VMtoDomain
        * Use Help for Examples and Pre-Req's

    Add-DisktoVM
        * Use Help for Examples and Pre-Req's

    Additional Functions for Post VM creation are below.

        New-SSLCertificate

#>

# Add Helper Functions
Invoke-Expression (
    (
        Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/davesil2/Scripts/master/Global%20Functions.ps1'
    ).content -join [environment]::newline
)

function New-VMfromTemplate {
    [CmdletBinding()]
    param(
        # vCenter Server Fully Qualified Domain Name
        [parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true
        )]
        [Alias('vCenterServer')]
        [string]
        $vCenterFQDN,

        # Credentials to connect to vCenter
        [parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [Alias('vCenterCredential')]
        [PSCredential]
        $vCenterCreds,

        # Cluster or Host to create VM on
        [parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true
        )]
        [Alias('Cluster','ClusterName')]
        [string]
        $vCenterCluster,

        # Folder under VM and Template to create VM
        [parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [Alias('Folder')]
        [string]
        $vCenterFolder,

        # Name of vCenter Template
        [parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true
        )]
        [Alias('Template')]
        [string]
        $vCenterTemplate,

        # Datastore or Datastore cluster to create VM on
        [parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true
        )]
        [Alias('DataStore','vCenterDataStoreCluster','DataStoreCluster')]
        [string]
        $vCenterDataStore,

        # Port Group Name to assign to VM (Default is is the CIDR notation + *)
        [parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [Alias('PortGroup')]
        [string]
        $vCenterPortGroup,

        # Customization Spec to use for VM
        [parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true
        )]
        [Alias('CustomizationSpec')]
        [string]
        $vCenterCustomizationSpec,

        # Allocation of Space Type to use on Datastore (thick or thin)
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [ValidateSet('Thin','Thick')]
        [ValidateNotNullorEmpty()]
        [string]
        $vCenterDiskType = 'Thin',

        # Name of Server and VM to create
        [parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true
        )]
        [Alias('ComputerName','Name','HostName','cn','Server')]
        [ValidateLength(3,15)]
        [string]
        $ServerName,

        # vCenter Attribute to assign for Server Purpose (goes to notes if attribute doesn't exist)
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [Alias('Purpose')]
        [string]
        $ServerPurpose,

        # vCenter Attribute to assign for Server Team Owner (goes to notes if attribute doesn't exist)
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [Alias('TeamOwner')]
        [string]
        $ServerTeamOwner,

        # IP Address to assign to Server in CIDR Notation (x.x.x.x/x)
        [parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            ParameterSetName='CIDR'
        )]
        [Alias('CIDR')]
        [string]
        $ServerIPAddressCIDR,

        # IP Address
        [Parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            ParameterSetName='IP'
        )]
        [Alias('IP','IPAddress')]
        [string]
        $ServerIPAddress,

        # Subnet for IP address (calculated by CIDR Notation)
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true,
            ParameterSetName='CIDR'
        )]
        [Parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            ParameterSetName='IP'
        )]
        [Alias('Subnet')]
        [string]
        $ServerIPSubnet,

        # Calculated by CIDR Notation assuming .1
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [ValidateNotNullorEmpty()]
        [Alias('Gateway')]
        [string]
        $ServerIPGateway,

        # DNS Servers to Assign to Server (get's local client DNS Servers by default)
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [ValidateNotNullorEmpty()]
        [string[]]
        $ServerDNSServers = ((Get-WmiObject win32_networkadapterconfiguration | Where-Object{$_.ipaddress -and $_.servicename -notlike 'msloop'}).dnsserversearchorder),

        # Number of CPU's to assign to VM (default = 2)
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [ValidateNotNullorEmpty()]
        [Alias('CPUCount','NumCPU')]
        [int]
        $ServerNumberofCPUs = 2,

        # Server Memory in GB to Assign to VM (default = 4)
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [ValidateNotNullorEmpty()]
        [Alias('Memory')]
        [int]
        $ServerMemoryGB = 4,

        # Option to start VM after it's created (default = true)
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [boolean]
        $StartVMAfterCreation = $true,

        # Attributes written to VM Notes Field when attributes do not exist (default = true)
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [boolean]
        $AttributestoNotesWhenMissing = $true,

        # Show the Configuration Summary when creating VM (default = true)
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [Switch]
        $ShowConfigurationSummary
    )

    #region Validate Input from Function
    #region vCenter Validation
    $_vCenter = $global:DefaultVIServers | Where-Object{$_.name -eq $vCenterFQDN -and $_.isconnected -eq 'True'}
    if (-Not $_vCenter) {
        if ($global:DefaultVIServers.Count -gt 0) {
            VMware.VimAutomation.Core\Disconnect-VIServer -Force -Server * -ErrorAction SilentlyContinue -Confirm:$false -Verbose:$false

            Write-Verbose ('{0}: Disconnected form Existing vCenters' -f (get-date).tostring())
        }
        try{
            if ($vCenterCreds) {
                $_vCenter = VMware.VimAutomation.Core\Connect-VIServer -Server $vCenterFQDN -Credential $vCenterCreds -Force -Verbose:$false
            } else {
                $_vCenter = VMware.VimAutomation.Core\Connect-VIServer -Server $vCenterFQDN -Force -Verbose:$false
            }
        } catch {
            Write-Error ('A Problem occured connecting to vCenter!') -ErrorAction Stop
        }
    }
    if (-Not $_vCenter) {
        Write-Error ('No vCenter Connection!') -ErrorAction Stop
    }
    Write-Verbose ('{0}: VALIDATED - vCenter "{1}" connection established as "{2}"' -f (get-date).tostring(),$_vCenter.Name, $_vCenter.User)
    #endregion

    #region Server does not exist already
    if (VMware.VimAutomation.Core\Get-VM $ServerName -ErrorAction SilentlyContinue -Verbose:$false) {
        Write-Error ('VM already exists with that name!') -ErrorAction Stop
    }
    Write-Verbose ('{0}: VALIDATED - VM "{1}" not found in vCenter "{2}"' -f (get-date).ToString(),$ServerName,$_vCenter.Name)
    #endregion

    #region Datastore/Cluster Valiation
    $DatastoreClusters = VMware.VimAutomation.Core\Get-DatastoreCluster -Verbose:$false -ErrorAction SilentlyContinue
    $Datastores = VMware.VimAutomation.Core\Get-Datastore -Verbose:$false -ErrorAction SilentlyContinue
    if ($DatastoreClusters) {
        $_Datastore = $DatastoreClusters | Where-Object {$_.Name -like $vCenterDataStore}
    }
    if ($Datastores -and -Not $_Datastore) {
        $_Datastore = $Datastores | Where-Object {$_.Name -like $vCenterDataStore}
    }
    if (-Not $_Datastore) {
        Write-Error ('No matching datastore found!') -ErrorAction Stop
    }
    if ($_Datastore.Count -ne 1) {
        Write-Error ('More than one matching datastore found!') -ErrorAction Stop
    }
    Write-Verbose ('{0}: VALIDATED - Datastore "{1}" found on vCenter "{2}"' -f (get-date).ToString(),$_Datastore.Name,$_vCenter.Name)
    #endregion
    
    #region VMHost/Cluster Validation
    $VMClusters = VMware.VimAutomation.Core\Get-Cluster -Verbose:$false
    $VMHosts = VMware.VimAutomation.Core\Get-VMHost -Verbose:$false
    if ($VMClusters) {
        $_VMHost = $VMClusters | Where-Object {$_.Name -like $vCenterCluster}
    }
    if ($VMhosts -and -Not $_VMHost) {
        $_VMHost = $VMHosts | Where-Object {$_.Name -like $vCenterCluster}
    }
    if (-Not $_VMHost) {
        Write-Error ('No matching placement for VM to hosts!') -ErrorAction Stop
    }
    if ($_VMHost.Count -ne 1) {
        Write-Error ('Found more than one host/cluster for placement!') -ErrorAction Stop
    }
    Write-Verbose ('{0}: VALIDATED - Placement Resource "{1}" found on vCenter "{2}"' -f (get-date).ToString(),$_VMHost.Name,$_vCenter.Name)
    #endregion

    #region Template Validation
    $Templates = VMware.VimAutomation.Core\Get-Template -Verbose:$false
    if ($Templates){
        $_Template = $Templates | Where-Object {$_.Name -like $vCenterTemplate}
    }
    if (-Not $_Template) {
        Write-Error ('No matching template found') -ErrorAction Stop
    }
    if ($_Template.Count -ne 1) {
        Write-Error ('Found more than one matching template!') -ErrorAction Stop
    }
    Write-Verbose ('{0}: VALIDATED - Template "{1}" found on vCenter "{2}"' -f (get-date).ToString(),$_Template.Name,$_vCenter.Name)
    #endregion

    #region VM Folder Validation
    if ($vCenterFolder) {
        $_VMFolder = VMware.VimAutomation.Core\Get-Folder $vCenterFolder -Verbose:$false -ErrorAction SilentlyContinue
    }
    if (-Not $_VMFolder) {
        Write-Warning ('VM Folder not Found!') -ErrorAction Stop
    }
    if ($_VMFolder.Count -gt 1) {
        Write-Error ('More than one matching folder found!') -ErrorAction Stop
    }
    Write-Verbose ('{0}: VALIDATED - Folder "{1}" found on vCenter "{2}"' -f (get-date).ToString(),$_VMFolder.Name,$_vCenter.Name)
    #endregion

    #region Customization Spec Validation
    $_CustomizationSpec = VMware.VimAutomation.Core\Get-OSCustomizationSpec -Name $vCenterCustomizationSpec -Verbose:$false
    if (-Not $_CustomizationSpec) {
        Write-Error ('no customization specs found!') -ErrorAction Stop
    }
    if ($_CustomizationSpec.count -ne 1) {
        Write-Error ('more than one matching customization spec found!') -ErrorAction Stop
    }
    if ($_Template.ExtensionData.Config.GuestFullName -notlike ('*{0}*' -f $_CustomizationSpec.OSType)) {
        Write-Error ('Customization Spec OS Type does not match Template!') -ErrorAction Stop
    }
    Write-Verbose ('{0}: VALIDATED - Customization Spec "{1}" found on vCenter "{2}"' -f (get-date).ToString(),$_CustomizationSpec.Name,$_vCenter.Name)
    #endregion

    #region Check for custom attributes
    $Attributes = VMware.VimAutomation.Core\Get-CustomAttribute -Verbose:$false -ErrorAction SilentlyContinue
    if ($Attributes) {
        if ($Attributes | Where-Object {$_.name -like 'Created By'}) {
            Write-Warning ('Created By Attribute Not Found!')
        }
        if ($Attributes | Where-Object {$_.name -like 'Created Date'}) {
            Write-Warning ('Created Date Attribute Not Found!')
        }
        if ($Attributes | Where-Object {$_.name -like 'Purpose'}) {
            Write-Warning ('Purpose Attribute Not Found!')
        }
        if ($Attributes | Where-Object {$_.name -like 'Team Owner'}) {
            Write-Warning ('Team Owner Attribute Not Found!')
        }
    } else {
        Write-Warning ('No Attributes Founs!')
    }
    #endregion

    #region IP Address Validation
    if ($ServerIPAddressCIDR) {
        $_NetworkInfo = Get-IPNetworkInfo -IPAddress $ServerIPAddressCIDR.Split('/')[0] -CIDR $ServerIPAddressCIDR.Split('/')[1]
    } else {
        $_NetworkInfo = Get-IPNetworkInfo -IPAddress $ServerIPAddress -SubnetMask $ServerIPSubnet
    }
    $_IPAddress = $_NetworkInfo.IPAddress
    $_IPSubnet = $_NetworkInfo.SubnetMask
    if (-Not $ServerIPGateway) {
        $_IPGateway = $_NetworkInfo.NetworkStartAddress
    } else {
        $_IPGateway = $ServerIPGateway
    }

    # Verify IP is not Pingable
    if ((New-Object system.net.networkinformation.ping).send($_IPAddress).Status -eq 'Success') {
        Write-Error ('IP address is responding to Ping already') -ErrorAction Stop
    }

    try {
        # Verify IP Doesn't resolve in reverse lookup
        $result = $null
        $result = [net.dns]::GetHostByAddress($_IPAddress)
    } catch {}
    finally {    
        if ($result) {
            Write-Error ('IP Address currently resolves to an existing name, may be in use!') -ErrorAction Stop
        }
    }
    Write-Verbose ('{0}: VALIDATED - IPAddress "{1}" with subnet "{2}" and gateway "{3}" ready to use for server "{4}"' -f (get-date).ToString(),$_IPAddress,$_IPSubnet,$_IPGateway,$ServerName)
    #endregion

    #region Switch Portgroup Validation
    if (-Not $vCenterPortGroup) {
        $vCenterPortGroup = ($_NetworkInfo.Network + '*')
    }
    # Get Portgroups
    if ($_VMHost.GetType().name -notlike '*host*') {
        $PortGroups = $_VMHost | VMware.VimAutomation.Core\Get-VMHost -Verbose:$false | Select-Object -First 1 | VMware.VimAutomation.Core\Get-VirtualPortGroup -Verbose:$false
    } else {
        $PortGroups = $_VMHost | VMware.VimAutomation.Core\Get-VirtualPortGroup -Verbose:$false
    }

    # Find Portgroup in vCenter that matches IP network
    if ($PortGroups) {
        $_PortGroup = $PortGroups | Where-Object {$_.name -like $vCenterPortGroup}
    }

    if (-Not $_PortGroup) {
        Write-Error ('No matching port groups found') -ErrorAction Stop
    }

    if ($_PortGroup.Count -ne 1) {
        Write-Error ('More than one port group found!') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - Porgroup "{1}" found on vCenter "{2}"' -f (get-date).ToString(),$_PortGroup.Name,$_vCenter.Name)
    #endregion

    #region Datastore Usage Validation
    if ($vCenterDiskType -eq 'Thin') {
        $SpaceUsage = [math]::round($_Template.ExtensionData.Summary.Storage.Committed/1Gb)
    } else {
        $SpaceUsage = [math]::round(($_Template.ExtensionData.Summary.Storage.Committed + $_Template.ExtensionData.Summary.Storage.Uncommitted)/1Gb)
    }
    if (($_datastore.CapacityGB - $_datastore.FreeSpaceGB) -gt ($_datastore.CapacityGB *.95)) {
        Write-Error ('Datastore using greater than 95% of datastore!') -ErrorAction Stop
    }
    if (($_datastore.CapacityGB - $_datastore.FreeSpaceGB) -gt ($_datastore.CapacityGB *.8)) {
        Write-Warning ('Datastore using greater than 80% of datastore!') -ErrorAction Stop
    }
    if (($_datastore.CapacityGB - $_datastore.FreeSpaceGB + $SpaceUsage) -gt ($_datastore.CapacityGB *.95)) {
        Write-Error ('Datastore Usage with VM will be greater than 95%!') -ErrorAction Stop
    }
    Write-Verbose ('{0}: VALIDATED - Datastore "{1}" has "{2}" GB Free and ready to create VM with "{3}" GB using "{4}" provisioning' -f (get-date).ToString(),$_Datastore.Name,$_Datastore.FreeSpaceGB,$ServerName,$SpaceUsage)
    #endregion

    #endregion

    #region Summarize and Create VM

    #region Summarize Configuration
    $SummaryTable = (
        [pscustomobject]@{ConfigItem='vCenter Server';OriginalValue=$vCenterFQDN;ValidatedValue=$_vCenter.Name;},
        [pscustomobject]@{ConfigItem='vCenter Credentials';OriginalValue=$vCenterCreds.UserName;ValidatedValue=$_vCenter.User;},
        [pscustomobject]@{ConfigItem='vCenter Cluster/Host';OriginalValue=$vCenterCluster;ValidatedValue=$_VMHost.Name},
        [pscustomobject]@{ConfigItem='vCenter Folder Placement';OriginalValue=$vCenterFolder;ValidatedValue=$_VMFolder.Name},
        [pscustomobject]@{ConfigItem='vCenter Template';OriginalValue=$vCenterTemplate;ValidatedValue=$_Template.Name},
        [pscustomobject]@{ConfigItem='vCenter DataStore/Cluster';OriginalValue=$vCenterDataStore;ValidatedValue=$_Datastore.Name},
        [pscustomobject]@{ConfigItem='vCenter Port Group';OriginalValue=$vCenterPortGroup;ValidatedValue=$_PortGroup.Name},
        [pscustomobject]@{ConfigItem='vCenter Customization Spec';OriginalValue=$vCenterCustomizationSpec;ValidatedValue=$_CustomizationSpec.Name},
        [pscustomobject]@{ConfigItem='vCenter Datastore Disk Type';OriginalValue=$vCenterDiskType;ValidatedValue=$vCenterDiskType},
        [pscustomobject]@{ConfigItem='Server Name';OriginalValue=$ServerName;ValidatedValue=$ServerName},
        [pscustomobject]@{ConfigItem='Server Purpose';OriginalValue=$ServerPurpose;ValidatedValue=$ServerPurpose},
        [pscustomobject]@{ConfigItem='Server Team Owner';OriginalValue=$ServerTeamOwner;ValidatedValue=$ServerTeamOwner},
        [pscustomobject]@{ConfigItem='Server IP Address/CIDR';OriginalValue=$ServerIPAddressCIDR;ValidatedValue=$_IPAddress},
        [pscustomobject]@{ConfigItem='Server IP Subnet';OriginalValue=$ServerIPSubnet;ValidatedValue=$_IPSubnet},
        [pscustomobject]@{ConfigItem='Server IP Gateway';OriginalValue=$ServerIPGateway;ValidatedValue=$_IPGateway}
    )
    
    if ($ShowConfigurationSummary) {
        $SummaryTable | Select-Object ConfigItem,OriginalValue,ValidatedValue
    } else {
        (
            $SummaryTable | Select-Object ConfigItem,OriginalValue,ValidatedValue | Out-String
        ).split([environment]::newline) | where-object {$_} | foreach-object {
            Write-Verbose ("{0}:`t`t{1}" -f (get-date).ToString(),$_)
        }
    }
    #endregion

    #region Configure Customization Spec
    $_CustomSpecNic = $_CustomizationSpec | VMware.VimAutomation.Core\Get-OSCustomizationNicMapping -Verbose:$false
    if ($_CustomizationSpec.OSType -like '*windows*') {
        $_CustomSpecNic | VMware.VimAutomation.Core\Set-OSCustomizationNicMapping `
            -IpMode UseStaticIP `
            -IpAddress $_IPAddress `
            -SubnetMask $_IPSubnet `
            -DefaultGateway $_IPGateway `
            -Dns $ServerDNSServers `
            -Verbose:$false | Out-Null
    } else {
        $_CustomSpecNic | VMware.VimAutomation.Core\Set-OSCustomizationNicMapping `
            -IpMode UseStaticIP `
            -IpAddress $_IPAddress `
            -SubnetMask $_IPSubnet `
            -DefaultGateway $_IPGateway `
            -Verbose:$false | Out-Null
    }
    Write-Verbose ('{0}: Customization Spec [{1}] Configured - (IP Address: [{2}] - Subnet Mask: [{3}] - Gateway: [{4}])' -f (get-date).ToString(), $_CustomizationSpec,$_IPAddress,$_IPSubnet,$_IPGateway)
    #endregion

    #region Create VM
    if ($_VMFolder) {
        VMware.VimAutomation.Core\New-VM `
            -ResourcePool $_VMHost.Name `
            -Name $ServerName `
            -Location $_VMFolder `
            -Template $_Template `
            -OSCustomizationSpec $_CustomizationSpec `
            -DiskStorageFormat $vCenterDiskType `
            -Datastore $_Datastore.Name `
            -Verbose:$false `
            -ErrorAction SilentlyContinue
    } else {
        VMware.VimAutomation.Core\New-VM `
            -ResourcePool $_VMHost.Name `
            -Name $ServerName `
            -Template $_Template `
            -OSCustomizationSpec $_CustomizationSpec `
            -DiskStorageFormat $vCenterDiskType `
            -Datastore $_Datastore.Name `
            -Verbose:$false `
            -ErrorAction SilentlyContinue
    }

    Write-Verbose ('{0}: VM [{1}] Created!' -f (get-date).ToString(),$ServerName)

    $_VM = VMware.VimAutomation.Core\Get-VM $ServerName -Verbose:$false
    $_VM | VMware.VimAutomation.Core\Set-VM `
        -NumCPU $ServerNumberofCPUs `
        -MemoryGB $ServerMemoryGB `
        -Confirm:$false `
        -Verbose:$false `
        -ErrorAction SilentlyContinue | Out-Null
    Write-Verbose ('{0}: Updated VM "{1}" CPU to "{2}" and Memory to "{3}"' -f (get-date).ToString(),$_VM.Name,$ServerNumberofCPUs,$ServerMemoryGB)
    
    $_VM | VMware.VimAutomation.Core\Get-NetworkAdapter -Verbose:$false | VMware.VimAutomation.Core\Set-NetworkAdapter -Portgroup $_PortGroup.Name -Confirm:$false -Verbose:$false | Out-Null
    Write-Verbose ('{0}: Updated VM "{1}" network adapter to port group "{2}"' -f (get-date).ToString(),$_VM.Name,$_PortGroup.Name)

    if ($StartVMAfterCreation) {
        $_VM | VMware.VimAutomation.Core\Start-VM -Verbose:$false | Out-Null

        Write-Verbose ('{0}: VM "{1}" started...' -f (get-date).ToString(),$_VM.Name)

        While (
            -Not (
                VMware.VimAutomation.Core\Get-VIEvent `
                    -Entity $_VM `
                    -Verbose:$false `
                    -ErrorAction SilentlyContinue | Where-Object {
                        $_.fullformattedmessage -like '*customization*' -and $_.fullformattedmessage -like '*succeeded*'
                    }
                )
            ) {
            Write-Verbose ("`t`tWaiting for VM Customization to Complete...")
            Start-Sleep 10
        }
        Write-Verbose ('{0}: Customization on VM "{1}" completed!' -f (get-date).ToString(),$_VM.Name)
    }
    #endregion
    
    #region Configure Annotation/Notes for VM
    $_Notes = $_VM.Notes

    # Create Array and set Values or notes
    (
        [PSCustomObject]@{Attribute = 'Created By';     AttribValue = $_vCenter.User.Split('\') | Select-Object -Last 1;},
        [PSCustomObject]@{Attribute = 'Created Date';   AttribValue = (get-date).ToString();},
        [PSCustomObject]@{Attribute = 'Purpose';        AttribValue = $ServerPurpose;},
        [PSCustomObject]@{Attribute = 'Team Owner';     AttribValue = $ServerTeamOwner;}
    ) | ForEach-Object {
        if ($_VM | VMware.VimAutomation.Core\Get-Annotation -CustomAttribute $_.Attribute -ErrorAction SilentlyContinue -Verbose:$false) {
            $_VM | VMware.VimAutomation.Core\Set-Annotation `
                -CustomAttribute $_.Attribute `
                -Value $_.AttribValue `
                -ErrorAction SilentlyContinue `
                -Verbose:$false | Out-Null

            Write-Verbose ('{0}: Set Attribute [{1}] to [{2}] - VM: [{3}]' -f (get-date).tostring(),$_.Attribute,$_.AttribValue,$_VM.Name)
        } else {
            if ($_notes) {
                $_Notes += [System.Environment]::NewLine
            }
            $_Notes += ("{0}:`t{1}" -f $_.Attribute,$_.AttribValue)
        }
    }
    
    # Set Notes if appropriate
    if ($AttributestoNotesWhenMissing) {
        $_VM | VMware.VimAutomation.Core\Set-VM `
            -Notes $_Notes `
            -Confirm:$false `
            -Verbose:$false `
            -ErrorAction SilentlyContinue | Out-Null
        Write-Verbose ('{0}: Updated Notes on VM [{1}]' -f (get-date).ToString(),$_VM.Name)
    }
    #endregion

    #endregion

    <#
    
    .SYNOPSIS

    New-VMfromTemplate is intended to streamline the VM creation process.

    .DESCRIPTION

    This function uses the following components:

        1.) VM Template
        2.) Customization Spec
        3.) CIDR notation for IP Address
        
        **Note: each option can be customized as desired, the default values relate to how I prefer the environment to look/work

    VM Templates utilize the Customization Spec to change configuration.  For windows this includes a new SID for the machine.

    Cutomization Spec for Windows and Linux Systems are required be separate in how VMware uses them.  We recommend you create two:

        PowerCLI - Windows
        PowerCLI - Linux

        **Note: the Network Adapter configuration does not matter since the function updates the setup appropriately but only one nic is needed

    .EXAMPLE

    $vCenterCreds = Get-Credential 'administrator@vsphere.local'

    New-VMfromTemplate -vCenterFQDN 'vCenter.domain.local' `
        -vCenterCreds $vCenterCreds `
        -vCenterCluster 'Cluster01' `
        -vCenterDatastore 'datastore01' `
        -ServerName 'SERVER01' `
        -ServerIPAddressCIDR '10.0.0.10/24'
        -vCenterFolder 'POC - Testing' `
        -vCenterTemplate '2016' `
        -vCenterCustomizationSpec 'PowerCLI - Windows'

    .EXAMPLE

    $Array = @()

    $Arrary += New-Object psobject -Property @{
        vCenterFQDN='vCenter.domain.local';
        vCenterCreds=$vCenterCreds;
        vCenterCluster='Cluster01';
        vCenterDataStore='datastore01';
        ServerName='SERVER01';
        ServerIPAddressCIDR='10.0.0.10/24';
        vCenterFolder='POC - Testing';
        vCenterTemplate='2016';
        vCenterCustomizationSpec='PowerCLI - Windows'
    }
    $Arrary += New-Object psobject -Property @{
        vCenterFQDN='vCenter.domain.local';
        vCenterCreds=$vCenterCreds;
        vCenterCluster='Cluster01';
        vCenterDataStore='datastore01';
        ServerName='SERVER02';
        ServerIPAddressCIDR='10.0.0.11/24';
        vCenterFolder='POC - Testing';
        vCenterTemplate='2016';
        vCenterCustomizationSpec='PowerCLI - Windows'
    }

    $Array | foreach-object {New-VMfromTemplate -vCenterFQDN $_.vCenterFQDN -vCenterCreds $_.vCenterCreds -vCenterCluster $_.vCenterCluster -vCenterDatastore $_.vCenterDataStore -ServerName $_.servername -ServerIPAddressCIDR $_.ServerIPAddressCIDR -vCenterFolder $_.vCenterFolder -vCenterTemplate $_.vCenterTemplate -vCenterCustomizationSpec $_.vCenterCustomizationSpec}

    #>
}

function Add-VMtoDomain {
    [CmdletBinding()]
    param(
        #Fully Qualified Domain Name of vCenter Server where server exists
        [parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true
        )]
        [Alias('vCenterServer')]
        [string]
        $vCenterFQDN,
        
        #Credentials to access vCenter (not required but will use current user)
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [Alias('vCenterCredential')]
        [pscredential]
        $vCenterCreds,
        
        #Domain Credentials that allow joining domain and access via WSMAN after Joining domain
        [parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true
        )]
        [Alias('DomainCredential')]
        [pscredential]
        $DomainCreds,
        
        #Name of Server to Join to AD
        [parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true
        )]
        [Alias('ComputerName','Name','HostName','cn','Server')]
        [string]
        $ServerName,
        
        #Credentials to access OS before Joining domain
        [parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true
        )]
        [Alias('ServerCredential','OSCredential','ServerCreds')]
        [pscredential]
        $ServerOSCreds,
        
        #Operating System of Server being joined
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [ValidateSet('Windows','Linux')]
        [string]
        $ServerOSType = 'Windows',

        #Domain to join machine to
        [parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $ADDomainName = (Get-ADDomain).DNSRoot,

        #Enables creation of AD Admin Group(s)
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [boolean]
        $ConfigureADAdminGroup = $true,
        
        #OU Path for Joining computer to domain (ie. OU=somefolder,DC=domain,DC=com)
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $ADServerOUPath = ('OU=Prod,OU=Servers,{0}' -f (Get-ADDomain).DistinguishedName),

        #Admin Group Name that will be created in AD
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $ADGroupAdminName = (& {if ($ServerOSType -eq 'Windows') {('Local_{0}_Administrators' -f $servername)} else {('Local_{0}_Sudo' -f $servername)}}),

        #SSH Group Name to limit SSH access that will be created in AD (linux only)
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $ADGroupSSHName = ('Local_{0}_SSH' -f $ServerName),

        #Users and Groups to add to AD Admin Group
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $ADGroupAdminMembers,

        #OU Path to Create AD Groups for Server
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $ADGroupOUPath = ('OU=Server Groups,OU=EnteriseAdmin,{0}' -f (Get-ADDomain).DistinguishedName),

        #Enable Delegation for computer in AD
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [boolean]
        $TrustComputerforDelegation = $true,
        
        #Ensure PSRemoting/WSMAN is enabled
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [boolean]
        $EnableWSMAN = $true,
        
        #Match the OS Network Adapter Name to vCenter PortGroup Name
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [boolean]
        $UpdateOSNICtoPortGroupName = $true

    )

    $ErrorActionPreference = 'Stop'

    #region Validate input options

    #region vCenter Validation
    $_vCenter = $global:DefaultVIServers | Where-Object{$_.name -eq $vCenterFQDN -and $_.isconnected -eq 'True'}
    if (-Not $_vCenter) {
        if ($global:DefaultVIServers.Count -gt 0) {
            VMware.VimAutomation.Core\Disconnect-VIServer -Force -Server * -ErrorAction SilentlyContinue -Confirm:$false -Verbose:$false

            Write-Verbose ('{0}: Disconnected form Existing vCenters' -f (get-date).tostring())
        }
        try{
            if ($vCenterCreds) {
                $_vCenter = VMware.VimAutomation.Core\Connect-VIServer -Server $vCenterFQDN -Credential $vCenterCreds -Force -Verbose:$false
            } else {
                $_vCenter = VMware.VimAutomation.Core\Connect-VIServer -Server $vCenterFQDN -Force -Verbose:$false
            }
        } catch {
            Write-Error ('A Problem occured connecting to vCenter!') -ErrorAction Stop
        }
    }
    if (-Not $_vCenter) {
        Write-Error ('No vCenter Connection!') -ErrorAction Stop
    }
    Write-Verbose ('{0}: VALIDATED - vCenter "{1}" connection established as "{2}"' -f (get-date).tostring(),$_vCenter.Name, $_vCenter.User)
    #endregion

    #region VM/Server Validation
    $_VM = VMware.VimAutomation.Core\Get-VM $ServerName -Verbose:$false -ErrorAction SilentlyContinue
    if (Get-ADComputer -filter {name -like $servername} -ErrorAction SilentlyContinue -Verbose:$false) {
        Write-Error ('Server AD Computer Object already exists!') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - Computer Object [{1}] Ready to Be Created' -f (get-date).tostring(),$ServerName)
    if (-Not $_VM) {
        Write-Error ('Server Name [{0}] not found in VMware!' -f $ServerName) -ErrorAction Stop
    }
    
    Write-Verbose ('{0}: VALIDATED - VM [{1}] Located in vCenter [{2}]' -f (get-date).tostring(),$ServerName,$_vCenter.Name)
    if ($ServerOSType -eq 'Windows') {
        $_Result = VMware.VimAutomation.Core\Invoke-VMScript `
            -VM $_VM `
            -ScriptText ('ping {0} -n 1' -f $ADDomainName) `
            -GuestCredential $ServerOSCreds `
            -Verbose:$false `
            -ErrorAction SilentlyContinue
        
    } else {
        $_Result = VMware.VimAutomation.Core\Invoke-VMScript `
            -VM $_VM `
            -ScriptText ('Ping {0} -c 1' -f $ADDomainName) `
            -GuestCredential $ServerOSCreds `
            -ScriptType bash `
            -Verbose:$false `
            -ErrorAction SilentlyContinue
    }

    if ($_Result.ScriptOutput -notlike '*Lost = 0*') {
        Write-Error ('Domain [{0}] not available on VM, check network' -f $ADDomainName) -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - Domain [{1}] is pingable from VM [{2}]' -f (get-date).tostring(),$ADDomainName,$_VM.Name)
    #endregion

    #region Server and Group OUPath Validation
    $_ServerOUPath = Get-ADObject $ADServerOUPath  -ErrorAction SilentlyContinue -Verbose:$false
    # $_GroupOUPath = Get-ADObject $ADGroupOUPath -ErrorAction SilentlyContinue -Verbose:$false

    if (-Not $_ServerOUPath) {
        Write-Error ('Server OU [{0}] Path not found!' -f $ADServerOUPath) -ErrorAction Stop
    }
    Write-Verbose ('{0}: VALIDATED - Server OU Path [{1}]' -f (get-date).tostring(),$_ServerOUPath.distinguishedName)

    # if (-Not $_GroupOUPath) {
    #     Write-Error ('Group OU [{0}] Path Not Found!' -f $ADGroupOUPath) -ErrorAction Stop
    # }
    # Write-Verbose ('{0}: VALIDATED - Group OU Path [{1}]' -f (get-date).tostring(),$_GroupOUPath.distinguishedName)
    #endregion

    #endregion

    #region Join AD Domain
    if ($ServerOSType -eq 'Windows') {
        $_Result = Invoke-VMScript `
            -VM $_VM `
            -GuestCredential $ServerOSCreds `
            -ScriptText (
                ('$Password = Convertto-SecureString ') +
                ("'{0}' -Force -AsPlainText;" -f $DomainCreds.GetNetworkCredential().Password) + [environment]::newline +
                ('$Cred = New-Object PSCredential "{0}",$Password;' -f $DomainCreds.UserName) + [environment]::newline +
                ('Add-Computer -DomainName "{0}" -OUPath "{1}" -Credential $Cred' -f $ADDomainName,$ADServerOUPath)
            ) `
            -ScriptType Powershell `
            -Verbose:$false `
            -ErrorAction SilentlyContinue
            
        if ($_Result.ScriptOutput -match 'The changes will take effect after you restart the computer') {
            Invoke-VMScript `
                -VM $_VM `
                -GuestCredential $ServerOSCreds `
                -ScriptText (
                    'Clear-EventLog -LogName "Windows PowerShell"' + [environment]::NewLine +
                    'Restart-Computer -Force -Confirm:$false'
                ) `
                -ScriptType Powershell `
                -Verbose:$false `
                -ErrorAction SilentlyContinue | Out-Null
        } else {
            Write-Error ('PROBLEM: An Error Occured Joining domain [{0}] for computer [{1}] - `n{2}' -f $ADDomainName,$ServerName,$_Result) -ErrorAction Stop
        }
    } else {
        $_Result = Invoke-VMScript `
            -VM $_VM `
            -GuestCredential $ServerOSCreds `
            -ScriptText (
                ('domainjoin-cli join --ou {0} {1} {2} {3}' -f $serveroupath, $ADDomainName, $creds.GetNetworkCredential().UserName, $creds.GetNetworkCredential().Password) +
                ('history -c')
            ) `
            -Verbose $false `
            -ErrorAction SilentlyContinue
    }
    #$result = VMware.VimAutomation.Core\Invoke-VMScript -ScriptText $Script -VM $_VM -GuestCredential $ServerOSCreds -ErrorAction SilentlyContinue -Verbose:$false

    Write-Verbose ('{0}: Executed Join to AD Domain [{1}] in OU Path [{2}]' -f (get-date).tostring(),$ADDomainName,$_ServerOUPath.distinguishedName)

    # wait for server name to resolve and respond to ping
    $_Ping = $null
    While (($_Ping.Status -ne 'Success') -and -Not ($_Ping)) {
        try { $_Ping = (New-Object system.net.networkinformation.ping).Send($ServerName) } catch {}

        Start-Sleep 5
        Write-Verbose ('Waiting for VM to Reboot...')

        if ($PSVersionTable.OS -like '*windows*') {
            Start-Process powershell -ArgumentList 'ipconfig /flushdns' -Verb runas -WindowStyle hidden | Out-Null
        }
        if ($PSVersionTable.OS -like '*darwin*') {
            dscacheutil -flushcache
        }
    }

    # wait for AD Object to replicate
    while (-Not (Get-ADComputer -filter "name -like '$ServerName'" -ErrorAction SilentlyContinue -Verbose:$false)) {
        Write-Verbose ('Waiting for AD Replication...')
        Start-Sleep 10
    }
    # add kerberos delegation
    if ($TrustComputerforDelegation) {
        Get-ADComputer $ServerName -Verbose:$false | Set-ADComputer -TrustedForDelegation $true -Credential $DomainCreds -Verbose:$false

        Write-Verbose ('{0}: Enabled Trusted Delegation for AD Computer "{1}"' -f (get-date).tostring(),$ServerName)
    }
    #endregion

    #region OS Configuration

    #region Ensure PSRemoting is enabled for Windows
    # if ($ServerOSType -eq 'Windows') {
    #     $_Session = Test-PSRemoting `
    #         -ServerName $ServerName `
    #         -ServerCreds $DomainCreds `
    #         -Verbose:$false `
    #         -ErrorAction SilentlyContinue
    #     if (-Not ($_Session) -and $EnableWSMAN) {
    #         Write-Verbose ('{0}: REMOTING - Not currently enabled on [{1}]' -f (get-date).tostring(),$ServerName)

    #         VMware.VimAutomation.Core\Invoke-VMScript `
    #             -VM $_VM `
    #             -GuestCredential $ServerOSCreds `
    #             -ScriptText "Enable-PSRemoting -Force" `
    #             -Verbose:$false | Out-Null

    #         Write-Verbose ('{0}: REMOTING - Executing (Enable-PSRemoting -Force) on [{1}]' -f (get-date).ToString(),$_VM.Name)

    #         $_Session = Test-PSRemoting `
    #             -ServerName $ServerName `
    #             -ServerCreds $DomainCreds `
    #             -Verbose:$false `
    #             -ErrorAction SilentlyContinue

    #         if (-Not $_Session) {
    #             Write-Error ('PROBLEM: An Error occured configuring remoting on [{0}]' -f $ServerName) -ErrorAction Stop
    #         }

    #         Write-Verbose ('{0}: REMOTING - Successfully configured remoting on [{1}]' -f (get-date).tostring(),$ServerName)
    #     }
    # }
    #endregion

    #region Update OS network adapter name
    if ($ServerOSType -eq 'Windows' -and ($_session)) {
        if ($UpdateOSNICtoPortGroupName) {
            $_Result = Invoke-Command `
                -Session $_session `
                -Verbose:$false `
                -ErrorAction SilentlyContinue `
                -ScriptBlock {
                    Get-NetAdapter | Rename-NetAdapter -NewName ($using:_VM.ExtensionData.Guest.Net.Network) | Out-Null
                    (Get-NetAdapter).Name
                }
            
            if ($_Result -ne $_VM.ExtensionData.Guest.Net.network) {
                Write-Warning ('{0}: Network Adapter Name Change did not succeed' -f (get-date).tostring())
            } else {
                Write-Verbose ('{0}: Updated OS Network Adapter Name to [{1}]' -f (get-date).ToString(),$_VM.ExtensionData.Guest.Net.Network)
            }
        }
    }
    #endregion

    #region AD Groups for Local Administrators
    # if ($ConfigureADAdminGroup) {
    #     $_CreateGroup = $false
    #     if (-Not (Get-ADGroup -filter ('Name -eq "{0}"' -f $ADGroupAdminName))) {
    #         $_CreateGroup = $true
    #     }
    #     $_ADGroup = New-ADGroupforSQL `
    #         -GroupScope DomainLocal `
    #         -GroupOUPath $_GroupOUPath.distinguishedName `
    #         -DomainCreds $DomainCreds `
    #         -GroupName $ADGroupAdminName `
    #         -Verbose:$false `
    #         -ErrorAction SilentlyContinue `
    #         -GroupMembers $ADGroupAdminMembers `
    #         -CreateGroup $_CreateGroup

    #     if (-Not $_ADGroup) {
    #         Write-Error ('PROBLEM: AD Group Creation Failed')
    #     }

    #     Write-Verbose('{0}: Created AD Group [{1}] @ [{2}]' -f (get-date).ToString(),$ADGroupAdminName,$_GroupOUPath.distinguishedName)
    #     Write-Verbose ('{0}: Added "{1}" to AD Group "{2}"' -f (get-date).ToString(),($ADGroupAdminMembers.split([environment]::newline) -join ','),$ADGroupAdminName)

    #     if ($ServerOSType -eq 'Linux') {
    #         $_CreateGroup = $false
    #         if (-Not (Get-ADGroup -Filter ('Name -like "*{0}*"' -f $ADGroupSSHName) -Verbose:$false)) {
    #             $_CreateGroup = $true
    #         }

    #         $_ADSSHGroup = New-ADGroupforSQL `
    #             -GroupScope DomainLocal `
    #             -GroupOUPath $_GroupOUPath.distinguishedName `
    #             -DomainCreds $DomainCreds `
    #             -GroupName $ADGroupSSHName `
    #             -Verbose:$false `
    #             -ErrorAction SilentlyContinue `
    #             -GroupMembers $ADGroupAdminName `
    #             -CreateGroup $_CreateGroup

    #         if (-Not $_ADSSHGroup) {
    #             Write-Warning ("`t`tAD Group [{0}] had a problem during creation/update...manual steps may need to be taken" -f $ADGroupSSHName)
    #         }

    #         Write-Verbose('{0}: Created AD Group "{1}" @ "{2}"' -f (get-date).ToString(),$ADGroupSSHName,$_GroupOUPath.distinguishedName)
    #         Write-Verbose ('{0}: Added AD Group "{1}" to AD Group "{2}"' -f (get-date).ToString(),$ADGroupAdminName,$ADGroupSSHName)
    #     }   
    # }
    
    # if ($ServerOSType -eq 'Windows') {
    #     # configure AD group on Server OS
    #     VMware.VimAutomation.Core\Invoke-VMScript `
    #         -VM $_VM `
    #         -GuestCredential $ServerOSCreds `
    #         -ScriptText (
    #             'Add-LocalGroupMember -Group "Administrators" -Member "{0}" -Verbose:$false' -f $ADGroupAdminName
    #         ) `
    #         -Verbose:$false

    #     Write-Verbose ('{0}: Added Group "{1}" to local Administrators Group!' -f (get-date).ToString(),$ADGroupAdminName)
    # } else {
    #     VMware.VimAutomation.Core\Invoke-VMScript `
    #         -VM $_VM `
    #         -GuestCredential $rootcred `
    #         -ScriptType bash `
    #         -Verbose:$false `
    #         -ScriptText (
    #             ('echo -e "%{0}\t\t\t\tALL=(root)\t\tNOEXEC:ALL,"'  -f $ADGroupAdminName) + "'!/usr/bin/su,!/usr/bin/passwd' >> /etc/sudoers.d/Admins" + [environment]::newline +
    #             ('if (($(grep -c allowgroups /etc/ssh/sshd_config)!=0)); then sed -i "s/allowgroups*/allowgroups linux^admins {0}/g" /etc/ssh/sshd_config; else sed -i "/#Listener/aallowgroups linux^admins {0}" /etc/ssh/sshd_config; fi' -f $ADGroupSSHName) +
    #             ('/opt/pbis/bin/update-dns')
    #         )
        
    #     <# #Configure Sudoers file
    #     $Script = ('echo -e "%{0}\t\t\t\tALL=(root)\t\tNOEXEC:ALL,"'  -f $ADGroupAdminName) + "'!/usr/bin/su,!/usr/bin/passwd' >> /etc/sudoers.d/Admins"
    #     VMware.VimAutomation.Core\Invoke-VMScript -VM $_VM -ScriptText $script -GuestCredential $rootcred -ScriptType Bash -Verbose:$false

    #     #Configure SSH Allowed
    #     $Script = ('if (($(grep -c allowgroups /etc/ssh/sshd_config)!=0)); then sed -i "s/allowgroups*/allowgroups linux^admins {0}/g" /etc/ssh/sshd_config; else sed -i "/#Listener/aallowgroups linux^admins {0}" /etc/ssh/sshd_config; fi' -f $ADGroupSSHName)
    #     #$Script = { sed -i "s/linux^admins/linux^admins srv-$(hostname | tr /A-Z/ /a-z/)-ssh/" /etc/ssh/sshd_config }
    #     VMware.VimAutomation.Core\Invoke-VMScript -VM $_VM -ScriptText $script -GuestCredential $rootcred -ScriptType Bash -Verbose:$false

    #     ##Update DNS registration
    #     $Script = { /opt/pbis/bin/update-dns }
    #     VMware.VimAutomation.Core\Invoke-VMScript -VM $_VM -ScriptText $script -GuestCredential $rootcred -ScriptType Bash -Verbose:$false #>
    # }
    #endregion

    #endregion

    <#
    .SYNOPSIS

    Configures Machine on domain and performs additional Steps

    .DESCRIPTION

    This function performs validation that the Server will be able to join the domain.  Afterwards it performs the following:

        * Join the AD Domain
        * Trust machine for delegation (support for network access with kerberos)
        * Create AD Group(s) for Server
        * Configure AD Groups for Admin access
        * Configure Network Adapter to match Network Port Group Name
        * configure PSRemoting to use SSL Certificate
    
    .EXAMPLE

    $vCenterCreds = Get-Credential 'administrator@vsphere.local'
    $DomainCreds = Get-Credential 'administrator@domain.local'
    $ServerOSCreds = Get-Credential 'Administrator'

    Add-VMtoDomain -vCenterFQDN 'vCenter.domain.local' `
        -vCenterCreds $vCenterCreds `
        -DomainCreds $DomainCreds `
        -ServerName 'SERVER01' `
        -ServerOSCreds $ServerOSCreds `
        -ADGroupAdminMembers ('user1','group1') `
        -ADServerOUPath 'OU=Servers,DC=domain,DC=local' `
        -ADGroupOUPath 'OU=EnterpriseAdmin,DC=domain,DC=local'

    #>
}

function Add-DisktoVM {
    [CmdletBinding()]
    param(
        #Fully Qualified Domain Name to vCenter Server
        [parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true
        )]
        [Alias('vCenter','vCenterServer')]
        [string]
        $vCenterFQDN,
        
        #Credentials to Connect to vCenter (if not provided your current user must work)
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [Alias('vCenterCredential')]
        [pscredential]
        $vCenterCreds,
        
        #Credentials to be able to connect to server with PowerShell Remoting
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [Alias('DomainCredential')]
        [pscredential]
        $DomainCreds,
        
        #Name of Server to configure (must match in vCenter)
        [parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true
        )]
        [Alias('ComputerName','HostName','Computer','Server')]
        [string]
        $ServerName,

        #Datastore to add Disk to (default will be where the vmx file is)
        [parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [Alias('DataStore')]
        [ValidateNotNullOrEmpty()]
        [String]
        $vCenterDatastore = '',
        
        #Server OS Path to mount the disk to (can be Drive Letter E:\ or path to Mount point E:\SQLData01)
        [parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true
        )]
        [Alias('DiskPath','Path')]
        [string]
        $ServerDiskPath,
        
        #Size of Disk to create for VM (Script will make sure it can fit on datastore)
        [parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true
        )]
        [Alias('Size','DiskSize','SizeGB','DiskSizeGB')]
        [int]
        $ServerDiskSizeGB,
        
        #Type of Disk Allocation on VMFS
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [Alias('DiskType','Type')]
        [ValidateSet('Thin','Thick')]
        [String]
        $ServerDiskType = 'Thin',
        
        #Label to specify on Disk in OS
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [Alias('Label','DiskLabel')]
        [String]
        $ServerDiskLabel = ('{0} - {1}' -f $ServerDiskPath,$ServerName),
        
        #NTFS Allocation Unit Size (4Kb, 8Kb, 16Kb, 32Kb, 64Kb)
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [ValidateSet('4kb','8kb','16kb','32kb','64kb')]
        [string]
        $AllocationUnitSize = '4Kb',
        
        #Remove default ACL's on disk (users access and creator owner)
        [Parameter(
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$true
        )]
        [boolean]
        $CleanDiskACL = $true
    )

    Process {
        #region Validate Variables

        #region vCenter Validation
        if (-Not (Get-Module 'VMware*')) {
            Import-Module `
                -Name VMware.PowerCLI `
                -Verbose:$false `
                -WarningAction SilentlyContinue `
                -ErrorAction Stop | Out-Null

            Write-Verbose ('{0}: IMPORTED - VMware PowerCLI Imported' -f (get-date).tostring())
        }

        $_vCenter = $global:DefaultVIServers | Where-Object{$_.name -eq $vCenterFQDN -and $_.isconnected -eq 'True'}
        if (-Not $_vCenter) {
            if ($global:DefaultVIServers.Count -gt 0) {
                VMware.VimAutomation.Core\Disconnect-VIServer `
                    -Force `
                    -Server * `
                    -ErrorAction SilentlyContinue `
                    -Confirm:$false `
                    -Verbose:$false

                Write-Verbose ('{0}: VALIDATED - Disconnected form Existing vCenters' -f (get-date).tostring())
            }
            try{
                if ($vCenterCreds) {
                    $_vCenter = VMware.VimAutomation.Core\Connect-VIServer `
                        -Server $vCenterFQDN `
                        -Credential $vCenterCreds `
                        -Force `
                        -Verbose:$false
                } else {
                    $_vCenter = VMware.VimAutomation.Core\Connect-VIServer `
                        -Server $vCenterFQDN `
                        -Force `
                        -Verbose:$false
                }
            } catch {
                Write-Error ('PROBLEM: A Problem occured connecting to vCenter!') -ErrorAction Stop
            }
        }
        if (-Not $_vCenter) {
            Write-Error ('PROBLEM: No vCenter Connection!') -ErrorAction Stop
        }
        Write-Verbose ('{0}: VALIDATED - vCenter "{1}" connection established as "{2}"' -f (get-date).tostring(),$_vCenter.Name, $_vCenter.User)
        #endregion

        #region Validate VM, OS, and Disk Path
        $_VM = VMware.VimAutomation.Core\Get-VM `
            -Name $ServerName `
            -Verbose:$false `
            -ErrorAction SilentlyContinue

        if (-Not $_VM) {
            Write-Error ('PROBLEM: VM [{0}] not found!' -f $ServerName) -ErrorAction Stop
        }

        if (-Not $ServerDiskPath.EndsWith('\')) {
            $ServerDiskPath += '\'
        }

        $_Result = $_VM | Invoke-VMScript `
            -GuestCredential $DomainCreds `
            -ScriptText "Test-Path -Path $ServerDiskPath -ErrorAction SilentlyContinue" `
            -ErrorAction SilentlyContinue `
            -Verbose:$false

        if ($_Result.ScriptOutput -Match 'True') {
            Write-Error ('PROBLEM: DiskPath [{0}] already exists on Server [{1}]' -f $ServerDiskPath,$ServerName) -ErrorAction Stop
        }

        Write-Verbose ('{0}: VALIDATED - Ready to Add Disk "{1}" at "{2}" GB to VM "{3}"' -f (get-date).tostring(),$ServerDiskPath,$ServerDiskSizeGB,$_VM.Name)

        #endregion

        #region Validate Datastore and Disk Space
        if (-Not $vCenterDataStore) {
            $_Datastore = VMware.VimAutomation.Core\Get-DataStore `
                -Name ($_VM | Get-Datastore | Select-Object -First 1) `
                -Verbose:$false

            Write-Verbose ('{0}: VALIDATED - No Datastore Selected, Using VM [{1}] Default [{2}]"' -f (get-date).tostring(),$_VM.Name,$_Datastore.Name)
        } else {
            $DatastoreClusters = VMware.VimAutomation.Core\Get-DatastoreCluster -Verbose:$false
            $Datastores = VMware.VimAutomation.Core\Get-Datastore -Verbose:$false

            if ($DatastoreClusters) {
                $_Datastore = $DatastoreClusters | Where-Object {$_.Name -like $vCenterDataStore}
            }
            if ($Datastores -and -Not $_Datastore) {
                $_Datastore = $Datastores | Where-Object {$_.Name -like $vCenterDataStore}
            }
            if (-Not $_Datastore) {
                Write-Error ('PROBLEM: No matching datastore found!') -ErrorAction Stop
            }
            if ($_Datastore.Count -ne 1) {
                Write-Error ('PROBLEM: Found [{0}] Datastores [{1}]' -f $_Datastore.Count,($_Datastore.Name -join ',')) -ErrorAction Stop
            }
            Write-Verbose ('{0}: VALIDATED - Using Datastore: [{1}] for Disk Placement' -f (get-date).tostring(),$_Datastore.Name)
        }
        
        $SpaceUsage = 0
        if ($vCenterDiskType -ne 'Thin') {
            $SpaceUsage = $ServerDiskSizeGB
        } 
        if (($_datastore.CapacityGB - $_datastore.FreeSpaceGB) -gt ($_datastore.CapacityGB *.95)) {
            Write-Error ('PROBLEM: Datastore using greater than 95% of datastore!') -ErrorAction Stop
        }
        if (($_datastore.CapacityGB - $_datastore.FreeSpaceGB) -gt ($_datastore.CapacityGB *.8)) {
            Write-Warning ('PROBLEM: Datastore using greater than 80% of datastore!') -ErrorAction Stop
        }
        if (($_datastore.CapacityGB - $_datastore.FreeSpaceGB + $SpaceUsage) -gt ($_datastore.CapacityGB *.95)) {
            Write-Error ('PROBLEM: Datastore Usage [{0}]GB with VM [{1}]GB will be greater than 95%!' -f $_Datastore.CapacityGB,$SpaceUsage) -ErrorAction Stop
        }
        Write-Verbose ('{0}: VALIDATED - Using Datastore [{1}] which has [{2}] GB Free' -f (get-date).tostring(),$_Datastore.Name,$_Datastore.FreeSpaceGB)
        #endregion

        #endregion

        #region Create Configure Disk

        #region Create Disk on VM
        $_VM | VMware.VimAutomation.Core\New-HardDisk `
            -StorageFormat $ServerDiskType `
            -CapacityGB $ServerDiskSizeGB `
            -Datastore $_datastore.Name `
            -Verbose:$false | Out-Null

        Write-Verbose ('{0}: CREATED - New Disk (VM Name: [{1}] - Size GB: [{2}] - DataStore: [{3}] - Type: [{4}])' -f (get-date).tostring(),$_VM.Name,$ServerDiskSizeGB,$_Datastore.Name,$ServerDiskType)
        #endregion

        #region Create Partion, format and mount
        $_Script = @()
        $_Script += '$_Disk = Get-Disk | Where-Object {$_.partitionStyle -eq "RAW"}'
        $_Script += '$_Disk | Initialize-Disk'
        $_Script += '$_Partition = $_Disk | New-Partition -UseMaximumSize -AssignDriveLetter'
        $_Script += '$_Partition | Format-Volume -AllocationUnit (invoke-expression "{0}") -Confirm:$false -NewFileSystemLabel "{1}" | Out-Null' -f $AllocationUnitSize,$ServerDiskLabel
        if ($CleanDiskACL) {
            $_Script += '$_ACL = Get-ACL ($_Partition.AccessPaths | Where-Object {$_ -notlike "*volume*"})'
            $_Script += '$_ACL.Access | Where-Object {$_.IdentityReference -in ("BUILTIN\Users","CREATOR OWNER")} | ForEach-Object {$_ACL.RemoveAccessRule($_) | Out-Null}'
            $_Script += '$_ACL | Set-ACL ($_Partition.AccessPaths | Where-Object {$_ -notlike "\\?\volume*"})'
        }
        if ($ServerDiskPath.Split('\')[1]) {
            $_Script += ("New-Item -Path '{0}' -ItemType Container | Out-Null" -f $ServerDiskPath)
        }
        $_Script += '$_Partition | Remove-PartitionAccessPath -AccessPath ($_Partition.AccessPaths | Where-Object {$_ -notlike "*volume*"})'
        $_Script += ('$_Partition | Add-PartitionAccessPath -AccessPath "{0}"' -f $ServerdiskPath)
        
        $_Result = $_VM | Invoke-VMScript `
            -GuestCredential $DomainCreds `
            -ScriptText ($_Script -join [environment]::newline) `
            -ErrorAction SilentlyContinue `
            -Verbose:$false

        if ($_Result.ScriptOutput -Match 'Error') {
            Write-Error ('PROBLEM: An Error occured configuring the Disk: [{0}]' -f $_Result.ScriptOutput) -ErrorAction Stop
        }

        $_Result.ScriptOutput.Split([environment]::newline) | Where-object {$_} | foreach-object { Write-Verbose ("{0}: DISK CONFIG: `t {1}" -f (get-date).tostring(),$_)}

        $_Result = $_VM | Invoke-VMScript `
            -ScriptText "Get-Partition | Where-Object {`$_.AccessPaths -contains '$ServerDiskPath'} | fl *" `
            -ErrorAction SilentlyContinue `
            -GuestCredential $DomainCreds `
            -Verbose:$false

        if ($_Result.ScriptOutput) {
            Write-Verbose ('{0}: [{1} GB] Size Disk Added at [{2}]' -f (get-date).tostring(),$ServerDiskSizeGB,$ServerDiskPath)
        } else {
            Write-Error ('PROBLEM: The Disk Path [{0}] is not available as requested' -f $ServerDiskPath) -ErrorAction Stop
        }

        #endregion

        #endregion
    }
    End {
    }
    <#
    .SYNOPSIS

    Adds a disk to VM, Formats and Mounts

    .DESCRIPTION

    This function provides a method to quickly add virtual disks to VM's while configuring the OS level format and mount points.  It also cleanups up permissions to the disk as well.

    .EXAMPLE

    $vCenterCreds = Get-Credential 'administrator@vsphere.local'
    $DomainCreds = Get-Credential 'administrator@domain.local'

    Add-DisktoVM -vCenterFQDN '010-pa-vsivc01.boncura.com' `
        -vCenterCreds $vCentercreds `
        -DomainCreds $DomainCreds `
        -ServerName 'SERVER01' `
        -ServerDiskPath 'E:\' `
        -ServerDiskSizeGB 10

    #>
}

function New-SSLCertificate {
    [CmdletBinding()]
    param(
        #Certificate name (usually the short name)    
        [parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('ServerName,ComputerName')]
        [string]
        $Name,

        #Domain Name for request (combined with Name to get FQDN)
        [parameter(Mandatory = $false)]
        [string]
        $DomainName = ($env:USERDNSDOMAIN),

        #Common Name (set to FQDN by default)
        [parameter(Mandatory = $false)]
        [string]
        $CommonName = ('{0}.{1}' -f $Name, $DomainName),
    
        #IPAddress for FQDN
        [parameter(Mandatory = $false)]
        [string]
        $IPAddress = ([net.dns]::GetHostEntry($CommonName).AddressList.IPAddresstoString),
    
        #Subject Alternative Name to apply
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [string[]]
        $SubjectAlternativeNames = $null,
    
        #Server that is your Certificate Authority
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [string]
        $CAServer = ((certutil -ADCA | select-string dnshostname | Select-Object -first 1).tostring().split('=')[1]).Trim(),
    
        #Certificate Authority Name
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [string]
        $CAName = ((certutil -ADCA | select-string displayName | Select-Object -first 1).tostring().split('=')[1]).Trim(),
    
        #Name of Template in Certificate Authority
        [parameter(Mandatory = $True, ValueFromPipelineByPropertyName)]
        [string]
        $TemplateName,
    
        #Password assigned to PFX file
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [string]
        $PFXPassword = 'testpassword',
    
        #Path to Certificate Chain (will download from CA if not specified)
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [string]
        $ChainPath,
    
        #Country to be used by Certificate Request (uses public IP to determine country)
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [string]
        $Country = (Invoke-RestMethod -Method Get -Uri "https://ipinfo.io/$((Invoke-WebRequest -uri 'http://ifconfig.me/ip' -verbose:$false).Content)" -Verbose:$false).country,
    
        #State to be used by Certificiate Request (uses public IP to determine State)
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [string]
        $State = (Invoke-RestMethod -Method Get -Uri "https://ipinfo.io/$((Invoke-WebRequest -uri 'http://ifconfig.me/ip' -verbose:$false).Content)" -Verbose:$false).region,
    
        #Locality or City for CSR (uses public IP to determine city/locality)
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [string]
        $Locality = (Invoke-RestMethod -Method Get -Uri "https://ipinfo.io/$((Invoke-WebRequest -uri 'http://ifconfig.me/ip' -verbose:$false).Content)" -Verbose:$false).city,
    
        #Organization for CSR
        [parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [ValidateNotNullorEmpty()]
        [string]
        $Organization,
    
        #Organization Unit for CSR
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [string]
        $OrganizationalUnit = 'n/a',
    
        #Path to OpenSSL executable (must be available)
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [string]
        $OpenSSLPath = (Get-command openssl*).Source,
    
        #Path to create folder and files for Certificate Request
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [string]
        $OutputPath = "$((get-location).path)\$Name.$DomainName",
    
        #Overwrite existing Certificate (renames folder to backup-<date>)
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [boolean]
        $OverwriteExisting = $false,
    
        #Regenerate Certificate (unused)
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [boolean]
        $Regenerate = $false,
    
        #Adds default SAN Names to Request (DNS: short name, DNS: FQDN, DNS: <ipaddresss>, IP: <ipaddress>)
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [boolean]
        $UseDefaultSAN = $true,
    
        #self sign the certificate
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [boolean]
        $SelfSignCertificate = $false
    )

    $ErrorActionPreference = 'Stop'

    $Name = $Name.ToUpper()
    $DomainName = $DomainName.ToUpper()
    $FQDN = ('{0}.{1}' -f $Name, $DomainName)

    #region Test Path for Openssl
    If (-Not (Test-Path -Path $OpenSSLPath)) {
        Write-Error ('Path to OpenSSL not Found') -ErrorAction Stop
    }
    Write-Verbose ('{0}: VALIDATED - OpenSSL executable found at "{1}"' -f (get-date).tostring(), $OpenSSLPath)
    #endregion

    #region Validate Path is available)
    if ((Test-Path -Path $OutputPath) -and -Not $OverwriteExisting) {
        Write-Error ('Output path already exists and overwrite is not selected!') -ErrorAction Stop
    }
    Write-Verbose ('{0}: VALIDATED - Output path "{1}" not available to created' -f (get-date).tostring(), $OutputPath)
    #endregion

    #region Backup existing if overwriting
    if ($OverwriteExisting -and (Test-Path $OutputPath)) {
        try {
            Move-Item -Path $OutputPath -Destination ('{0}-Backup_{1}' -f $OutputPath, (get-date).ToString('yyyy.MM.dd_hh.mm.ss'))
        }
        catch {
            Write-Error ('Error Moving Folder!') -ErrorAction Stop
        }
    }
    Write-Verbose ('{0}: Renamed Existing Folder from "{1}" to "{1}-Backup_{2}"' -f (get-date).tostring(), $outputpath, (get-date).tostring('yyyy.MM.dd_hh.mm.ss'))
    #endregion

    #region Create Output Folder
    if (-Not (Test-Path -Path $OutputPath)) {
        try {
            New-Item $OutputPath -ItemType container | Out-Null
        }
        catch {
            Write-Error ('Unable to create Output Path location!') -ErrorAction Stop
        }

        Write-Verbose ('{0}: Created Output Folder "{1}"' -f (get-date).tostring(), $OutputPath)
    }
    #endregion

    #region Get Certificate Chain if not provided
    if (-Not $ChainPath) {
        try {
            Invoke-Expression ("certutil -'ca.chain' -config '{0}\{1}' {2}\chain.der" -f $CAServer, $CAName, $OutputPath) | Out-Null
            Write-Verbose ('{0}: Certutil CA Chain Exported from "{1}\{2}" to "{3}\chain.der"' -f (get-date).tostring(), $CAServer, $CAName, $OutputPath)
            Invoke-Expression ("certutil -encode '{0}\chain.der' '{0}\chain.p7b'" -f $OutputPath) | Out-Null
            Write-Verbose ('{0}: Converted Encoding of CA Chain to "{1}\chain.p7b"' -f (get-date).tostring(), $OutputPath)
            Invoke-Expression ("&'{0}' pkcs7 -print_certs -in '{1}\chain.p7b' -out '{1}\chain.pem'" -f $OpenSSLPath, $OutputPath) | Out-Null
            Write-Verbose ('{0}: Converted P7B file to PEM at "{1}\chain.pem"' -f (get-date).tostring(), $OutputPath)
        }
        catch {
            Write-Warning ('A problem occured retrieving the Certificate Chain from CA, PFX will not be created')
        }
    }
    else {
        if (-Not (Test-Path -Path $ChainPath)) {
            Write-Warning ('Provided Certificate Chain Path is not valid!')
        }
        else {
            Copy-Item -Path $ChainPath -Destination "$OutputPath\chain.pem"
            Write-Verbose ('{0}: Copied Certificate Chain from "{1}" to "{2}\chain.pem"' -f (get-date).tostring(), $ChainPath, $OutputPath)
        }
    }
    #endregion

    #region Generate Request File
    $Template = '[ req ]' + [environment]::NewLine
    $Template += "default_bits = 2048" + [environment]::newline
    $Template += "default_keyfile = rui.key" + [environment]::newline
    $Template += "distinguished_name = req_distinguished_name" + [environment]::newline
    $Template += "encrypt_key = no" + [environment]::newline
    $Template += "prompt = no" + [environment]::newline
    $Template += "string_mask = nombstr" + [environment]::newline
    $Template += "req_extensions = v3_req" + [environment]::newline
    $Template += "[ v3_req ]" + [environment]::newline
    $Template += "basicConstraints = CA:FALSE" + [environment]::newline
    $Template += "keyUsage = digitalSignature, keyEncipherment, dataEncipherment" + [environment]::newline
    $Template += "extendedKeyUsage = serverAuth, clientAuth" + [environment]::newline
    $Template += "subjectAltName = "
    ## Check if Default SANs should be used
    if ($UseDefaultSAN) {
        $Template += "DNS: $name, DNS: $FQDN, DNS: $IPAddress, IP: $IPAddress"
    }
    else {
        $Template += "DNS: $CommonName"
    }
    ## Add any additional SANs provided
    $SubjectAlternativeNames | Where-Object { $_ } | ForEach-Object { if ($_ -notlike '*:*') { $Template += ",DNS:$_" } else { $Template += ",$_" } }

    $Template += [environment]::NewLine + [environment]::newline
    $Template += "[ req_distinguished_name ]" + [environment]::newline
    $Template += "countryName = $Country" + [environment]::newline
    $Template += "stateOrProvinceName = $State" + [environment]::newline
    $Template += "localityName = $Locality" + [environment]::newline
    $Template += "0.organizationName = $Organization" + [environment]::newline
    $Template += "organizationalUnitName = $OrganizationalUnit" + [environment]::newline
    $Template += "commonName = $CommonName" + [environment]::newline

    $Template | Set-Content -Path "$OutputPath\$name.cfg" -Encoding Ascii

    Write-Verbose ('{0}: Generated Config File Template at "{1}\{2}.cfg"' -f (get-date).tostring(), $OutputPath, $name)
    Get-Content "$OutputPath\$name.cfg" | ForEach-Object { Write-Verbose ("{0}:`t`t{1}" -f (get-date).tostring(), $_) }

    #endregion

    #region Generate CSR and Key
    #Create CSR and DSA version of Private key
    Write-Verbose ('{0}: Starting Generation of Certificate Files...' -f (get-date).tostring())
    $ErrorActionPreference = 'silentlycontinue'
    Invoke-Expression ("& '{0}' req -new -nodes -out '{1}\{2}.csr' -keyout '{1}\{2}-orig.key' -config '{1}\{2}.cfg' -sha256 {3}" -f $OpenSSLPath, $OutputPath, $name, '2>&1 | out-null')
    $ErrorActionPreference = 'Stop'
    if (-Not (Test-Path -Path "$outputpath\$name-orig.key")) { Write-Error ('A problem occured Generating the DSA key file') -ErrorAction Stop }
    if (-Not (Test-Path -Path "$OutputPath\$Name.csr")) { Write-Error ('A problem occured Generating the CSR file') -ErrorAction Stop }
    Write-Verbose ('{0}: CSR and DSA Key Generated' -f (get-date).tostring())
    #Create RSA version
    $ErrorActionPreference = 'silentlycontinue'
    Invoke-Expression ("& '{0}' rsa -in '{1}\{2}-orig.key' -out '{1}\{2}.key' {3}" -f $OpenSSLPath, $OutputPath, $name, '2>&1 | out-null')
    $ErrorActionPreference = 'stop'
    if (-Not (Test-Path -Path "$outputpath\$name.key")) { Write-Error ('A problem occured Generating the RSA key file') -ErrorAction Stop }
    Write-Verbose ('{0}: RSA Key created from DSA Key' -f (get-date).tostring())
    #endregion

    #region Submit Signing request
    if ($SelfSignCertificate) {
        Invoke-Expression ("& '{0}' req x509 -sha256 -days 365 -key '{1}\{2}.key' -'{1}\{2}.csr' -out '{1}\{2}.crt' {3}" -f $OpenSSLPath, $OutputPath, $Name, '2>&1 | out-null') -ErrorAction Stop | Out-Null
        Write-Verbose ('{0}: CSR Signed by Self')
    }
    else {
        Invoke-Expression ("certreq.exe -submit -config '{0}\{1}' -attrib 'CertificateTemplate:{2}' '{3}\{4}.csr' '{3}\{4}.crt' {5}" -f $CAServer, $CAName, $TemplateName, $OutputPath, $Name, '2>&1 | out-null') -ErrorAction Stop | Out-Null
        Write-Verbose ('{0}: CSR Signed by CA "{1}\{2}"' -f (get-date).tostring(), $caserver, $CAName)
    }
    #endregion

    #region Create PFX
    if ((Test-Path -Path "$OutputPath\Chain.pem") -and -Not $SelfSignCertificate) {
        Invoke-Expression ("& '{0}' pkcs12 -export -in '{1}\{2}.crt' -inkey '{1}\{2}.key' -certfile '{1}\chain.pem' -name '{3}' -passout pass:'{4}' -out '{1}\{2}.pfx' {5}" -f $OpenSSLPath, $OutputPath, $Name, $FQDN, $PFXPassword, '2>&1 | out-null') -ErrorAction Continue | Out-Null
        Write-Verbose ('{0}: PFX File Generated' -f (get-date).tostring())
    }
    #endregion

    <#
.SYNOPSIS
Creates Certificate Request and signs with internal CA or self

.DESCRIPTION
This function attempts to pre-populate parameters to allow a relatively quick Certificate Creation Process.

Minimum Required Values = Name,TemplateName,Organization (assuming only one CA in environment)

OpenSSL.exe is used to execute most commands except the signing process since certutil is the best path for Windows CA.

If you do not have OpenSSL, we recommend using choco to install openssl.light or download to your computer appropriately through the web.

.EXAMPLE

Minimum Options Used Below:

New-SSLCertificate -Name SERVER01 -TemplateName WebServer -Organization Constoso

**Note: This Assumes you have: 
    1.) openssl in your command path under powershell, 
    2.) one CA on your network
    3.) you want the local path for output
    4.) PublicIP is correct for country, state and city/locality
    5.) FQDN resolves to IP address
    6.) domain name is the same as for the computer you are current running command

.EXAMPLE

All Options being Set Below:

New-SSLCertificate -Name SERVER01 `
    -Domain 'contoso.local' `
    -IPAddress '10.0.0.5' `
    -CAServer 'CASERVER01' `
    -CAName 'CASERVER01-CA' `
    -TemplateName WebServer `
    -PFXPassword 'supersecure' `
    -ChainPath 'C:\chain.pem' `
    -Country US -State TX `
    -Locality Austin `
    -Organization 'Contoso' `
    -OpenSSLPath 'C:\openssl\openssl.exe' `
    -OutputPath 'c:\Certs\SERVER01.contoso.local'

**Note: generally this it is not necessary to specify ALL options

.EXAMPLE

$Array = @()
$Array += New-Object psobject -Property @{Name='SERVER01';
    TemplateName='WebServer';
    Organization='Contoso';
    OpenSSLPath='C:\Program Files\OpenSSL\bin\openssl.exe';
    OverwriteExisting=$true}

$Array | foreach-object {New-SSLCertificate -Name $_.Name -TemplateName $_.TemplateName -Organization $_.Organization -OpenSSLPath $_.OpenSSLPath -OverwriteExisting $_.OverwriteExisting}

**Note: The above can be used to create multiple Certificates quickly

#>
}

function Enable-WSMANwithSSL {
    [CmdletBinding()]
    param(
        # vCenter Fully Qualified Domain Name
        [parameter(Mandatory=$false)]
        [string]
        $vCenterFQDN,

        # optional credentails to vCenter
        [parameter(Mandatory=$false)]
        [pscredential]
        $vCenterCreds,

        # name of server to configure
        [parameter(Mandatory=$True)]
        [string]
        $ServerName,

        # optional Credentials to Server
        [parameter(Mandatory=$false)]
        [pscredential]
        $ServerCreds,

        # path to pfx file with crt and key
        [parameter(Mandatory=$true)]
        [string]
        $PathtoPFXFile,

        # password for pfx file
        [parameter(Mandatory=$true)]
        [string]
        $PFXPassword
    )

    $ErrorActionPreference = 'Stop'

    #region Validation

    #region vCenter Validation
    $_vCenter = $global:DefaultVIServers | Where-Object{$_.name -eq $vCenterFQDN -and $_.isconnected -eq 'True'}
    if (-Not $_vCenter) {
        if ($global:DefaultVIServers.Count -gt 0) {
            Disconnect-VIServer -Force -Server * -ErrorAction SilentlyContinue -Confirm:$false -Verbose:$false

            Write-Verbose ('{0}: Disconnected form Existing vCenters' -f (get-date).tostring())
        }
        try{
            if ($vCenterCreds) {
                $_vCenter = Connect-VIServer -Server $vCenterFQDN -Credential $vCenterCreds -Force -Verbose:$false
            } else {
                $_vCenter = Connect-VIServer -Server $vCenterFQDN -Force -Verbose:$false
            }
        } catch {
            Write-Warning ('A Problem occured connecting to vCenter!')
        }
    }

    if (-Not $_vCenter) {
        Write-Warning ('No vCenter Connection!') -ErrorAction Stop
    }
    Write-Verbose ('{0}: VALIDATED - vCenter "{1}" connection established as "{2}"' -f (get-date).tostring(),$_vCenter.Name, $_vCenter.User)
    #endregion

    #region Server Validation
    #Connect to psremoting
    if ($ServerCreds) {
        $_Session = New-PSSession -ComputerName $ServerName -Credential $ServerCreds -ErrorAction SilentlyContinue -Verbose:$false
    }
    else {
        $_Session = New-PSSession -ComputerName $ServerName -ErrorAction SilentlyContinue -Verbose:$false
    }

    #Get VM from vCenter if connected
    if ($_vCenter) {
        $_VM = Get-VM -Name $ServerName -ErrorAction SilentlyContinue -Verbose:$false
    }

    if (-Not ($_Session)) {
        Write-Warning ('Unable to connect to pssession for "{0}"' -f (get-date).tostring(), $ServerName)
        if (-Not ($_VM)) {
            Write-Error ('No PS Remoting and No VM Connection to Server "{0}"' -f $ServerName)
        }
        Write-Verbose ('{0}: VALIDATED - VM Found for Server "{1}"' -f (get-date).ToString(), $ServerName)
    }
    else {
        Write-Verbose ('{0}: VALIDATED - PS Remoting Already Configured on Server "{1}"' -f (get-date).ToString(), $ServerName)
    }

    #see if already listening on https
    #<code needed>

    #endregion

    #region PFX Validation
    if (-Not (Test-Path -Path $PathtoPFXFile -PathType Leaf)) {
        Write-Error ('File Path Provide does not exist and/or is not a file!')
    }
    else {
        try {
            if ($ServerCreds) {
                New-PSDrive -Name $servername -PSProvider FileSystem -Root ('\\{0}\c$' -f $ServerName) -Credential $ServerCreds | Out-Null
                Copy-Item $PathtoPFXFile -Destination('{0}:\Windows\{0}.pfx' -f $ServerName) | Out-Null
            }
            else {
                Copy-Item $PathtoPFXFile -Destination ('\\{0}\c$\Windows\{0}.pfx' -f $ServerName) -ErrorAction Stop
            }
            Write-Verbose ('{0}: Copied file "{1}" to Server "{2}" C:\Windows\' -f (get-date).ToString(),$PathtoPFXFile,$ServerName)
        }
        catch {
            Write-Error ('A problem occured trying to copy file "{0}" to server "{1}"' -f $PathtoPFXFile, $ServerName)
        }
    }
    #endregion

    #endregion

    #region Configure WSMAN with SSL

    #Enable PS Remoting if not already enabled
    if (-Not $_Session -and $_VM) {
        VMware.VimAutomation.Core\Invoke-VMScript -VM $_VM -GuestCredential $ServerCreds -ScriptText "Enable-PSRemoting -Force"

        if ($ServerCreds) {
            $_Session = New-PSSession -ComputerName $ServerName -Credential $ServerCreds
        }
        else {
            $_Session = New-PSSession -ComputerName $ServerName
        }

        Write-Verbose ('{0}: PSRemoting Enabled on "{1}"' -f $ServerName)
    }

    #PS Remoting Is already enabled   
    if ($_Session) {
        Invoke-Command -Session $_Session -ScriptBlock { Param($PFXPassword) $Cert = Import-PfxCertificate -Password (ConvertTo-SecureString $pfxpassword -AsPlainText -Force) -CertStoreLocation 'Cert:\LocalMachine\My' -FilePath ('C:\Windows\{0}.pfx' -f $env:COMPUTERNAME) } -ArgumentList $PFXPassword
        Write-Verbose ('{0}: Imported PFX Certificate')
        Invoke-Command -Session $_Session -ScriptBlock { New-Item WSMan:\localhost\Listener -Address * -Transport https -CertificateThumbPrint $Cert.thumbprint -Force -Confirm:$false} -ErrorAction Stop | Out-Null
        Write-Verbose ('{0}: Configured SSL Listener')
    }

    #endregion

    <#
    .SYNOPSIS

    Enables WSMAN SSL Listener by installing SSL Certificate specified and creating Listener

    .DESCRIPTION

    Enable WSMAN SSL Listener.  This requires the SSL Cerficiate be already Generated.  The partner function is New-SSLCertificate, which is designed for this function.

    .EXAMPLE

    $creds = Get-Credential 'administrator@domain.local'

    New-SSLCertificate -Name 'SERVER01' -Organization Contoso -Template 'WebServer'

    Enable-WSMANwithSSL -ServerName 'SERVER01' -ServerCreds $creds -PathtoPFXFile 'C:\server01.domain.local\server01.pfx' -PFXpassword 'testpassword'
    
    **Note: The above example assumes PS Remoting is already enabled.  If not already enable, you can use vCenter Credentials to enable it along with the SSL listener
    #>

}

function Install-IISServer {
    [CmdletBinding()]
    Param(
        # Name of Server that IIS will be installed on
        [Parameter(Mandatory=$True)]
        [ValidateLength(1,15)]
        [String]
        $ServerName,

        # Credentials to connect to Server
        [Parameter(Mandatory=$True)]
        [PSCredential]
        $AdminCreds,

        # Drive letter where InetPub should exist
        [Parameter(Mandatory=$false)]
        [ValidateLength(1,1)]
        [String]
        $RootDriveLetter = 'E',

        # Cleanup Application Pools
        [parameter(Mandatory=$false)]
        [boolean]
        $CleanupAppPools = $true,

        # Configure WMSVC to use signed Certificate
        [parameter(Mandatory=$false)]
        [boolean]
        $ConfigureCertWMSVC = $true,

        # IIS Features to install
        [Parameter(Mandatory=$false)]
        [ValidateSet('Web-Application-Proxy','Web-Server','Web-WebServer','Web-Common-Http','Web-Default-Doc','Web-Dir-Browsing','Web-Http-Errors','Web-Static-Content','Web-Http-Redirect','Web-DAV-Publishing','Web-Health','Web-Http-Logging','Web-Custom-Logging','Web-Log-Libraries','Web-ODBC-Logging','Web-Request-Monitor','Web-Http-Tracing','Web-Performance','Web-Stat-Compression','Web-Dyn-Compression','Web-Security','Web-Filtering','Web-Basic-Auth','Web-CertProvider','Web-Client-Auth','Web-Digest-Auth','Web-Cert-Auth','Web-IP-Security','Web-Url-Auth','Web-Windows-Auth','Web-App-Dev','Web-Net-Ext','Web-Net-Ext45','Web-AppInit','Web-ASP','Web-Asp-Net','Web-Asp-Net45','Web-CGI','Web-ISAPI-Ext','Web-ISAPI-Filter','Web-Includes','Web-WebSockets','Web-Ftp-Server','Web-Ftp-Service','Web-Ftp-Ext','Web-Mgmt-Tools','Web-Mgmt-Console','Web-Mgmt-Compat','Web-Metabase','Web-Lgcy-Mgmt-Console','Web-Lgcy-Scripting','Web-WMI','Web-Scripting-Tools','Web-Mgmt-Service','Web-WHC')]
        [String[]]
        $RolesandFeatures = ('Web-Server','Web-Common-Http','Web-Default-Doc','Web-Dir-Browsing','Web-Http-Errors','Web-Static-Content','Web-Health','Web-http-logging','Web-custom-logging','web-http-tracing','web-performance','web-stat-compression','web-dyn-compression','web-security','web-filtering','web-basic-auth','web-ip-security','web-url-auth','web-windows-auth','web-app-dev','web-net-ext45','web-appinit','web-asp','web-asp-net45','web-isapi-ext','web-isapi-filter','web-mgmt-console','web-mgmt-service','Web-Log-Libraries','Web-Request-Monitor','Web-Digest-Auth','Web-Mgmt-Compat','Web-Metabase','Web-Lgcy-Scripting','Web-WMI')

    )

    $ErrorActionPreference = 'Stop'

    #region Validation

    #region Validate Server
    if ($AdminCreds) {
        $_Session = New-PSSession -ComputerName $ServerName -Credential $AdminCreds -ErrorAction SilentlyContinue
    } else {
        $_Session = New-PSSession -ComputerName $ServerName -ErrorAction SilentlyContinue
    }

    if (-Not ($_Session)) {
        Write-Error ('A problem occured connecting to WSMAN/PSRemoting on Server!') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - Established PS Remoting/WSMAN session to server "{1}" as "{2}"' -f (get-date).tostring(),$ServerName,$AdminCreds.UserName)
    #endregion

    #region Validate Drive for IIS
    if (-Not (Invoke-Command -Session $_Session -ScriptBlock {Param($RootDriveLetter); Get-PSDrive -Name $RootDriveLetter} -ArgumentList $RootDriveLetter)) {
        Write-Error ('Root Drive Letter "{0}" not found on Server.' -f $RootDriveLetter)
    }

    Write-Verbose ('{0}: VALIDATED - Root Drive Letter "{1}" Found' -f (get-date).ToString(),$RootDriveLetter)
    #endregion

    #endregion

    #region Install IIS on Server

    try {
        Invoke-Command -Session $_Session -ScriptBlock {Param($RolesandFeatures); $RolesandFeatures | Add-windowsFeature } -ArgumentList (,$RolesandFeatures) | Out-Null
    } catch {
        Write-Error ('A problem occurred adding windows features "{0}"' -f ($RolesandFeatures -join ','))
    }
    Write-Verbose ('{0}: Features "{1}" installed on Server "{2}"' -f (get-date).ToString(),($RolesandFeatures -join ','),$ServerName)

    #endregion

    #region Move InetPub to RootDriveLetter

    if ($RootDriveLetter -ne 'C') {
        $Script = {
            Param(
                $RootDriveLetter
            )
            
            Get-Module -ListAvailable WebAdministration | Import-Module -ErrorAction SilentlyContinue

            #Backup-WebConfiguration -Name 'BeforeRootMove'
            Stop-Service W3SVC,WAS,WMSVC -Force -ErrorAction Continue

            New-Item ('{0}:\InetPub' -f $RootDriveLetter) -ItemType Container | Out-Null
            Get-ACL -Path 'C:\InetPub' | Set-ACL -Path ('{0}:\InetPub' -f $RootDriveLetter)

            $files = Get-ChildItem C:\InetPub -recurse

            $files | ForEach-Object {
                Copy-Item $_.FullName -Destination $_.FullName.Replace('C:',('{0}:' -f $RootDriveLetter));
                Get-Acl -Path $_.FullName | Set-Acl -Path $_.FullName.Replace('C:',('{0}:' -f $RootDriveLetter))
            }

            Set-WebConfigurationProperty "/system.applicationHost/sites/siteDefaults" -name "traceFailedRequestsLogging.Directory" -Value ("{0}:\InetPub\Logs\FailedRequestLogFiles" -f $RootDriveLetter)
            Set-WebConfigurationProperty "/system.applicationHost/sites/siteDefaults" -name "LogFile.Directory" -Value ("{0}:\InetPub\Logs\LogFiles" -f $RootDriveLetter)
            Set-WebConfigurationProperty "/system.applicationHost/log" -name "centralBinaryLogFile.directory" -Value ("{0}:\InetPub\Logs\LogFiles" -f $RootDriveLetter)
            Set-WebConfigurationProperty "/system.applicationHost/log" -name "centralW3CLogFile.directory" -Value ("{0}:\InetPub\Logs\LogFiles" -f $RootDriveLetter)
            Set-WebConfigurationProperty "/system.applicationHost/configHistory" -name "Path" -Value ("{0}:\InetPub\History" -f $RootDriveLetter)
            Set-WebConfigurationProperty "/system.webServer/asp" -name "cache.disktemplateCacheDirectory" -Value ("{0}:\InetPub\Temp\ASP Compiled Templates" -f $RootDriveLetter)
            Set-WebConfigurationProperty "/system.webServer/httpCompression" -name "directory" -Value ("{0}:\InetPub\Temp\IIS Temporary Compressed Files" -f $RootDriveLetter)
            Set-WebConfigurationProperty "/system.WebServer/HttpErrors/error[@statusCode='401']" -name "prefixLanguageFilePath" -Value ("{0}:\InetPub\CustErr" -f $RootDriveLetter)
            Set-WebConfigurationProperty "/system.WebServer/HttpErrors/error[@statusCode='403']" -name "prefixLanguageFilePath" -Value ("{0}:\InetPub\CustErr" -f $RootDriveLetter)
            Set-WebConfigurationProperty "/system.WebServer/HttpErrors/error[@statusCode='404']" -name "prefixLanguageFilePath" -Value ("{0}:\InetPub\CustErr" -f $RootDriveLetter)
            Set-WebConfigurationProperty "/system.WebServer/HttpErrors/error[@statusCode='405']" -name "prefixLanguageFilePath" -Value ("{0}:\InetPub\CustErr" -f $RootDriveLetter)
            Set-WebConfigurationProperty "/system.WebServer/HttpErrors/error[@statusCode='406']" -name "prefixLanguageFilePath" -Value ("{0}:\InetPub\CustErr" -f $RootDriveLetter)
            Set-WebConfigurationProperty "/system.WebServer/HttpErrors/error[@statusCode='412']" -name "prefixLanguageFilePath" -Value ("{0}:\InetPub\CustErr" -f $RootDriveLetter)
            Set-WebConfigurationProperty "/system.WebServer/HttpErrors/error[@statusCode='500']" -name "prefixLanguageFilePath" -Value ("{0}:\InetPub\CustErr" -f $RootDriveLetter)
            Set-WebConfigurationProperty "/system.WebServer/HttpErrors/error[@statusCode='501']" -name "prefixLanguageFilePath" -Value ("{0}:\InetPub\CustErr" -f $RootDriveLetter)
            Set-WebConfigurationProperty "/system.WebServer/HttpErrors/error[@statusCode='502']" -name "prefixLanguageFilePath" -Value ("{0}:\InetPub\CustErr" -f $RootDriveLetter)
            Set-ItemProperty 'IIS:\Sites\Default Web Site' -Name 'PhysicalPath' -Value ("{0}:\InetPub\WWWRoot" -f $RootDriveLetter)
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\InetStp' -Name PathWWWRoot -Value ('{0}:\InetPub\wwwroot' -f $RootDriveLetter) -Force
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\InetStp' -Name PathFTPRoot -Value ('{0}:\InetPub\wwwroot' -f $RootDriveLetter) -Force
            Set-ItemProperty -Path 'HKLM:\system\CurrentControlSet\Services\was\Parameters' -Name ConfigIsolationPath -Value ('{0}:\InetPub\temp\AppPools' -f $RootDriveLetter) -Force
            If ([environment]::Is64BitOperatingSystem) { 
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\InetStp' -Name PathWWWRoot -Value ('{0}:\InetPub\wwwroot' -f $RootDriveLetter) -Force
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\InetStp' -Name PathFTPRoot -Value ('{0}:\InetPub\wwwroot' -f $RootDriveLetter) -Force
            }
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WebManagement\Server' -Name LoggingDirectory -Value ('{0}:\InetPub\logs\WMSvc' -f $RootDriveLetter) -Force
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WebManagement\Server' -Name EnableRemoteManagement -Value 1 -Force
            Start-Service W3SVC,WAS,WMSVC -ErrorAction SilentlyContinue
            Set-Service WMSVC -StartupType Automatic
            Remove-Item 'C:\InetPub' -Recurse -Force
        }
        Invoke-Command -Session $_Session -ScriptBlock $Script -ArgumentList $RootDriveLetter
    }

    #endregion

    #region Configure SSL for Remote Management
    if ($ConfigureCertWMSVC -and 'web-mgmt-service' -in $RolesandFeatures) {
        Invoke-Command -Session $_Session -ScriptBlock {Stop-Service wmsvc -force} -WarningAction SilentlyContinue
        Write-Verbose ('{0}: Stopped IIS Remote Management Service' -f (Get-Date).ToString())
        
        $Cert = Invoke-Command -Session $_Session -ScriptBlock {Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.subject -like "*CN=" + $env:COMPUTERNAME + "*"}}
        if ($Cert) {
            Invoke-Command -Session $_Session -ScriptBlock {Remove-Item IIS:\SSLBindings\0.0.0.0!8172} -ErrorAction Stop| Out-Null
            Write-Verbose ('{0}: Removed existing listener "IIS:\SSLBindings\0.0.0.0!8172"')
            Invoke-Command -Session $_Session -ScriptBlock {Param($Cert); $Cert | New-Item IIS:\SSLBindings\0.0.0.0!8172} -ErrorAction Stop -ArgumentList $cert | Out-Null
            Write-Verbose ('{0}: Created New Listener with thumbprint "{1}"' -f (Get-Date).ToString(),$Cert.thumbprint)
        } else {
            Write-Warning ('{0}: No Certificate matching server name found')
        }

        Invoke-Command -Session $_Session -ScriptBlock {Start-Service wmsvc} -ErrorAction Stop | Out-Null
        Write-Verbose ('{0}: Started IIS Remote Management Service' -f (Get-Date).ToString())
    }
    #endregion

    #region Remove Extra AppPools
    if ($CleanupAppPools) {
        Invoke-Command -Session $_Session -ScriptBlock {remove-item iis:\apppools\*.net* -force -confirm:$false -recurse} | Out-Null

        Write-Verbose ('{0}: Removed Extra Unused App Pools' -f (Get-Date).ToString())
    }
    #endregion

    <#
    
    .SYNOPSIS

    This function will install IIS on the specified Server using PS Remoting and move InetPub to an alternate location

    .DESCRIPTION

    Installs Windows IIS Server on the remote machine.  Additional setup includes:

        configure IIS Remote Management Certificate to be signed
        Move IIS settings off of C Drive to specified drive letter
        Cleanup Unnecessary Application Pools
    
    Roles and Features are selectable but a default list is set by default

    #>
}