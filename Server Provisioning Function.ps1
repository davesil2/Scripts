Function Create-NewVM
{
    Param(
        [Parameter(Mandatory=$true)]
        [String]$vCenterServer,

        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$vCenterCreds,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$LocalAdminCreds,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$DomainJoinCreds = $vCenterCreds,

        [Parameter(Mandatory=$true)]
        [ValidateLength(1,15)]
        [String]$ServerName,    
                
        [Parameter(Mandatory=$true)]
        [ValidateSet('Prod','Dev','Test')]
        [String]$ServerEnv = 'Prod',

        [Parameter(Mandatory=$true)]
        [ValidateSet('WB','DB','AP','DC')]
        [String]$ServerType = 'AP',

        [Parameter(Mandatory=$true)]
        [ValidateSet('Linux','Windows')]
        [String]$ServerOS = 'Windows',

        [Parameter(Mandatory=$true)]
        [String]$TemplateName = '*2016',

        [Parameter(Mandatory=$true)]
        [String]$TemplateLocation = 'Templates',

        [Parameter(Mandatory=$true)]
        [String]$vmLocation = 'POC - Testing',

        [Parameter(Mandatory=$true)]
        [String]$TargetDatastoreName = '*VVOL*',

        [Parameter(Mandastory=$false)]
        [switch]$TargetDatastoreIsCluster = $false,

        [Parameter(Mandatory=$true)]
        [String]$TargetClusterName = 'Servers',

        [Parameter(Mandatory=$false)]
        [Switch]$TargetClusterIsHost = $false,

        [Parameter(Mandatory=$true)]
        [String]$ServerIP,

        [Parameter(Mandatory=$true)]
        [String]$ServerSubnet = '255.255.255.0',

        [Parameter(Mandatory=$true)]
        [String]$ServerGW = ('{0}.254' -f $ServerIP.SubString(0,$ServerIP.LastIndexOf('.'))),

        [Paramater(Mandatory=$true)]
        [String]$ServerNetworkName = ('*{0}*' -f $ServerIP.SubString(0,$ServerIP.LastIndexOf('.'))),

        [Parameter(Mandtory=$true)]
        [String]$OUPath,

        [Parameter(Mandatory=$true)]
        [String]$CustomOSSpecName = ('PowerCLI - {0}' -f $ServerOS),

        [Parameter(Mandatory=$false)]
        [ValidateSet('2016','2014','2012')]
        [String]$SQLServerVersion = '2016',

        [Parameter(Mandatory=$true)]
        [String[]]$DNSServers = (((Get-DnsClientServerAddress | select -first 1).serveraddresses)),

        [Parameter(Mandatory=$true)]
        [String]$DNSDomain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name),

        [Parameter(Mandatory=$false)]
        [String]$ServerAdmins = ('{0} Admins' -f $ServerOS),

        [String]$ServerGroupsOU,

        [String]$ServiceAccountOU
    )

    $ErrorActionPreference = 'Stop'

    #region Script Input Validation/Testing
    #############################################################################################################################################
    ## Script Input Validation
    #############################################################################################################################################

    if ($functionTesting)
    {
        $vCenterServer = 'd01-pa-vsivc01.esb.com'
        $vCenterCreds = Get-Credential ($env:UserDomain + '\' + $env:USERNAME)
        $DomainJoinCreds = $vCenterCreds
        $LocalAdminCreds = Get-Credential -Message 'Local Admin Creds'
        $ServerName = 'TL-DHSAP01'
        $ServerEnv = 'Test'
        $ServerOS = 'Windows'
        $ServerType = 'DB'
        $TemplateName = '*2016'
        $TemplateLocation = 'Templates'
        $vmLocation = 'POC - Testing'
        $TargetDatastoreName = '*VVOL*'
        $TargetDataStoreIsCluster = $False
        $TargetClusterName = 'Servers'
        $TargetClusterIsHost = $false
        $ServerIP = '10.1.4.189'
        $ServerSubnet = '255.255.255.0'
        $ServerGW = ('{0}.254' -f $ServerIP.SubString(0,$ServerIP.LastIndexOf('.')))
        $ServerNetworkName = ('*{0}*' -f $ServerIP.SubString(0,$ServerIP.LastIndexOf('.')))
        $OUPath = 'OU=QA,OU=Non-PCI,OU=Servers,DC=esb,DC=com'
        $CustomOSSpecName = ('PowerCLI - {0}' -f $ServerOS)
        $SQLServerVersion = '2016'
        $DNSSErvers = (((Get-DnsClientServerAddress | select -first 1).serveraddresses))
        $DNSDomain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name)
        $ServerAdmins = ('{0} Admins' -f $ServerOS)
        $ServerGroupsOU = 'OU=Server Groups,OU=Enterpriseadmin,DC=esb,DC=com'
        $ServiceAccountOU = 'OU=Service Accounts,OU=EnterpriseAdmin,DC=esb,DC=com'
    }
    
    ##Output Values
    $variables = Get-Variable vCenterServer,vCenterCreds,DomainJoinCreds,LocalAdminCreds,ServerName,ServerEnv,ServerType,ServerOS,TemplateName,TemplateLocation,VMLocation,TargetDataStoreName,TargetDatastoreIsCluster,TargetClusterName,TargetClusterIsHost,ServerIP,ServerSubnet,ServerGW,ServerNetworkName,OUPath,CustomOSSpecName,SqlServerVersion,DNSServers,DNSDomain,ServerAdmins,ServerGroupsOU,ServiceAccountOU
    $variables | %{ Write-Verbose ($_ | select name,value)}
    
    ##Validate needed tools
    try
    {
        Write-Verbose ('Checking if required Modules are installed...')
        if (!(Get-Module -Name ActiveDirectory -ListAvailable)) { throw ('Unable to find ActiveDirectory Module - RSAT PowerShell Modules Required!') }
        if (!(Get-Module -Name VMware.PowerCLI -ListAvailable)) { throw ('Unable to find VMware PowerCLI Module - This module is required!') }
        Write-Verbose ('Found Required Modules. Checking if Modules are loaded...')
        if (!(Get-Module -Name ActiveDirectory))
        {
            Write-Verbose ('Active Directory Module not loaded.  Loading Module...')
            Import-Module ActiveDirectory -Verbose:$false | Out-Null
            Write-Verbose ('Active Directory Module Loaded')
        }
        if (!(Get-Module -Name VMware.PowerCLI))
        {
            Write-Verbose ('VMware.PowerCLI Module not loaded.  Loading Module...')
            Import-Module VMware.PowerCLI -Verbose:$false | Out-Null
            Write-Verbose ('VMware.PowerCLIy Module Loaded')
        }
    }
    Catch
    {
        throw ('Problem Validating required PowerShell Modules: {0}' -f $error[0])
    }

    ## Connect to vCenter
    try
    {
        ### If there are any other vCenter connections, all connections will be removed
        Write-Verbose ('Checking for other vCenter Connections...')
        if ($global:DefaultVIServer.IsConnected -and $Global:DefaultVIServer.Name -ne $vCenterServer)
        {
            Write-Verbose ('Found other vCenter Servers connected.  These will be disconnected...')
            Disconnect-VIServer -Server $global:defaultviservers -ErrorAction SilentlyContinue -Confirm:$false -Force
            Write-Verbose ('All vCenter Connections removed')
        }

        ### If vCenter is not connected, the connection will be attempted
        Write-Verbose ('Checking for Existing vCenter Connection...')
        if (!$global:DefaultVIServer.IsConnected -and $global:DefaultVIServer.Name -ne $vCenterServer -and $global:DefaultVIServer.User -ne $vCenterCreds.UserName)
        {
            Write-Verbose ('Connecting to vCenter Server {0} ...' -f $vCenterServer)
            Connect-VIserver -Server $vCenterServer -Credential $vCenterCreds -Force | Out-Null
            Write-Verbose ('Connected to vCenter Server {1} as {0}' -f $vCenterCreds.UserName,$vCenterServer)
        }
        Else
        {
            Write-Verbose ('vCenter connection already exists. Continuing...')
        }
    }
    Catch
    {
        ### Reporting error with the check and the error provided
        throw ('Error connecting to vCenter Server {0}: {1}' -f $vCenterServer, $Error[0])
    }

    ## Validate Server Name
    try
    {
        ### Verify Server Name doesn't already exist in vCenter
        Write-Verbose ('Checking for duplicate server name in vCenter...')
        if (Get-VM $ServerName -ErrorAction SilentlyContinue) { throw ('VM Name {0} already exists' -f $servername) } Else { Write-Verbose ('VM Name {0} not found...' -f $servername) }
        
        ### Verify Server Name doesn't already exist in Active Directory
        Write-Verbose ('Checking for duplicate server name in Active Directory..')
        if (Get-ADComputer -filter ('name -like "*{0}*"' -f $ServerName)) {throw ('Server Name {0} already exists in AD' -f $servername)} Else { Write-Verbose ('Server Name {0} not found in AD' -f $ServerName)}
    }
    Catch
    {
        ### Reporting error with the check and the error provided
        throw ('Problem with Server Name {0}: {1}' -f $ServerName, $error[0])
    }

    ##Validate IP Address
    try
    {
        ### Simple Ping Test for IP address usage
        if ((new-object System.Net.NetworkInformation.Ping).Send($ServerIP).Status -eq 'Success')
        {
            throw ('IP Address {0} is currently in use' -f $ServerIP)
        }
        Write-Verbose ('IP Address {0} not responding to ping...' -f $ServerIP)

        ### Check for DNS Reverse Lookup (this could indicate the IP is in use but just not responding to ICMP)
        Write-Verbose ('Checking IP Address for Reverse Lookup...')
        $ErrorActionPreference = 'SilentlyContinue'
        $HostEntry = [net.dns]::GetHostEntry([IPAddress]$ServerIP)
        $ErrorActionPreference = 'Continue'

        if ($HostEntry)
        { 
            throw ('IP Address Reverse lookup show host {0}.  IP address {1} may be in use.' -f $HostEntry.HostName, $serverIP) 
        }        
        Write-Verbose ('IP Address {0} has no reverse lookup entried')
    }
    Catch
    {
        ### Reporting error with the check and the error provided
        throw ('Problem with IP address {0}: {1}' -f $ServerIP, $Error[0])
    }

    ##Validate Template
    try
    {
        Write-Verbose ('Checking for Template requirements...')
        $Template = Get-Template -Location $TemplateLocation -Name $TemplateName
        if (!$Template)
        {
            throw ('No Template found matching {0}' -f $TemplateName)
        }
        if ($template.count -ne 1)
        {
            throw ('Multiple Templates found matching Template Name {0}, you may need to be more specific in the name or location.' -f $TemplateName)
        }

        Write-Verbose ('Template {0} found matching {1}' -f $Template.Name, $TemplateName)
    }
    Catch
    {
        throw ('Error validating the template: {0}' -f $Error[0])
    }

    ##Validate Location for VM
    try
    {
        Write-Verbose ('Checking location to create VM...')
        If (!(Get-Folder $vmLocation)) { throw 'VM Location folder not found' }
        Write-Verbose ('Verified Folder "{0}" for VM Placement' -f $vmLocation)
        
    }
    Catch
    {
        throw ('Problem encountered validating Location to place VM: {0}' -f $Error[0])
    }

    ##Validate Datastore
    try
    {
        if ($TargetDatastoreIsCluster)
        {
            Write-Verbose ('Checking for Cluster Datastores...')
            $TargetDatastore = Get-DatastoreCluster $TargetDatastoreName
        }
        Else
        {
            Write-Verbose ('Checking for Non-Cluster Datastores...')
            $TargetDatastore = Get-Datastore $TargetDatastoreName
        }
        if (!$TargetDatastore)
        {
            Throw ('No Datastore found matching supplied name {0}' -f $TargetDatastoreName)
        }
        if ($TargetDatastore.Count -ne 1) 
        { 
            throw ('Found {0} datastores like {1}, be more specific with the name!' -f $TargetDatastore.count, $TargetDatastoreName)
        }
        Write-Verbose ('Found datastore {0}' -f $TargetDatastore)
    }
    Catch
    {
        throw ('Problem Validating DataStore provided: {0}' -f $Error[0])
    }

    ##Validate VM Cluster/Host
    try
    {
        if ($TargetClusterIsHost)
        {
            Write-Verbose ('Checking Target Host to create VM on...')
            $TargetCluster = Get-Host $TargetClusterName
        }
        Else
        {
            Write-Verbose ('Checking Target Cluster to Create VM on...')
            $TargetCluster = Get-Cluster $TargetClusterName
        }
        if (!$TargetCluster)
        {
            Throw ('No Target Host/Cluster found matching provided name.')
        }
        if ($TargetCluster.count -ne 1)
        {
            throw ('Found {0} target hosts/clusters matching "{1}", be more specific with the name' -f $targetcluster.Count,$TargetClusterName)
        }
        
        Write-Verbose ('Found Target "{0}" for VM Creation' -f $TargetCluster.Name)
    }
    Catch
    {
        throw ('Problem validating Cluster/Host for VM Creation: {0}' -f $Error[0])
    }

    ##Validate CustomOS Spec
    try
    {
        Write-Verbose ('Checking for VM Customization Spec...')
        $CustomSpec = Get-OSCustomizationSpec -Name $CustomOSSpecName
        if (!$CustomSpec)
        {
            Throw ('VM Customization Spec ({0}) Not Found' -f $CustomOSSpecName)
        }
        if ($CustomSpec.Count -ne 1)
        {
            Throw ('Found more than one Customization Spec matching name')
        }
        Write-Verbose ('Found VM Customization Spec {0}' -f $CustomSpec.name)

        ##Configure CustomOS Spec
        Write-Verbose ('Creating Nic Cusomization Mapping')
        if ($ServerOS -like '*linux*')
        {
            $customspecNic = $CustomSpec | Get-OSCustomizationNicMapping
            $customspecNic | Set-OSCustomizationNicMapping -IpMode UseStaticIP -IpAddress $ServerIP -SubnetMask $ServerSubnet -DefaultGateway $ServerGW | Out-Null
            Write-Verbose ('Created Linux Nic Cusomization Mapping')
        }
        if ($ServerOS -like '*Windows*')
        {
            $customspecNic = $CustomSpec | Get-OSCustomizationNicMapping
            $customspecNic | Set-OSCustomizationNicMapping -IpMode UseStaticIP -IpAddress $ServerIP -SubnetMask $ServerSubnet -DefaultGateway $ServerGW -Dns $DNSServers | Out-Null
            Write-Verbose ('Created Windows Nic Cusomization Mapping')
        }
    }
    Catch
    {
        throw ('Problem Validating VM Customization Spec: {0}' -f $Error[0])
    }

    ##Validate Server Network
    try
    {
        Write-Verbose ('Checking VM for Network...')
        $ServerNetwork = (Get-VirtualPortGroup -Name "$ServerNetworkName")
        if (!$ServerNetwork)
        {
            Throw ('Server Network {0} Not Found!' -f $ServerNetworkName)
        }
        If ($ServerNetwork.Count -ne 1)
        {
            Throw ('Found {0} Network maching name "{1}"' -f $servernetwork.count, $ServerNetworkName)
        }
        Write-Verbose ('Network "{0}" found and read to be used!' -f $ServerNetwork.Name)
    }
    Catch
    {
        throw ('Problem Validating Network: {0}' -f $error[0])
    }

    ##Validate OU Paths
    try
    {
        $Result = $null
        Write-Verbose ('Check OU Path to make sure it exists...')
        if (!(Test-Path ('AD:\{0}' -f $OUPath)))
        {
            throw ('Invalid OU path "{0}" for Servers' -f $OUPath)
        }
        Write-Verbose ('OU Path: "{0}" for Servers is valid' -f $OUPath)

        if (!(Test-Path ('AD:\{0}' -f $ServerGroupsOU)))
        {
            throw ('Invalid OU path "{0}" for Server Groups' -f $ServerGroupsOU)
        }
        Write-Verbose ('OU Path: "{0}" for Server Groups is valid' -f $ServerGroupsOU)

        if (!(Test-Path ('AD:\{0}' -f $ServiceAccountOU)))
        {
            throw ('Invalid OU path "{0}" for Service Accounts' -f $ServiceAccountOU)
        }
        Write-Verbose ('OU Path: "{0}" for Service Accounts is valid' -f $ServiceAccountOU)
    }
    Catch
    {
        throw ('Problem Validating OU Path {0}: {1}' -f $OUPath, $error[0])
    }

    Write-Verbose ('All Validation Steps completed successfully!')

    #endregion

    #region VM Creation Process
    #############################################################################################################################################
    ## VM Creation
    #############################################################################################################################################

    ###Execute VM Creation Command
    try
    {
        Write-Verbose ('Starting VM Creation Process..')
        $VM = New-VM -Name $ServerName -Template $Template -ResourcePool $TargetCluster.Name -Datastore $TargetDataStore.Name -OSCustomizationSpec $CustomSpec -Location "$vmLocation" -DiskStorageFormat Thin -Verbose:$false
        Write-Verbose ('VM Created and ready to power on')

        Write-Verbose ('Assigning Port Group Name to Network Adapter')
        $vm | Get-NetworkAdapter -verbose:$false | Set-NetworkAdapter -NetworkName $ServerNetwork.Name -Confirm:$false -Verbose:$false | Out-Null
        Write-Verbose ('Network Adapter Assigned to {0}' -f $ServerNetwork.Name)

        Write-Verbose ('Starting VM...')
        $VM | Start-VM -Verbose:$false| Out-Null

        While (!(Get-VIEvent -Entity $vm -verbose:$false| ?{$_.fullformattedmessage -like '*customization*' -and $_.fullformattedmessage -like '*succeeded*'}))
        {
            Write-Verbose ('Waiting for VM {0} to customize!' -f $vm.name)
            Start-Sleep 30
        }

        Write-Verbose ('Verifying VM Tools are running')
        Wait-Tools -VM $vm -Verbose:$false | Out-Null

        $vm = Get-VM $ServerName -verbose:$false

        Write-Verbose ('VM Creation Completed!')
    }
    Catch
    {
        throw ('Problem occurred with VM Creation process:' -f $error[0])
    }

    #endregion

    #region Configure Operating System
    #############################################################################################################################################
    ## Operating System Configuration
    #############################################################################################################################################

    ## OS Configuration for Linux
    If ($ServerOS -eq 'Linux')
    {
        try
        {
            ##Test AD domain on Linux Machine
            $result = $null
            Write-Verbose ('Testing domain Accessibility before attempt to join domain')
            $Script = ('ping {0} -c 1' -f $DNSDomain)
            $result = Invoke-VMScript-VM $vm -ScriptText $script -GuestCredential $LocalAdminCreds -ScriptType bash

            if ($result.ScriptOutput -notlike '*0% packet loss*') { throw ('Network connectivity problem on VM with domain {0}' -f $DNSDomain)}
            Write-Verbose ('Verified connectivity with AD domain {0}' -f $DNSDomain)

            ##Join Machine to AD domain
            $result = $null
            Write-Verbose ('Begin domain Join')
            $script = "domainjoin-cli join --ou '"+$oupath+"' esb.com " + $vCentercreds.GetNetworkCredential().username + ' ' + $vCenterCreds.GetNetworkCredential().Password + '; history -c'
            $result = Invoke-VMScript -VM $vm -ScriptText $script -GuestCredential $LocalAdminCreds -ScriptType Bash

            if ($result.ScriptOutput -notlike '*successful*')
            {
                throw ("Error joining the AD Domain {0}`n`n{1}" -f $DNSDomain,$result.ScriptOutput)
            }
            Write-Verbose ('Successfully Joined domain!')

            ##Configure AD Groups for Server access
            $GroupSSH = ('Local_{0}_SSH' -f $ServerName)
            if (!(Get-ADGroup -Filter ('name -like "*{0}*"' -f $GroupSSH)))
            {
                $result = $null
                Write-Verbose ('Creating Group for SSH Access to Server...')
                $result = New-ADGroup -Name $GroupSSH -SamAccountName $GroupSSH -GroupCategory Security -GroupScope DomainLocal -Path $ServerGroupsOU
                Start-Sleep 15
                if (!$result) {throw ('Error Creating AD Group: {0}' -f $error[0])}
                Write-Verbose ('AD Group {0} Created' -f $GroupSSH)
            }

            $GroupSudo = ('Local_{0}_Sudo' -f $ServerName)
            if (!(Get-ADGroup -Filter ('name -like "*{0}*"' -f $GroupSudo)))
            {
                ##Create AD Group for Sudo rights
                $result = $null
                Write-Verbose ('Creating Group for Sudo rights on Server...')
                $result = New-ADGroup -Name $GroupSudo -SamAccountName $GroupSudo -GroupCategory Security -GroupScope DomainLocal -Path $ServerGroupsOU
                Start-Sleep 10
                if (!$result) { throw ('Error creating AD Group: {0}' -f $error[0]) }
                Write-Verbose ('AD Group {0} Created' -f $GroupSudo)

                ##Make sure Sudo rights are provide to Linux Admins
                $result = null
                Write-Verbose ('Adding Sudo AD Group to LinuxAdmins AD Group...')
                $result = Add-ADGroupMember -Identity $GroupSudo -Members $ServerAdmins
                if (!$result) { Write-Warning ('Error adding {0} to {1}: this may need to be manually corrected.' -f $ServerAdmins, $groupSudo) } Else {Write-Verbose ('Added {0} to {1}' -f $ServerAdmins, $groupSudo)}

                ##Make sure SSH right are granted to the Sudo users
                $result = null
                Write-Verbose ('Adding Sudo Group to SSH Group for Server...')
                $result = Add-ADGroupMember -Identity $GroupSSH -Members $GroupSudo
                if (!$result) {Write-Warning ('Error adding {0} to {1}: this may need to be manually corrected.' -f $GroupSudo, $GroupSSH)} Else {Write-Verbose ('Added {0} to {1}' -f $GroupSudo, $GroupSSH)}

            }

            #Configure Sudoers file
            $result = $null
            Write-Verbose ('Configuring Sudoers File on Linux Host...')
            $Script = {echo $(echo -e "%Local_$(hostname | tr /a-z/ /A-Z/)_Sudo\t\t\t\tALL=(ALL)\t\tNOEXEC:ALL,"'!/usr/bin/su,!/usr/bin/passwd') >> /etc/sudoers.d/Admins}
            $Result = Invoke-VMScript -VM $vm -ScriptText $script -GuestCredential $LocalAdminCreds -ScriptType Bash
            if ($result.ScriptOutput -notlike '') { Write-Warning ('') } Else { Write-verbose ('') }

            #Configure SSH Allowed
            $result = $null
            Write-Verbose ('Configure SSH controlled access to AD Group...')
            $Script = {sed -i "s/linux^admins/linux^admins local_$(hostname | tr /A-Z/ /a-z/)_ssh/" /etc/ssh/sshd_config}
            $result = Invoke-VMScript -VM $vm -ScriptText $script -GuestCredential $LocalAdminCreds -ScriptType Bash
            if ($result.ScriptOutput -notlike '') { Write-Warning ('') } Else { Write-Verbose ('') }

            ##Update DNS registration
            $result = $null
            Write-Verbose ('Run DNS Update to ensure DNS Records are created...')
            $Script = {/opt/pbis/bin/update-dns}
            $result = Invoke-VMScript -VM $vm -ScriptText $script -GuestCredential $LocalAdminCreds -ScriptType Bash
            if ($Result.ScriptOutput -notlike '') { Write-Warning ('') } Else { Write-Verbose ('') }

        }
        Catch
        {
            throw ('Problem with OS configuration on {0}: {0}' -f $VM.Name, $error[0])
        }
        
    }

    ## OS Configuration for Windows
    If ($ServerOS -eq 'Windows')
    {
        try
        {
            ##Test AD domain on Linux Machine
            $result = $null
            Write-Verbose ('Testing domain Accessibility before attempt to join domain')
            $Script = ('ping {0} -n 1' -f $DNSDomain)
            $result = Invoke-VMScript $vm -ScriptText $script -GuestCredential $LocalAdminCreds -ScriptType Bat -Verbose:$false
            if ($result.ScriptOutput -notlike '*0% loss*') { throw ('Network connectivity problem on VM with domain {0}' -f $DNSDomain)}
            Write-Verbose ('Verified connectivity with AD domain {0}' -f $DNSDomain)

            ##Join Machine to AD domain
            $result = $null
            Write-Verbose ('Configuring machine to join to domain...')
            $Script = '$Password = convertto-securestring "'+ $DomainJoinCreds.GetNetworkCredential().Password+'" -force -asplaintext;$user = "' + $vCenterCreds.UserName + '";$cred = new-object system.management.automation.pscredential $user, $password; add-computer -domainname '+ $dnsdomain +' -oupath "' + $OUPath + '" -Credential $cred -restart'
            $result = Invoke-VMScript -ScriptText $Script -VM $vm -GuestCredential $LocalAdminCreds -ErrorAction SilentlyContinue -Verbose:$false
            if ($result.ScriptOutput -notlike '') { throw ('') }
            Write-Verbose ('Succesfully Joined domain, waiting for reboot...')

            ##Wait/Test for machine to be available
            $status = (Test-Ping -Server $servername -Count 1)
            While (($status.status -ne 'Success') -and ($status)) 
            {
                Start-Sleep 15
                Write-Verbose ('Waiting for VM {0} Reboot..' -f $vm.Name)
                Clear-DnsClientCache
        
                if(([net.dns]::Resolve($servername)))
                {
                    Write-Verbose ('Server Name resolves with DNS, clearing Cache!')
                    Clear-DnsClientCache
                    $status = (Test-Ping -Server $servername -Count 1)
                }
            }

            ##Configure Kerberos Delegation for Computer Object
            Write-Verbose ('Enabling trusted delegation for computer Account...')
            Start-Sleep 10
            Get-ADComputer $vm.Name | Set-ADComputer -TrustedForDelegation $True -Credential $DomainJoinCreds
            Write-Verbose ('Computer {0} is trusted for delegation' -f $ServerName)

            ##Force GPUpdate for large kerberos token size issue
            $result = $null
            Write-Verbose ('Forcing Group Policy Update - ensure kerberos max token size is adjusted...')
            $Script = "gpupdate /force;"
            $Result = Invoke-VMScript -ScriptText $Script -VM $vm -GuestCredential $DomainJoinCreds -ErrorAction SilentlyContinue -ScriptType PowerShell -verbose:$false
            Write-Verbose ('Completed Group Policy Update on {0}' -f $ServerName)
            Write-Verbose ('Restarting WinRM Service to reflect update...')
            (Get-WmiObject Win32_Service -ComputerName $serverName -Filter 'name = "winrm"').StopService() | Out-Null
            Start-Sleep -Seconds 3
            (Get-WmiObject Win32_Service -ComputerName $serverName -Filter 'name = "winrm"').StartService() | Out-Null
            Write-Verbose ('Completed restarting WinRM Service.')

            ##restart computer to make sure tokens are working
            Write-Verbose ('Rebooting VM {0}...' -f $servername)
            Restart-Computer -ComputerName $servername
            Start-Sleep 10
            While (($status.status -ne 'Success') -and ($status)) 
            {
                Start-Sleep 15
                Write-Verbose ('Waiting for VM {0} Reboot..' -f $vm.Name)
            }

            ##Assign Existing SSL Cert for WSMAN
            $result = $null
            Write-Verbose ('Updating WSMAN service to use HTTPS for WinRM Service...')
            $Script = {
                $ServerName = $env:COMPUTERNAME
                $Domain = $env:USERDNSDOMAIN
                $Cert = Get-ChildItem Cert:\LocalMachine\My | ?{$_.Subject -eq "CN=$Servername.$domain"} | Sort-Object NotAfter -Descending | select -First 1
        
                New-Item WSMan:\localhost\Listener -Address * -Transport https -CertificateThumbPrint $cert.Thumbprint -Force -Confirm:$false
            }
            $result = Invoke-Command -ComputerName $serverName -ScriptBlock $Script -Credential $DomainJoinCreds -Verbose:$false
            if ($Result.ScriptOutput -notlike '') { Write-Warning ('a problem occured configuring WSMAN SSL') } Else { Write-Verbose ('WSMAN SSL Listener configured.') }

            ##Add Disk for data
            $result = $null
            Write-Verbose ('Adding data Disk as E:\ to server...')
            $result = New-HardDisk -CapacityGB 10 -StorageFormat Thin -VM $vm -verbose:$false
            if (!$result) { throw ('Error adding Data Disk: {0}' -f $Error[0]) }
            Write-Verbose ('New Disk Added to {0} @ {1} GB' -f $ServerName, $result.capacityGB)

            ##Configure Data Disk
            $result = $null
            Write-Verbose ('Configuring Disk as E:\ on Server...')
            $Script = {
                $Disk = Get-Disk | Where {$_.PartitionStyle -eq 'RAW'}
                $Disk | Initialize-Disk
                $result = $null
                $result = $Disk | New-Partition -UseMaximumSize -DriveLetter E | Format-Volume -Confirm:$false
                if ($result.DriveLetter -ne 'E') { throw ('Error creating partition and Drive Letter') }

                $acl = get-acl E:\
                $acl.RemoveAccessRule(($acl.Access | ?{$_.IdentityReference -like 'creator owner'})) | Out-Null
                $acl.RemoveAccessRule(($acl.Access | ?{$_.IdentityReference -like 'Builtin\Users' -and $_.FileSystemRights -like 'AppendData'})) | Out-Null
                $acl.RemoveAccessRule(($acl.Access | ?{$_.IdentityReference -like 'Builtin\Users' -and $_.FileSystemRights -like 'CreateFiles'})) | Out-Null
                $acl.RemoveAccessRule(($acl.Access | ?{$_.IdentityReference -like 'Builtin\Users' -and $_.FileSystemRights -like 'ReadAndExecute*'})) | Out-Null
                $result = $null
                $result = $acl | Set-Acl E:\
                if (!$result) { throw ('Error applying permissions to E:\') }

                New-Item E:\Scripts, E:\Software -ItemType container | Out-Null
            }
            $result = Invoke-Command -ComputerName $ServerName -ScriptBlock $script -Credential $DomainJoinCreds
            if ($result.scriptOutput -like '*Error*') { throw ('Error occured configuring E:\ Drive!') }
            Write-Verbose ('Disk Configured Successfully at E:\ on {0}' -f $ServerName)

            ### Configure AD Group for Local Admins
            if ($ServerType -ne 'DC')
            {
                Write-Verbose ('Server Type not a domain controller...')
                $Group = ('Local_{0}_Administrators' -f $ServerName)
                if (!(Get-ADGroup -Filter ('name -like "*{0}*"' -f $Group)))
                {
                    $result = $null
                    Write-Verbose ('Creating AD Group {0}' -f $Group)
                    New-ADGroup -Name $Group -SamAccountName $Group -GroupCategory Security -GroupScope DomainLocal -Path $ServerGroupsOU
                    $result = Get-ADGroup $Group
                    Start-Sleep 15
                    if (!$result) { Throw ('Error Creating AD Group: {0}' -f $error[0]) }
                    Write-Verbose ('AD Group created successfully.')
                }

                $result = $null
                Write-Verbose ('Adding AD Group to Local Administrators Group...')
                Add-LocalGroupMembers -ComputerName $servername -LocalGroupName Administrators -AccountObject $Group
                Write-Verbose ('AD Group {0} Added to Local Administrators Group On {1}' -f $Group,$ServerName)
                
                try
                {
                    Write-Verbose ('Adding AD Group {0} to Global Admins {1} ' -f $Group, $ServerAdmins)
                    Add-ADGroupMember -Identity $group -Members $ServerAdmins
                    Write-Verbose ('AD Group Successfully Added.')
                }
                Catch
                {
                    Write-Warning ('Error adding {0} to {1}' -f $Group, $ServerAdmins)
                }
            }

            ###Configure NIC name to the Network Name
            $result = $null
            Write-Verbose ('Updateing computer {0} Network Adapter name to {1}' -f $ServerName, $ServerNetwork.Name)
            $Script = {
                Param ($param) 
                Get-NetAdapter | Rename-NetAdapter -NewName $param
            }
            Invoke-Command -ComputerName $serverName -ScriptBlock $Script -Credential $vCenterCreds -ArgumentList $ServerNetwork.Name -Verbose:$false
            Write-Verbose ('Network adapter name updated successfully!')
        }
        Catch
        {
            throw ('Problem with OS configuration on {0}: {0}' -f $VM.Name, $error[0])
        }
    }

    #endregion

    #region Prepare for Applications (IIS and SQL so far)
    #############################################################################################################################################
    ## Prepare for Applications (IIS and SQL so far)
    #############################################################################################################################################

    $VM = Get-VM $ServerName -Verbose:$false

    If ($ServerOS -eq 'Windows' -and $ServerType -eq 'DB' -and $SQLServerVersion)
    {
        # Add Folders for Mount Points
        Write-Verbose ('Creating Table for Mount Points..')
        $MountPoints = @()
        if ($SQLServerVersion -eq '2016') {$MountPoints += New-Object psobject -Property @{Name='MSSQL13.MSSQLSERVER';Size=10}}
        if ($SQLServerVersion -eq '2014') {$MountPoints += New-Object psobject -Property @{Name='MSSQL12.MSSQLSERVER';Size=10}}
        if ($SQLServerVersion -eq '2012') {$MountPoints += New-Object psobject -Property @{Name='MSSQL11.MSSQLSERVER';Size=10}}
        $MountPoints += New-Object psobject -Property @{Name='SQLData1';Size=20}
        $MountPoints += New-Object psobject -Property @{Name='SQLLogs1';Size=10}
        $MountPoints += New-Object psobject -Property @{Name='TDBData1';Size=10}
        $MountPoints += New-Object psobject -Property @{Name='TDBLogs1';Size=10}
        Write-Verbose ($MountPoints)

        ## Add disks, initialize, format, mount, fix permissions
        Write-Verbose ('Iterating through Mount Points...')
        ForEach ($MP in $MountPoints)
        {
            Write-Verbose ('Creating Mount Point for E:\{0}...' -f $MP.Name)
            $result = $null
            Write-Verbose ('Adding {0} GB Disk to VM' -f $MP.size)
            $result = New-HardDisk -CapacityGB $MP.size -Datastore $TargetDatastore.Name -VM $VM -Verbose:$false
            if (!$Result) { throw ('New Disk Added') }

            Write-Verbose ('Executing Script on Server for disk...')
            $Script = {
                Param($MP)

                # Create Folder
                New-Item ('E:\{0}' -f $MP.Name) -ItemType container | Out-Null
        
                # Get New Disk and Initialize and create partition
                $Disk = Get-Disk | Where {$_.PartitionStyle -eq 'RAW'}
                Initialize-Disk $Disk.Number | Out-Null
                New-Partition -DiskNumber $Disk.Number -UseMaximumSize -DriveLetter F | Format-Volume -NewFileSystemLabel ('{0}_{1}' -f $MP.Name.Split('.')[0],$env:COMPUTERNAME) -AllocationUnitSize 64Kb -Confirm:$false | Out-Null

                # Fix up Security on disk
                $acl = Get-Acl F:\
                $acl.RemoveAccessRule(($acl.Access | ?{$_.IdentityReference -like 'creator owner'})) | Out-Null
                $acl.RemoveAccessRule(($acl.Access | ?{$_.IdentityReference -like 'Builtin\Users' -and $_.FileSystemRights -like 'AppendData'})) | Out-Null
                $acl.RemoveAccessRule(($acl.Access | ?{$_.IdentityReference -like 'Builtin\Users' -and $_.FileSystemRights -like 'CreateFiles'})) | Out-Null
                $acl.RemoveAccessRule(($acl.Access | ?{$_.IdentityReference -like 'Builtin\Users' -and $_.FileSystemRights -like 'ReadAndExecute*'})) | Out-Null
                $acl | Set-Acl F:\ | Out-Null
    
                # remove drive letter and configure mount point
                Remove-PartitionAccessPath -DiskNumber $Disk.Number -PartitionNumber 2 -AccessPath F:\ | Out-Null
                Add-PartitionAccessPath -DiskNumber $Disk.Number -PartitionNumber 2 -AccessPath ('E:\{0}' -f $MP.Name) | Out-Null
            }
            Invoke-Command -ComputerName $vm.name -ScriptBlock $Script -ArgumentList $MP | Out-Null
            Write-Verbose ('Done Creating Mount Point E:\{0}' -f $MP.name)
        }
    }

    If ($ServerOS -eq 'Windows' -and $ServerType -eq 'WB')
    {
        ##Install IIS
        $Result = $null
        Write-Verbose ('Installing IIS Role and Features...')
        $Script = {
            Add-WindowsFeature Web-Server, Web-Common-Http, Web-Default-Doc, Web-Dir-Browsing, Web-Http-Errors, Web-Static-Content, Web-Health, Web-http-logging, Web-custom-logging, web-http-tracing, web-performance, web-stat-compression, web-dyn-compression, web-security, web-filtering, web-basic-auth, web-ip-security, web-url-auth, web-windows-auth, web-app-dev, web-net-ext45, web-appinit, web-asp, web-asp-net45, web-isapi-ext, web-isapi-filter, web-mgmt-console, web-mgmt-service, Web-Log-Libraries, Web-Request-Monitor, Web-Digest-Auth, Web-Mgmt-Compat, Web-Metabase, Web-Lgcy-Scripting, Web-WMI
        }
        $result = Invoke-Command -ComputerName $ServerName -ScriptBlock $Script
        Write-Verbose ('IIS Role and Features installed.')

        Write-Verbose ('Moving IIS to E:\ Drive...')
        $Script = {
            ##Import Module
            Get-Module -ListAvailable WebAdministration | Import-Module -ErrorAction SilentlyContinue

            ##Backup Config and stop services
            Backup-WebConfiguration -Name 'BeforeRootMove'
            Stop-Service W3SVC,WAS,WMSVC -Force -ErrorAction Continue

            New-Item E:\InetPub -ItemType Container | Out-Null
            Get-ACL -Path C:\InetPub | Set-ACL -Path E:\InetPub | Out-Null

            $files = Get-ChildItem C:\InetPub -recurse
            ForEach ($file in $files)
            {
                Copy-Item -LiteralPath $file.FullName -Destination $file.FullName.Replace('C:','E:') | Out-Null
                Get-Acl -Path $file.FullName | Set-Acl -Path $file.FullName.Replace('C:','E:') | Out-Null
            }

            Set-WebConfigurationProperty "/system.applicationHost/sites/siteDefaults" -name "traceFailedRequestsLogging.Directory" -Value "E:\InetPub\Logs\FailedRequestLogFiles"
            Set-WebConfigurationProperty "/system.applicationHost/sites/siteDefaults" -name "LogFile.Directory" -Value "E:\InetPub\Logs\LogFiles"
            Set-WebConfigurationProperty "/system.applicationHost/log" -name "centralBinaryLogFile.directory" -Value "E:\InetPub\Logs\LogFiles"
            Set-WebConfigurationProperty "/system.applicationHost/log" -name "centralW3CLogFile.directory" -Value "E:\InetPub\Logs\LogFiles"
            Set-WebConfigurationProperty "/system.applicationHost/configHistory" -name "Path" -Value "E:\InetPub\History"
            Set-WebConfigurationProperty "/system.webServer/asp" -name "cache.disktemplateCacheDirectory" -Value "E:\InetPub\Temp\ASP Compiled Templates"
            Set-WebConfigurationProperty "/system.webServer/httpCompression" -name "directory" -Value "E:\InetPub\Temp\IIS Temporary Compressed Files"
            Set-ItemProperty 'IIS:\Sites\Default Web Site' -Name 'PhysicalPath' -Value "E:\InetPub\WWWRoot"
            Set-WebConfigurationProperty  "/system.WebServer/HttpErrors/error[@statusCode='401']" -name "prefixLanguageFilePath" -Value "E:\InetPub\CustErr"
            Set-WebConfigurationProperty  "/system.WebServer/HttpErrors/error[@statusCode='403']" -name "prefixLanguageFilePath" -Value "E:\InetPub\CustErr"
            Set-WebConfigurationProperty  "/system.WebServer/HttpErrors/error[@statusCode='404']" -name "prefixLanguageFilePath" -Value "E:\InetPub\CustErr"
            Set-WebConfigurationProperty  "/system.WebServer/HttpErrors/error[@statusCode='405']" -name "prefixLanguageFilePath" -Value "E:\InetPub\CustErr"
            Set-WebConfigurationProperty  "/system.WebServer/HttpErrors/error[@statusCode='406']" -name "prefixLanguageFilePath" -Value "E:\InetPub\CustErr"
            Set-WebConfigurationProperty  "/system.WebServer/HttpErrors/error[@statusCode='412']" -name "prefixLanguageFilePath" -Value "E:\InetPub\CustErr"
            Set-WebConfigurationProperty  "/system.WebServer/HttpErrors/error[@statusCode='500']" -name "prefixLanguageFilePath" -Value "E:\InetPub\CustErr"
            Set-WebConfigurationProperty  "/system.WebServer/HttpErrors/error[@statusCode='501']" -name "prefixLanguageFilePath" -Value "E:\InetPub\CustErr"
            Set-WebConfigurationProperty  "/system.WebServer/HttpErrors/error[@statusCode='502']" -name "prefixLanguageFilePath" -Value "E:\InetPub\CustErr"
            Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\InetStp -Name PathWWWRoot -Value 'E:\InetPub\wwwroot' -Force
            Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\InetStp -Name PathFTPRoot -Value 'E:\InetPub\wwwroot' -Force
            Set-ItemProperty -Path HKLM:\system\CurrentControlSet\Services\was\Parameters -Name ConfigIsolationPath -Value 'E:\InetPub\temp\AppPools' -Force
            If ([environment]::Is64BitOperatingSystem)
            {
                Set-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\InetStp -Name PathWWWRoot -Value 'E:\InetPub\wwwroot' -Force
                Set-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\InetStp -Name PathFTPRoot -Value 'E:\InetPub\wwwroot' -Force
            }
            Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name LoggingDirectory -Value 'E:\InetPub\logs\WMSvc' -Force
            Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name EnableRemoteManagement -Value 1 -Force

            $cert = gci Cert:\LocalMachine\My | ?{$_.subject -like "*CN=" + $env:COMPUTERNAME + "*"}
            if ($cert)
            {
                Remove-Item IIS:\SSLBindings\0.0.0.0!8172 | Out-Null
                $Cert | New-Item IIS:\SSLBindings\0.0.0.0!8172 | Out-Null
            }

            #### Start Services
            Start-Service W3SVC,WAS,WMSVC
            Set-Service wmsvc -StartupType Automatic

            Remove-Item C:\Inetpub -Recurse | Out-Null

            remove-item iis:\apppools\*.net* -force -confirm:$false -recurse | Out-Null
        
    }
    Invoke-Command -ComputerName $ServerName -ScriptBlock $Script
    }

    #endregion

}