function Install-SQLServer {
    <#
    .SYNOPSIS
    This Funciton is designed to Install SQL Server with Provided ISO and other parameters
    .DESCRIPTION
    This function generates and executes the installation script for SQL Server on a Windows Server.  This function does the following Actions:

        1.) Generate Mount Points
            a.) Add new Disks for MSSQL, SQLData, SQLLogs, TDBData, and TDBLogs
            b.) Clean up Security Permissions to secure
        2.) Create Service Account
        3.) Create SysAdmin AD Group
        4.) Create File Share group
        5.) Grant Remote Access Permissions
        6.) Configure Kerberos SPN's
        7.) Generate SSL Certificate
        8.) Generate Install Script
        9.) Execute Install Script
    .EXAMPLE
    <to be written>
    #>
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $ServerName,

        [Parameter(Mandatory=$false)]
        [String]
        $vCenterServer,

        [Parameter(Mandatory=$false)]
        [PSCredential]
        $vCenterCreds,

        [Parameter(Mandatory=$true)]
        [pscredential]
        $DomainAdminCreds,

        [Parameter(Mandatory=$False)]
        [String]
        $TargetDataStoreName,

        [Parameter(Mandatory=$false)]
        [Switch]
        $TargetDataStoreIsCluster = $false,

        [Parameter(Mandatory=$false)]
        [Switch]
        $CreateMountPoints,

        [Parameter(Mandatory=$true)]
        [ValidateSet('2016','2014','2012')]
        [String]
        $SQLServerVersion = '2016',

        [Parameter(Mandatory=$True)]
        [String]
        $svcAccount = ('s-{0}' -f $ServerName),

        [Parameter(Mandatory = $false)]
        [Switch]
        $GenerateServiceAccount = $true,

        [Parameter(Mandatory=$True)]
        [String]
        $svcAccountOUPath,

        [Parameter(Mandatory=$false)]
        [String]
        $svcAccountPassword,

        [Parameter(Mandatory=$false)]
        [String]
        $DNSDomain = ($env:USERDNSDOMAIN),

        [Parameter(Mandatory=$true)]
        [String]
        $SysAdminGroup = ('SQL_{0}_SysAdmin' -f $ServerName),

        [Parameter(Mandatory=$true)]
        [String]
        $SysAdminGroupOUPath,

        [Parameter(Mandatory=$false)]
        [Switch]
        $GenerateSysAdminGroup = $true,

        [Parameter(Mandatory=$false)]
        [String]
        $SQLADminsGroup = 'SQL Admins',

        [Parameter(Mandatory=$true)]
        [String]
        $FileShareGroup = ('FS_{0}-DataAccess$_Modify'),

        [Parameter(Mandatory=$false)]
        [Switch]
        $GenerateFileShareGroup = $true,

        [Parameter(Mandatory=$true)]
        [String]
        $FileShareGroupOUPath,

        [Parameter(Mandatory=$false)]
        [String]
        $ServicePackPath,

        [Parameter(Mandatory=$true)]
        [String]
        $SQLISOPath,

        [Parameter(Mandatory=$true)]
        [String]
        $SQLInstallKey,

        [Parameter(Mandatory=$false)]
        [Switch]
        $InstallMgmtStudio,

        [Parameter(Mandatory=$true)]
        [String]
        $CertificateTemplate,

        [Parameter(Mandator=$true)]
        [String]
        $CertificateLocality,

        [Parameter(Mandatory=$true)]
        [String]
        $CertificateOrganization,
        
        [Parameter(Mandatory=$true)]
        [String]
        $CertificateOutputPath
    )

    #region Validate Input
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

    # Check Server Exists
    try {
        Write-Verbose ('Pinging Server to make sure it exists...')
        $Result = $null
        $Result = (new-object System.Net.NetworkInformation.Ping).Send($ServerName)
        if (!($Result.Status -eq 'Successful')) { throw ('Problem resolving or pinging "{0}"' -f $ServerName) }
        Write-Verbose ('Server "{0}" Responded Succefully to Ping' -f $ServerName)
    }
    catch {
        throw ('A Problem occured validating the server "{0}": {1}' -f $ServerName,$Error[0])
    }

    # Check Server Connection Credentials
    try {
        Write-Verbose ('Testing Domain Admin Credentials...')
        Connect-WSMan -ComputerName $ServerName -Credential $DomainAdminCreds | Out-Null
        Write-Verbose ('Succesfully connected "{0}" with Credentials {1}' -f $ServerName,$DomainAdminCreds.UserName)
    }
    catch {
        throw ('Problem testing Domain Admin Credentials to server {0}: {1} ' -f $servername,$error[0])
    }

    # Validate vCenter Connection
    try {
        if ($CreateMountPoints)
        {
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
        else {
            Write-Verbose ('Skipping Creating Mount Points!')
        }
    }
    catch {
        throw ('A problem occured validating connection to vCenter "{0}": {1}' -f $vCenterServer, $error[0])
    } 

    # Validate Target Datastore
    try {
        if ($CreateMountPoints)
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
    }
    catch {
        throw ('A problem occured validating target datastore "{0}": {1}' -f $TargetDataStoreName,$error[0])
    }

    # Checking Service Account Existance
    try {
        if ($GenerateServiceAccount)
        {
            Write-Verbose ("Verifying Service account doesn't exist...")
            $Result = Get-ADUser -Filter ('samaccountname -eq "{0}"' -f $svcAccount)
            if ($Result) { throw ('Server Account "{0}" already exists' -f $svcAccount) }
            Write-Verbose ('Service Account Not found, read to create')
        } else {
            Write-Verbose ('Verifying Service account exists...')
            $Result = Get-ADUser -Filter ('samaccountname -eq "{0}"' -f $svcAccount)
            if (-Not $Result) { throw ('Server Account "{0}" does NOT exists' -f $svcAccount) }
            Write-Verbose ('Account "{0}" found in AD' -f $svcAccount)
        }
    }
    catch {
        throw ('A problem occured checking the service account: {0}' -f $error[0])
    }

    # Check Password
    try {
        if ($GenerateServiceAccount)
        {
            ##Generate Password if not specified
            if (-Not $svcAccountPassword) 
            {
                Write-Verbose ('Generating Password')
                $svcAccountPassword = ([string]'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!$%&/()=?*+#_'[(1..12 | ForEach-Object { Get-Random -Maximum 75 })]).Replace(' ','')
                Write-verbose ('Generated Password "{0}" for Account "{1}"' -f $svcAccountPassword,$svcAccount)
            } else {
                Write-Verbose ('Using provided password')
            }

        } else {
            ##Test user Password
            if (-Not $svcAccountPassword) { throw ('Not Generating account and no password provided') }
            Write-Verbose ('Testing provided user and password...')
            Add-Type -AssemblyName System.DirectoryServices.AccountManagement | Out-Null
            if (-Not (New-Object System.DirectoryServices.AccountManagement.PrincipalContext('domain')).ValidateCredentials($svcAccount,$svcAccountPassword)) {throw ('Failed testing user "{0}" with provided password' -f $svcAccount)}
            
        }
    }
    catch {
        throw ('A problem occured validating the password {0}' -f $error[0])
    }

    # Check AD Service Account OU
    try
    {
        $Result = $null
        if (!(Test-Path ('AD:\{0}' -f $SysAdminGroupOUPath)))
        {
            throw ('Invalid OU path "{0}" for Server Groups' -f $SysAdminGroupOUPath)
        }
        Write-Verbose ('OU Path: "{0}" for Server Groups is valid' -f $SysAdminGroupOUPath)

        if (!(Test-Path ('AD:\{0}' -f $svcAccountOUPath)))
        {
            throw ('Invalid OU path "{0}" for Service Accounts' -f $svcAccountOUPath)
        }
        Write-Verbose ('OU Path: "{0}" for Service Accounts is valid' -f $svcAccountOUPath)

        if (!(Test-Path ('AD:\{0}' -f $FileShareGroupOUPath)))
        {
            throw ('Invalid OU path "{0}" for Service Accounts' -f $FileShareGroupOUPath)
        }
        Write-Verbose ('OU Path: "{0}" for Service Accounts is valid' -f $FileShareGroupOUPath)
    }
    Catch
    {
        throw ('Problem Validating OU Path {0}: {1}' -f $OUPath, $error[0])
    }
    # Checking SysAdmin Group Existance
    try {
        Write-Verbose ('Checking SysAdmin Group...')
        $Result = $null
        $Result = Get-ADGroup -Filter ('name -eq "{0}"' -f $SysAdminGroup)
        if ($GenerateSysAdminGroup)
        {
            if ($Result) { throw ('AD Group "{0}" already exists' -f $SysAdminGroup) }
            Write-Verbose ('AD Group "{0}" is free to be created' -f $SysAdminGroup)
        } else {
            if (-Not $Result) { throw ('AD Group "{0}" does not exist, either set GenerateSysAdminGroup to $true or make sure the group already exists!') }
            Write-Verbose ('AD Group "{0}" found and ready to use!')
        }
    }
    catch {
        throw ('A problem occured validating SysAdmin AD Group: {0}' -f $error[0])
    }
    
    # Checking File Share Group Existance
    try {
        Write-Verbose ('Check File Share Group...')
        $Result = $null
        $Result = Get-ADGroup -Filter ('name -eq "{0}"' -f $SysAdminGroup)
        if ($GenerateFileShareGroup)
        {
            if ($Result) { throw ('AD Group "{0}" already exists' -f $FileShareGroup) }
            Write-Verbose ('AD Group "{0}" is free to be created' -f $FileShareGroup)
        } else {
            if (-Not $Result) { throw ('AD Group "{0}" does not exist, either set GenerateFileShareGroup to $true or make sure the group already exists!') }
            Write-Verbose ('AD Group "{0}" found and ready to use.')
        }
    }
    catch {
        throw ('A problem occured checking File Share Group: {0}' -f $error[0])
    }

    #endregion

    #region configure Mount Points
    if ($CreateMountPoints)
    {
        try {
            ##Get VM from ServerName
            $VM = Get-VM -Name $ServerName
            Write-Verbose ('Got VM "{0}" from vCenter' -f $vm.Name)

            ##Define List to create
            $MountPoints = @()
            if ($SQLServerVersion -eq '2016') {$MountPoints += New-Object psobject -Property @{Name='MSSQL13.MSSQLSERVER';Size=10}}
            if ($SQLServerVersion -eq '2014') {$MountPoints += New-Object psobject -Property @{Name='MSSQL12.MSSQLSERVER';Size=10}}
            if ($SQLServerVersion -eq '2012') {$MountPoints += New-Object psobject -Property @{Name='MSSQL11.MSSQLSERVER';Size=10}}
            $MountPoints += New-Object psobject -Property @{Name='SQLData1';Size=20}
            $MountPoints += New-Object psobject -Property @{Name='SQLLogs1';Size=10}
            $MountPoints += New-Object psobject -Property @{Name='TDBData1';Size=10}
            $MountPoints += New-Object psobject -Property @{Name='TDBLogs1';Size=10}

            foreach ($MP in $MountPoints)
            {
                ##Create Virtual Disk
                New-HardDisk -CapacityGB $MP.size -Datastore $TargetDatastore -VM $VM | Out-Null
                Write-Verbose ('Created Virtual Disk on "{0}" for "{1}"@{2}GB' -f $servername,$mp.name,$mp.size)

                ##Create Script to execute with PS remoting
                $Script = {
                    Param($MP)

                    ##Create Folder
                    New-Item ('E:\{0}' -f $MP.Name) -ItemType Container | Out-Null
                    Write-Verbose ('Created folder "{0}" on E:\ Drive' -f $mp.name)

                    ##Get Disk, Initialize and create partition
                    $Disk = Get-Disk | Where-Object {$_.PartitionStyle -eq 'RAW'}
                    Initialize-Disk $Disk.Number | Out-Null
                    New-Partition -DiskNumber $Disk.Number -UseMaximumSize -DriveLetter F | Format-Volume -NewFileSystemLabel ('{0}_{1}' -f $MP.Name.Split('.')[0],$env:COMPUTERNAME) -AllocationUnitSize 64Kb -Confirm:$false | Out-Null
                    Write-Verbose ('Initialized and Partitioned Disk as F:\')

                    ##Fix File System Permissions
                    $acl = Get-Acl F:\
                    $acl.RemoveAccessRule(($acl.Access | Where-Object{$_.IdentityReference -like 'creator owner'})) | Out-Null
                    $acl.RemoveAccessRule(($acl.Access | Where-Object{$_.IdentityReference -like 'Builtin\Users' -and $_.FileSystemRights -like 'AppendData'})) | Out-Null
                    $acl.RemoveAccessRule(($acl.Access | Where-Object{$_.IdentityReference -like 'Builtin\Users' -and $_.FileSystemRights -like 'CreateFiles'})) | Out-Null
                    $acl.RemoveAccessRule(($acl.Access | Where-Object{$_.IdentityReference -like 'Builtin\Users' -and $_.FileSystemRights -like 'ReadAndExecute*'})) | Out-Null
                    $acl | Set-Acl F:\ | Out-Null
                    Write-Verbose ('Removed unsecure File System permissions')

                    ##remove drive letter and configure mount point
                    Remove-PartitionAccessPath -DiskNumber $Disk.Number -PartitionNumber 2 -AccessPath F:\ | Out-Null
                    Add-PartitionAccessPath -DiskNumber $Disk.Number -PartitionNumber 2 -AccessPath ('E:\{0}' -f $MP.Name) | Out-Null
                    Write-Verbose ('Disk Configured as "E:\{0}" on "{1}"' -f $MP.Name,$ServerName)
                }
                Invoke-Command -ComputerName $vm.name -ScriptBlock $Script -ArgumentList $MP -Credential $DomainAdminCreds
            }
            Write-Verbose ('Completed Adding and Configuring disks on "{0}"' -f $ServerName)
        }
        catch {
            throw ('A problem occured configuring the mount points: {0}' -f $error[0])
        }
    }
    #endregion

    #region Create/configure accounts and scripts
    # Create Service Account
    try {
        if ($GenerateServiceAccount)
        {
            Write-Verbose ('Creating AD Service Account...')
            $result = $null
            $result = New-ADUser -Name $svcAccount -SamAccountName $svcAccount -UserPrincipalName ('{0}@{1}' -f $svcAccount,$DNSDomain) -PasswordNeverExpires $true -CannotChangePassword $True -Path $svcAccountOUPath -Credential $DomainAdminCreds
            Write-verbose ('AD User {0} created at {1}' -f $svcAccount,$svcAccountOUPath)
            Start-Sleep 5
            $result = Get-ADUser $svcAccount | Set-ADAccountPassword -NewPassword (ConvertTo-SecureString $svcAccountPassword -AsPlainText -Force) -Credential $DomainAdminCreds
            $result = Get-ADUser $svcAccount | Enable-ADAccount -Credential $DomainAdminCreds
        } else {
            write-verbose ('Using Provided username and password')
        }
    }
    catch {
        throw ('A problem occured creating the Service Account')
    }

    # Create Sysadmin Group
    try {
        if ($GenerateSysAdminGroup)
        {
            Write-Verbose ('Creating AD Group...')
            $result = $null
            $result = New-ADGroup -Name $SysAdminGroup -SamAccountName $SysAdminGroup -GroupCategory Security -GroupScope DomainLocal -Path $SysAdminGroupOUPath -Credential $DomainAdminCreds
            Write-verbose ('AD Group {0} created at {1}' -f $SysAdminGroup,$SysAdminGroupOUPath)
            Start-Sleep -Seconds 5
        } else {
            Write-Verbose ('Using Existing SysAdmin Group')
        }
    
        ##Add SQL Server specific Group to global SQL Admins Group
        $result = Get-ADGroup $SysAdminGroup | Add-ADGroupMember -Members $SQLAdminsGroup -Credential $DomainAdminCreds
        Write-verbose ('{0} added to {1} as member of group' -f $SQLAdminsGroup,$SysAdminGroup)
        
        ##Get Server local administrators group
        $LocalAdminAccount = ('Local_{0}_Administrators' -f $ServerName)

        if ((Get-ADGroup -Filter ('samaccountname -like "*{0}*"' -f $LocalAdminAccount) -ErrorAction SilentlyContinue))
        {
            Get-ADGroup $LocalAdminAccount | Add-ADGroupMember -Members $SQLAdminsGroup -Credential $DomainAdminCreds
            Write-verbose ('Adding {0} to ensure local admin access with {1}' -f $SQLAdminsGroup,$LocalAdminAccount)
        }
    }
    catch {
        throw ('A problem occured creating the SysAdmin AD Group: {0}' -f $error[0])
    }

    # Create File Share Group
    try {
        if ($GenerateFileShareGroup)
        {
            Write-Verbose ('Creating AD Group for File Share...')
            $result = $null
            $result = New-ADGroup -Name $FileShareGroup -SamAccountName $FileShareGroup -GroupCategory Security -GroupScope DomainLocal -Path $FileShareGroupOUPath -Credential $DomainAdminCreds
            Write-Verbose ('AD Group "{0}" created at "{1}"' -f $FileShareGroup, $FileShareGroupOUPath)
            Start-Sleep 5
        } else {
            Write-Verbose ('Using Existing File Share Group "{0}"' -f $FileShareGroup)
        }

        ##Add SQL Admins Group, SvcAccount and SysAdmin Groups to File Share Group
        $Result = Get-ADGroup $FileShareGroup | Add-ADGroupMember -Members $SQLADminsGroup,$svcAccount,$SysAdminGroup -Credential $DomainAdminCreds
        Write-Verbose ('Added "{0}" to "{1}"' -f ($SQLADminsGroup + ',' + $svcAccount + ',' + $SysAdminGroup),$FileShareGroup)
    }
    catch {
        throw ('A problem occured creating the File Share AD Group: {0}' -f $error[0])
    }

    # Grant remote access permissions
    try {
        Write-verbose ('Configuring Remote Access permissions...')
        $result = Add-LocalGroupMembers -ComputerName $ServerName -LocalGroupName 'Event Log Readers' -AccountObject $SysAdminGroup -Credential $DomainAdminCreds
        Write-verbose ('Added Group {0} to local Group "Event Log Readers"' -f $SysAdmingroup)
        $result = Add-LocalGroupMembers -ComputerName $ServerName -LocalGroupName 'Performance Monitor Users' -AccountObject $SysAdminGroup -Credential $DomainAdminCreds
        Write-verbose ('Added Group {0} to local Group "Performance Monitor Users"' -f $SysAdminGroup)
        $result = Add-LocalGroupMembers -ComputerName $ServerName -LocalGroupName 'Distributed COM Users' -AccountObject $SysAdminGroup -Credential $DomainAdminCreds
        Write-verbose ('Added Group {0} to local Group "Distributed COM Users"' -f $SysAdminGroup)
        $result = Add-LocalGroupMembers -ComputerName $ServerName -LocalGroupName 'Remote Management Users' -AccountObject $svcAccount -AccountObjectIsUser -Credential $DomainAdminCreds
        Write-verbose ('Added User {0} to local Group "Remote Management Users"' -f $svcAccount)
        $result = Add-LocalGroupMembers -ComputerName $ServerName -LocalGroupName 'WinRMRemoteWMIUsers__' -AccountObject $SysAdminGroup -ErrorAction SilentlyContinue -Credential $DomainAdminCreds
        Write-verbose ('Added Group {0} to local Group "WinRMRemoteWMIUsers__"' -f $SysAdminGroup)
        $result = Add-LocalGroupMembers -ComputerName $ServerName -LocalGroupName 'Remote Management Users' -AccountObject $SysAdminGroup -Credential $DomainAdminCreds
        Write-verbose ('Added Group {0} to local Group "Remote Management Users"' -f $SysAdminGroup)
    }
    catch {
        throw ('A Problem occured Configureing Remote Access: {0}' -f $error[0])
    }
    
    ##Configure Kerberos/SPN's
    try {
        Write-verbose ('Starting Kerberos/SPN configuration...')
        $Result = Get-ADUser $svcAccount | Set-ADUser -TrustedForDelegation $true -Credential $DomainAdminCreds
        Write-verbose ('Service Account {0} trusted for delegation' -f $svcAccount)
        $Result = Get-ADUser $svcAccount | Set-ADUser -ServicePrincipalNames @{Add=('MSSQLSvc/{0}' -f $ServerName)} -Credential $DomainAdminCreds
        Write-verbose ('Added SPN {0}' -f ('MSSQLSvc/{0}' -f $ServerName))
        $Result = Get-ADUser $svcAccount | Set-ADUser -ServicePrincipalNames @{Add=('MSSQLSvc/{0}:1433' -f $ServerName)} -Credential $DomainAdminCreds
        Write-verbose ('Added SPN {0}' -f ('MSSQLSvc/{0}:1433' -f $ServerName))
        $Result = Get-ADUser $svcAccount | Set-ADUser -ServicePrincipalNames @{Add=('MSSQLSvc/{0}.{1}' -f $ServerName,$dnsdomain)} -Credential $DomainAdminCreds
        Write-verbose ('added SPN {0}' -f ('MSSQLSvc/{0}.{1}' -f $ServerName,$dnsdomain))
        $Result = Get-ADUser $svcAccount | Set-ADUser -ServicePrincipalNames @{Add=('MSSQLSvc/{0}.{1}:1433' -f $ServerName,$dnsdomain)} -Credential $DomainAdminCreds
        Write-verbose ('added SPN {0}' -f ('MSSQLSvc/{0}.{1}:1433' -f $ServerName,$dnsdomain))

        ##Make sure the computer is trusted for delegation
        $Result = Get-ADComputer $ServerName | Set-ADComputer -TrustedForDelegation $true -Credential $DomainAdminCreds
        Write-verbose ('Computer account configured to be trusted for delegation')
    }
    Catch {
        throw ('Error configuring kerberos/SPNs: {0}' -f $error[0])
    }
    
    ##Generate SSL Certificate for SQL Server
    try {
        ##Check for Create-Certificate Function
        Write-verbose ('Checking for Create-Certificate Function...')
        if (!(get-command -name Create-Certificate))
        {
            throw ('Create-Certificate Function missing')
        }
        Write-verbose ('Create-Certificate Function present')

        Create-Certificate -Name $servername -CertificateTemplateName $CertificateTemplate -Locality $CertificateLocality -Organization $CertificateOrganization -OutPutPath $CertificateOutputPath | Out-Null
        Write-Verbose ('Certificate created at {0}' -f $CertificateOutputPath)
        Copy-Item $CertificateOutputPath \\$ServerName\e$\Scripts\ | Out-Null
        Write-Verbose ('Copied Certificate to \\{0}\e$\Scripts\' -f $servername)

        ##Fix ACL on Server to allow service account access
        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule ('{1}\{0}' -f $svcAccount,$dnsdomain.split('.')[0]), 'Read', 'ContainerInherit, ObjectInherit', 'None','Allow'
        $ACL = Get-Acl \\$serverName\e$\Scripts
        $acl.AddAccessRule($AccessRule) | Out-Null
        $acl | set-acl \\$servername\e$\Scripts | Out-Null
        Write-verbose ('Added Service Account {0} to have access to {1}' -f $svcAccount,("$ServerName\e$\Scripts"))
    }
    Catch {
        throw ('Problem Creating Certificate for SQL Server: {0}' -f $error[0])
    }

    # Generate Install Script
    try {
        ##Verify SQL Key is there
        If (!$SQLInstallKey) {throw 'SQL Install Key not provided.'}
        Write-verbose ('Validated SQL server key is not empty.')
        ##Verify SQL ISO Path
        if (-Not (Test-Path -Path $SQLISOPath)) { throw ('Unable to get to path {0}' -f $SQLISOPath)}
        if (-Not ($SQLISOPath -like ('*{0}*' -f $SQLServerVersion))) { throw ('ISO File does not match target version')}
        Write-verbose ('Validated SQL Server ISO File path.')
        ##Generate PowerShell Install Script
        $Script = ('##Mount ISO Image from Provided Path' + [environment]::newline) 
        $Script += ('Mount-DiskImage -ImagePath "{0}"' -f $SQLISOPath) + [environment]::newline
        $Script += ('##Change working directory to mounted ISO image' + [environment]::newline)
        $Script += ('Set-Location ((Get-Volume | ?{$_.FileSystem -eq "CDFS"} | select -first 1).DriveLetter + ":")') + [environment]::newline
        $Script += ('##Set environment variables for User/Group/Password' + [environment]::newline) 
        $Script += ('$User = "{0}"' -f $svcAccount) + [environment]::newline
        $Script += ('$Group = "{0}"' -f $SysAdminGroup) + [environment]::newline
        $Script += ('$PW = '+"'{0}'" -f $Password) + [environment]::newline
        $Script += ('##Execute Install of Software with options' + [environment]::newline) 
        $Script += ('.\setup.exe /Quiet="True" /PID="{0}" /IndicateProgress /iAcceptSQLServerLicenseTerms /Action="Install" /UpdateEnabled="False" /Features=SQLEngine,Replication,FullText,Conn /X86="False" /InstanceName="MSSQLSERVER" /InstanceID="MSSQLSERVER" /InstanceDir="e:\\" /AgtSvcAccount="ESB\$User" /SQLSVCAccount="ESB\$User" /SQLSYSADMINACCOUNTS="$Group" /InstallSQLDataDir="E:" /SQLBackupDir="E:\Backups" /SQLUSERDBDIR="E:\SQLData1" /SQLUSERDBLOGDIR="E:\SQLLogs1" /SQLTEMPDBDIR="E:\TDBData1" /SQLTEMPDBLOGDIR="E:\TDBLogs1" /SQLSVCPassword="$pw" /AGTSVCPASSWORD="$pw" /TCPEnabled=1' -f $SQLKey) + [environment]::newline
        if ($InstallMgmtStudio -and $SQLVersion -ne '2016')
        {
            ##Install SSMS from ISO matching SQL Instance
            $Script += ('.\setup.exe /Quiet="True" /PID="{0}" /IndicateProgress /iAcceptSQLServerLicenseTerms /Action="Install" /UpdateEnabled="False" /Features=SSMS,ADV_SSMS /X86="False"' -f $SQLKey)
        }
        if ($InstallMgmtStudio -and $SQLVersion -eq '2016')
        {
            ##Download and install SSMS
            $Script += ('Invoke-WebRequest -Uri https://go.microsoft.com/fwlink/?linkid=2014306 -OutFile E:\Software\SSMS.exe')
            $Script += ('E:\Software\SSMS.exe /quiet')
        }
        $Script += ($ServicePackPath + '/Action=Patch /IACCEPTSQLSERVERLICENSETERMS /QUIET /ALLINSTANCES /INDICATEPROGRESS')
        #$Script += $ServicePack

        ##Wrtie file to DB Server Scripts folder
        Set-Content -Value $Script -Path ('\\{0}\E$\\Scripts\SQLInstall.ps1' -f $ServerName)
        Write-Verbose ('Execution Script written to "{0}"' -f ("\\$Servername\e$\Scripts\SQLInstall.ps1"))
    }
    Catch {
        throw ('Problem Generating SQL Server Install Script: {0}' -f $Error[0])
    }

    # Install SQL
    try {
        ##Verify WSMan required values
        Connect-WSMan -ComputerName $ServerName -Credential $DomainAdminCreds | Out-Null   
        if ((Get-Item WSMan:\$ServerName\Shell\MaxMemoryPerShellMB).Value -lt 750) { throw 'MaxMemoryPerShellMB is below 750 MB, this needs to be adjusted to 750 or higher to allow the install process!'}
        Write-verbose ('MaxMemoryPerShellMB is at or above the min suggested of 750MB.')
        
        ##Define Script to call on remote server and create powershell remoting session
        $session = New-PSSession -ComputerName $ServerName -Credential $DomainAdminCreds

        $Script = {
            Get-content E:\Scripts\SQLInstall.ps1 | Invoke-Expression
        }
        
        ##Execute Script file on Server via PowerShell Remoting
        $result = Invoke-Command -Session $session -ScriptBlock $Script
    }
    catch {
        throw ('A problem occured instaling SQL: {0}' -f $error[0])
    }
    #endregion

}