function Install-SQLServer {
    <#
    .SYNOPSIS
    <to be written>
    .DESCRIPTION
    <to be written>
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
        $SQLADminsGroup = 'SQL Admins'
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

    # Grant remote access permissions

    # Configure Kerberos/SPN's

    # Create Certificate

    # Generate Install Script

    # Install SQL

    #endregion

    #region Configure SQL Server
    # Install SSL Certificate

    # limit AD Service account rights

    # Remove SQL Powershell signed scripts restriction

    # Configure Services for auto start

    # Configure TCP and Named Pipes

    # Configure Service Delegation

    # Configure windows share and file permissions

    # Configure File Type Restrictions (FSRM)

    # Configure PowerShell Profile for SQL Permissions

    # Configure DFS Share

    # Restart Server

    # Set Max Memory usage

    # Enable Backup Compression

    # Configure DB Mail

    # Increase Job history

    # Update Database Settings (Size and Recovery type)

    # Create db_exec role on model db

    #endregion

    #region Configure DB Maintenance Jobs in SQL Agent

    #endregion

}