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
        [String]$ServerName,

        [Parameter(Mandatory=$false)]
        [String]$vCenterServer,

        [Parameter(Mandatory=$false)]
        [PSCredential]$vCenterCreds,

        [Parameter(Mandatory=$true)]
        [pscredential]$DomainAdminCreds,

        [Parameter(Mandatory=$False)]
        [String]$TargetDataStoreName,

        [Parameter(Mandatory=$false)]
        [Switch]$TargetDataStoreIsCluster = $false,

        [Parameter(Mandatory=$false)]
        [Switch]$CreateMountPoints,

        [Parameter(Mandatory=$true)]
        [ValidateSet('2016','2014','2012')]
        [String]$SQLServerVersion = '2016',

        [Parameter(Mandatory=$True)]
        [String]
        $svcAccount = ('s-{0}' -f $ServerName),

        [Parameter(Mandatory=$True)]
        [String]
        $svcAccountOUPath,

        [Parameter(Mandatory=$false)]
        [String]
        $svcAccountPassword = ([string]'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!$%&/()=?*+#_'[(1..12 | ForEach-Object { Get-Random -Maximum 75 })]).Replace(' ','')
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
        
    }
    catch {
        
    }

    # Check AD Service Account OU

    # Checking SysAdmin Group Existance

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
        Write-Verbose ('Creating AD Service Account')
    }
    catch {
        
    }

    # Create Sysadmin Group
    try {
        
    }
    catch {
        
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