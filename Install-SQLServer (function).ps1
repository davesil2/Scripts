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
        [PSCredential]$vCenterCreds,
        [pscredential]$DomainAdminCreds,
        [String]$TargetDataStoreName,
        [Switch]$CreateMountPoints,
        [Parameter(Mandatory=$true)]
        [ValidateSet('2016','2014','2012')]
        [String]$SQLServerVersion = '2016'
    )

    #region Validate Input
    # Check Server Exists

    # 
    #endregion

    #region configure Mount Points
    if ($CreateMountPoints)
    {
        try {
            ##Connect to vCenter

            ##Get VM from ServerName
            $VM = Get-VM -Name $ServerName
            Write-Verbose ('Got VM {0} from vCenter' -f $vm.Name)

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
                    $acl.RemoveAccessRule(($acl.Access | ?{$_.IdentityReference -like 'creator owner'})) | Out-Null
                    $acl.RemoveAccessRule(($acl.Access | ?{$_.IdentityReference -like 'Builtin\Users' -and $_.FileSystemRights -like 'AppendData'})) | Out-Null
                    $acl.RemoveAccessRule(($acl.Access | ?{$_.IdentityReference -like 'Builtin\Users' -and $_.FileSystemRights -like 'CreateFiles'})) | Out-Null
                    $acl.RemoveAccessRule(($acl.Access | ?{$_.IdentityReference -like 'Builtin\Users' -and $_.FileSystemRights -like 'ReadAndExecute*'})) | Out-Null
                    $acl | Set-Acl F:\ | Out-Null
                    Write-Verbose ('Removed unsecure File System permissions')

                    ##remove drive letter and configure mount point
                    Remove-PartitionAccessPath -DiskNumber $Disk.Number -PartitionNumber 2 -AccessPath F:\ | Out-Null
                    Add-PartitionAccessPath -DiskNumber $Disk.Number -PartitionNumber 2 -AccessPath ('E:\{0}' -f $MP.Name) | Out-Null
                    Write-Verbose ('Disk Configured as "E:\{0}" on "{1}"' -f $MP.Name,$ServerName)
                }
                Invoke-Command -ComputerName $vm.name -ScriptBlock $Script -ArgumentList $MP -Credential $DomainAdminCreds
                Write-Verbose ('Completed Adding and Configuring disks on "{0}"' -f $ServerName)
            }
        }
        catch {
            throw ('')
        }
    }
    #endregion

    #region Create/configure accounts and scripts
    # Create Service Account

    # Create Sysadmin Group

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