# Set Variables
$_Instance = "$(ESCAPE_DQUOTE(SRVR))"
$_DaysBack = -2
$_Extension = 'bak'
$_BackupAction = 'Database'
$_BackupRoot = ('\\{0}\Backup\SQLTemp\' -f $env:USERDNSDOMAIN)
$_JobSucceded = $true
$_Result = @()

# fix Instance if default
if ($_Instance -notlike '*\*') {
    $_Result += ('Using Default Instance...')
    $_Instance += "\Default"
}

# Connect to SQL Instance
$_Result += ('Connecting to "{0}"' -f $_Instance)
$_SQL = Get-Item "SQLServer:\SQL\$_Instance"

try {
    $_Result += ('Getting Databases from "{0}"' -f $_Instance)
    $_dbs = Get-ChildItem ("SQLSERVER:\SQL\$_instance\Databases") -Force | Where-Object {$_.Status -eq 'Normal' -and $_.Name -ne 'TempDB' -and $_.name -ne 'Model'}
} catch {
    $_Result += ('Error getting databases from server: {0}' -f $error[0].message)
    $_JobSucceded = $false
}

# Filter DB's that can't be backed up
if ($_SQL.isClustered) {
    $_Result += ("Filtering Clustered DB's that are not Primary...")
    $_dbs = $_dbs | Where-Object {!($_.AvailabilityGroupName) -or ($SQLServer.AvailabilityGroups[$_.availabilityGroupName].LocalReplicaRole -eq 'Primary')}
}

# Filter DB's Based on Action Type
if ($_BackupAction -eq 'log') {
    $_Result += ('Backup Type is Log Backup...removing DBs with Recovery Model of Simple')
    $_dbs = $_dbs | Where-Object {$_.RecoveryModel -ne 'Simple'}
}

# if there are DB's, start to backup
if ($_dbs) {
    $_Result += ('Getting ready to backup DBs "{0}"' -f (($_dbs | Select-Object -expandproperty name) -join ','))

    # configure backup location
    if ($_SQL.BackupDirectory) {
        $_Result += ('Using SQL Server Default Backup Directory')
        $_backupDir = $_SQL.BackupDirectory
    } else {
        $_Result += ('Using Network Share Root "{0}" - No Default Set' -f $_BackupRoot)
        $_backupDir = ('{0}\{1}\' -f $_backupRoot,$env:COMPUTERNAME)
    }

    # Set backup location for current directory
    Set-Location $_backupDir -ErrorAction SilentlyContinue
    $_Result += ('Backup Location set to "{0}"' -f $_backupDir)

    # Step through DB's
    foreach ($_db in $_dbs) {
        if ($_db) {
            # Backup Current DB
            try {
                $_filepath = ('{0}\{1}_{2}.{3}' -f $_backupDir, $_db.name, (get-date).ToString('MM-dd-yyyy_hh-mm-ss'),$_Extension)
                $_Start = (get-date)
                $_Result += ('Backing up DB "{0}" to Path "{1}"...' -f $_db.name,$_filepath)

                # load libraries to use SQL SMO and Backup (regardless of PS version loaded)
                [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO') | Out-Null
                $_backup = New-Object Microsoft.SqlServer.Management.SMO.backup
                $_backup.Database = $_db.name
                $_backup.Devices.AddDevice($_filepath,'File')
                $_backup.Action = $_BackupAction
                $_backup.SQLBackup($_SQL)
                $_Stop = (get-date)

                $_Result += ('Backup of DB "{0}" took "{1}" seconds to backup' -f $_db.name,($_stop - $_start).TotalSeconds)
            } catch {
                $_Result += ('An Error occured backing up DB "{0}": {1}' -f $_db.name,$error[0].Message)
                $_JobSucceded = $false
            }

            # Cleanup Files Older that $_DaysBack
            try {
                # Only perform Cleanup if $_DaysBack has a value and is Less than 0
                if ($_DaysBack -and $_DaysBack -lt 0) {
                    $_Result += ('Removing Files Older than "{0}" for DB "{1}" from "{2}"' -f $_DaysBack, $_db.name,$_backupDir)
                    Set-Location 'C:\' | Out-Null
                    $_files = Get-ChildItem -Path $_backupDir | Where-Object {$_.Name -like ('{0}*.{1}' -f $_db.name,$_Extension) -and $_.LastWriteTime -lt (get-date).AddDays($_DaysBack)}
                    if ($_files.Count -gt 0) {
                        foreach ($_file in $_files) {
                            $_Result += ('Removing file "{0}" for DB "{1}"' -f $_file.fullname, $_db.name)
                            $_File | Remove-Item -Force -Confirm:$false
                        }
                    }
                }
            } catch {
                $_Result += ('An error occured removing files for DB "{0}": "{1}"' -f $_db.name,$error[0])
                $_JobSucceded = $false
            }
        }
    }
} else {
    $_Result += ('No Databases for Backup')
}

if (-Not $_JobSucceded) {
    Write-Error ($_Result | out-string) -ErrorAction Stop
} else {
    Write-Output ($_Result | Out-string)
}