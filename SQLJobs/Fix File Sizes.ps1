# Set Variables
$_Instance = "$(ESCAPE_DQUOTE(SRVR))"
$LargeGrowth = 10240000
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
    $_Result += ('Getting Databases from [{0}]' -f $_Instance)
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

foreach ($_db in $_dbs) {
    if ($_db) {
        if ($_db.size -gt $LargeGrowth) {
            [int]$_GrowthSize = 1024000
        } else {
            [int]$_GrowthSize = 102400
        }
    }

    foreach ($_file in ($_db.logfiles + $_db.FileGroups.Files)) {
        if ($_file.growth -ne $GrowthSize) {
            $_file.growth = $GrowthSize
            $_file.GrowthType = 'KB'

            try {
                $_file.Alter()
                $_File.refresh()

                $_Result += ('Database [{0}] : File [{1}] - (GrowthSize [{2}])' -f $_db.name,$_file.FileName,$GrowthSize)
            } catch {
                $_Result += ('Database [{0}] : File [{1}] - Growth Size Set Failure!' -f $_db.name,$_file.FileName,$GrowthSize)
                $_JobSucceded = $false
            }
            
        }

        if ($_file.size/$GrowthSize -isnot [int]) {
            $_filesize = $_logfile.Size
            $_file.Size = ([math]::Truncate($_file.size / $GrowthSize) + 1) * $GrowthSize

            try {
                $_file.alter()
                $_file.refresh()
    
                $_Result += ('Database [{0}] : File [{1}] - (File Size [{2}]) (Previous Size [{3}])' -f $_db.name,$_file.FileName,$_file.size,$_FileSize)
            } catch {
                $_Result += ('Database [{0}] : File [{1}] - Resize Failure!' -f $_db.name,$_file.FileName)
                $_JobSucceded = $false
            }
            
        }
    }
}

if (-Not $_JobSucceded) {
    Write-Error ($_Result | out-string) -ErrorAction Stop
} else {
    Write-Output ($_Result | Out-string)
}