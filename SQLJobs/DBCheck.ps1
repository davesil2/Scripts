# Set Variables
$_Instance = "$(ESCAPE_DQUOTE(SRVR))"
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
    if ($_db -and $_db.tables) {
        try {
            $_db.CheckTables('None')
            $_Result += ('Database [{0}] - Check Completed.' -f $_db.name)
        } catch {
            $_Result += ('Database [{0}] - Check Failed!' -f $_db.name)
            $_JobSucceded = $false
        }
    }
}

if (-Not $_JobSucceded) {
    Write-Error ($_Result | out-string) -ErrorAction Stop
} else {
    Write-Output ($_result | Out-string)
}