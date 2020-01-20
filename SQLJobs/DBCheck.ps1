# Set Variables
$_Instance = "$(ESCAPE_DQUOTE(SRVR))"

# fix Instance if default
if ($_Instance -notlike '*\*') {
    ('Using Default Instance...')
    $_Instance += "\Default"
}

# Connect to SQL Instance
('Connecting to "{0}"' -f $_Instance)
$_SQL = Get-Item "SQLServer:\SQL\$_Instance"

try {
    ('Getting Databases from [{0}]' -f $_Instance)
    $_dbs = Get-ChildItem ("SQLSERVER:\SQL\$_instance\Databases") -Force | Where-Object {$_.Status -eq 'Normal' -and $_.Name -ne 'TempDB' -and $_.name -ne 'Model'}
} catch {
    throw ('Error getting databases from server: {0}' -f $error[0].message)
}

# Filter DB's that can't be backed up
if ($_SQL.isClustered) {
    ("Filtering Clustered DB's that are not Primary...")
    $_dbs = $_dbs | Where-Object {!($_.AvailabilityGroupName) -or ($SQLServer.AvailabilityGroups[$_.availabilityGroupName].LocalReplicaRole -eq 'Primary')}
}

foreach ($_db in $_dbs) {
    if ($_db -and $_db.tables) {
        try {
            $db.CheckTables('None')
            ('Database [{0}] Check Completed.' -f $_db.name)
        } catch {
            ('Database [{0}] Check Failed!' -f $_db.name)
        }
    }
}