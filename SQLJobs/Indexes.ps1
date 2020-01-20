# Set Variables
$_Instance = "$(ESCAPE_DQUOTE(SRVR))"
$rebuildfragmentationlevel = 30
$reorganizefragmentationlevel = 5

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

# Rebuild Indexes
foreach ($_db in $_dbs) {
    foreach ($_table in $_db.Tables) {
        foreach ($_index in $_table.indexes) {
            if ($_index -ne $null) {
                $_frag = $_index.EnumFragmentation() | Select-Object -First 1 *

                if ($_frag.averagefragmentation -gt $rebuildfragmentationlevel) {
                    try {
                        $_index.RebuildAllIndexes()
                        $_index.Alter()

                        ('Database [{0}] : Index [{1}] - Fragmentation [{2}] - Rebulid Success!' -f $_db.Name,$_index.Name,[int]$_frag.averagefragmentation)
                    } catch {
                        ('Database [{0}] : Index [{1}] - Fragmentation [{2}] - Rebulid Failed!' -f $_db.Name,$_index.Name,[int]$_frag.averagefragmentation)
                    }
                } elseif ($_frag.averagefragmentation -gt $reorganizefragmentationlevel) {
                    try {
                        $_index.ReorganizeAllIndexes()
                        $_index.Alter()

                        ('Database [{0}] : Index [{1}] - Fragmentation [{2]} - Reorganize Success!' -f $_db.name,$_index.name,[int]$_frag.averagefragmentation)
                    } catch {
                        ('Database [{0}] : Index [{1}] - Fragmentation [{2]} - Reorganize Failed!' -f $_db.name,$_index.name,[int]$_frag.averagefragmentation)
                    }
                } else {
                    ('Database [{0}] : Index [{1}] - Fragmentation [{2}] - Fragmentation Not High enough!' -f $_db.name,$_index.name,[int]$_frag.averagefragmentation)
                }

                $_index.Refresh()
            }
        }
    }
}