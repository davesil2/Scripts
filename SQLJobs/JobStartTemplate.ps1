$_Instance = "$(ESCAPE_DQUOTE(SRVR))"
                        
# fix Instance if default
if ($_Instance -notlike "*\*") {
    ("Using Default Instance...")
    $_Instance += "\Default"
}

$SQL = Get-Item SQLSERVER:\SQL\$_Instance

$Job = $SQL.JobServer.Jobs[{0}]

$Job.Start()

do {
    Start-Sleep 30

    $Job.Refresh()
} While ($Job.CurrentRunStatus -eq "Executing")