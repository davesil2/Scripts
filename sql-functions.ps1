function Copy-DatabaseTables {
    <#
    .SYNOPSIS
    Copy one or more tables from a source SQL Server database to a destination SQL Server database.

    .DESCRIPTION
    This function imports the SqlServer module, enumerates tables in the source database, and optionally copies a single table or all tables to the destination database.
    If the destination table exists and -DropTableIfExists is specified, the table is dropped and recreated before data is copied.

    .PARAMETER SourceServer
    The host name or network name of the source SQL Server instance.

    .PARAMETER SourceInstanceName
    The instance name on the source server. Defaults to 'Default'.

    .PARAMETER SourceDatabase
    The source database name that contains the tables to copy.

    .PARAMETER SourceTable
    Optional table name to copy. If omitted, all tables in the source database are copied.

    .PARAMETER DestinationServer
    The host name or network name of the destination SQL Server instance.

    .PARAMETER DestinationInstanceName
    The instance name on the destination server. Defaults to 'Default'.

    .PARAMETER DestinationDatabase
    The destination database name where tables and data will be written.

    .PARAMETER DropTableIfExists
    If specified, existing destination tables are dropped before creation.

    .EXAMPLE
    Copy-DatabaseTables -SourceServer 'SRC01' -SourceDatabase 'Sales' -DestinationServer 'DST01' -DestinationDatabase 'Reports'

    .EXAMPLE
    Copy-DatabaseTables -SourceServer 'SRC01' -SourceDatabase 'Sales' -SourceTable 'Orders' -DestinationServer 'DST01' -DestinationDatabase 'Reports' -DropTableIfExists
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SourceServer,

        [Parameter(Mandatory=$false)]
        [string]$SourceInstanceName = 'Default',

        [Parameter(Mandatory=$true)]
        [string]$SourceDatabase,

        [Parameter(Mandatory=$false)]
        [string]$SourceTable,

        [Parameter(Mandatory=$true)]
        [string]$DestinationServer,

        [Parameter(Mandatory=$false)]
        [string]$DestinationInstanceName = 'Default',

        [Parameter(Mandatory=$true)]
        [string]$DestinationDatabase,

        [Parameter(Mandatory=$false)]
        [switch]$DropTableIfExists
    )

    # Ensure the SqlServer module is available.
    Import-Module SqlServer -ErrorAction Stop | Out-Null

    $sourcePath = "SQLSERVER:\\SQL\\$SourceServer\\$SourceInstanceName\\Databases\\$SourceDatabase\\Tables"
    $destinationPath = "SQLSERVER:\\SQL\\$DestinationServer\\$DestinationInstanceName\\Databases\\$DestinationDatabase\\Tables"

    # Retrieve the list of source tables, optionally filtering by a single table name.
    $SourceTables = Get-ChildItem -Path $sourcePath
    if ($SourceTable) {
        $SourceTables = $SourceTables | Where-Object { $_.Name -eq $SourceTable }
    }

    # Retrieve destination tables once for existence checks.
    $DestinationTables = Get-ChildItem -Path $destinationPath

    foreach ($Table in $SourceTables) {
        $TableName = $Table.Name
        $TableSchema = $Table.Schema
        $QualifiedTableName = "[$TableSchema].[$TableName]"

        # Determine whether the destination table already exists.
        $DestinationTable = $DestinationTables | Where-Object { $_.Name -eq $TableName -and $_.Schema -eq $TableSchema }

        if ($DestinationTable -and $DropTableIfExists) {
            Write-Verbose "Dropping existing destination table $QualifiedTableName"
            $DestinationTable.Drop()
            $DestinationTable = $null
        }

        if (-not $DestinationTable) {
            Write-Verbose "Creating destination table $QualifiedTableName"
            $TableDDL = $Table.Script() | Out-String
            Invoke-Sqlcmd -ServerInstance $DestinationServer -Database $DestinationDatabase -TrustServerCertificate -Query $TableDDL
        }

        # Copy row data from the source table to the destination table.
        Write-Verbose "Copying data for table $QualifiedTableName"
        $TableData = Invoke-Sqlcmd -ServerInstance $SourceServer -Database $SourceDatabase -TrustServerCertificate -Query "SELECT * FROM $QualifiedTableName"

        if ($TableData) {
            Write-SqlTableData -ServerInstance $DestinationServer `
                -DatabaseName $DestinationDatabase `
                -SchemaName $TableSchema `
                -TableName $TableName `
                -TrustServerCertificate `
                -InputData $TableData 
        }
        else {
            Write-Verbose "No rows found in source table $QualifiedTableName"
        }
    }
}
