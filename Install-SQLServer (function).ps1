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
        [Switch]$CreateMountPoints
    )

    #region Validate Input
    # Check Server Exists

    # 
    #endregion

    #region configure Mount Points

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