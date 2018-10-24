function Configure-IISServer
{
    <#
    .SYNOPSIS
    Install and configure IIS on specified Server
    
    .DESCRIPTION
    Provides a standard tool that has pre-defined components and configuration to ensure a standard implementation of IIS with components.

    Additionally, this function will allow you to customize the configuration as necessary.
    
    .EXAMPLE
    $Creds = Get-Credential

    Configure-IIS -ServerName <name of server> -AdminCreds $creds

    This example shows a basic usage.  The Drive Letter and Roles and Features are pre-selected in the default values

    .EXAMPLE
    $creds = Get-Credential

    Configure-IISServer -ServerName <Name of Server> -AdminCreds $Creds -RootDriveLetter I -RolesAndFeatures ('Web-Server','Web-WebServer')

    .PARAMETER ServerName
    The name of the server to install and configure IIS on

    .PARAMETER AdminCreds
    Credentials as defined in the System.Management.Automation.PSCredential type.  Commonly this is the return value of Get-Credential

    .PARAMETER RootDriveLetter
    The Letter of the Drive IIS InetPub and sub folders will be moved to

    Default Value = E

    .PARAMETER RolesandFeatures
    The Roles and Features to include as part of the IIS Config/Install

    Default Value = ('Web-Server','Web-Common-Http','Web-Default-Doc','Web-Dir-Browsing','Web-Http-Errors','Web-Static-Content','Web-Health','Web-http-logging','Web-custom-logging','web-http-tracing','web-performance','web-stat-compression','web-dyn-compression','web-security','web-filtering','web-basic-auth','web-ip-security','web-url-auth','web-windows-auth','web-app-dev','web-net-ext45','web-appinit','web-asp','web-asp-net45','web-isapi-ext','web-isapi-filter','web-mgmt-console','web-mgmt-service','Web-Log-Libraries','Web-Request-Monitor','Web-Digest-Auth','Web-Mgmt-Compat','Web-Metabase','Web-Lgcy-Scripting','Web-WMI')

    #>
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateLength(1,15)]
        [String]$ServerName,

        [Parameter(Mandatory=$True)]
        [System.Management.Automation.PSCredential]$AdminCreds,

        [Parameter(Mandatory=$false)]
        [ValidateLength(1,1)]
        [String]$RootDriveLetter = 'E',

        [Parameter(Mandatory=$false)]
        [ValidateSet('Web-Application-Proxy','Web-Server','Web-WebServer','Web-Common-Http','Web-Default-Doc','Web-Dir-Browsing','Web-Http-Errors','Web-Static-Content','Web-Http-Redirect','Web-DAV-Publishing','Web-Health','Web-Http-Logging','Web-Custom-Logging','Web-Log-Libraries','Web-ODBC-Logging','Web-Request-Monitor','Web-Http-Tracing','Web-Performance','Web-Stat-Compression','Web-Dyn-Compression','Web-Security','Web-Filtering','Web-Basic-Auth','Web-CertProvider','Web-Client-Auth','Web-Digest-Auth','Web-Cert-Auth','Web-IP-Security','Web-Url-Auth','Web-Windows-Auth','Web-App-Dev','Web-Net-Ext','Web-Net-Ext45','Web-AppInit','Web-ASP','Web-Asp-Net','Web-Asp-Net45','Web-CGI','Web-ISAPI-Ext','Web-ISAPI-Filter','Web-Includes','Web-WebSockets','Web-Ftp-Server','Web-Ftp-Service','Web-Ftp-Ext','Web-Mgmt-Tools','Web-Mgmt-Console','Web-Mgmt-Compat','Web-Metabase','Web-Lgcy-Mgmt-Console','Web-Lgcy-Scripting','Web-WMI','Web-Scripting-Tools','Web-Mgmt-Service','Web-WHC')]
        [String[]]$RolesandFeatures = ('Web-Server','Web-Common-Http','Web-Default-Doc','Web-Dir-Browsing','Web-Http-Errors','Web-Static-Content','Web-Health','Web-http-logging','Web-custom-logging','web-http-tracing','web-performance','web-stat-compression','web-dyn-compression','web-security','web-filtering','web-basic-auth','web-ip-security','web-url-auth','web-windows-auth','web-app-dev','web-net-ext45','web-appinit','web-asp','web-asp-net45','web-isapi-ext','web-isapi-filter','web-mgmt-console','web-mgmt-service','Web-Log-Libraries','Web-Request-Monitor','Web-Digest-Auth','Web-Mgmt-Compat','Web-Metabase','Web-Lgcy-Scripting','Web-WMI')
    )

    #region Validate Variables
    ##Test Server Exists
    try {
        Write-Verbose ('Checking if Server exists via Ping...')
        ### Simple Ping Test for IP address usage
        if ((new-object System.Net.NetworkInformation.Ping).Send($ServerName).Status -ne 'Success')
        {
            throw ('Server "{0}" appears to be inaccessible' -f $ServerName)
        }
        Write-Verbose ('IP Address {0} not responding to ping...' -f $ServerName)
    }
    catch {
        throw ('Problem occured checking server: {0}' -f $error[0])
    }
    ##Test Admin Credentials
    try {
        Write-Verbose ('Testing Admin Credentials...')
        Connect-WSMan -ComputerName $ServerName -Credential $AdminCreds
        Write-Verbose ('Succesfully connected "{0}" with Credentials {1}' -f $ServerName,$AdminCreds.UserName)
    }
    catch {
        throw ('Problem testing Admin Credentials to server {0}: {1} ' -f $servername,$error[0])
    }
    
    ##Verify Drive Exists
    try {
        Write-Verbose ('Checking for Drive Letter...')
        $result = Invoke-Command -ComputerName $ServerName -ScriptBlock ([scriptblock]::Create("Get-Volume -DriveLetter $RootDriveLetter")) -ErrorAction SilentlyContinue
        if (!$result) { throw 'Drive Letter not found!'}
        Write-Verbose ('Drive Letter "{0}" found on {1}' -f $RootDriveLetter,$servername)
    }
    catch {
        throw ('Drive letter specified "{0}" does not exist' -f $RootDriveLetter)
    }

    Write-Host ('Variable Validated, Moving on to Install and Configure...')
    #endregion

    #region Install and configure IIS Role
    ##Install Roles for IIS
    try {
        $result = $null
        Write-Verbose ('Starting Roles and Features Install...')
        $Script = {
            Add-WindowsFeature $RolesandFeatures
        }
        $result = Invoke-Command -ComputerName $ServerName -ScriptBlock $Script  
        Write-Verbose ('Windows Features {0} Installed on {1}' -f $RolesandFeatures,$ServerName)  
    }
    catch {
        throw ('Problem Installing IIS Features {0} on server {1}' -f $RolesandFeatures,$ServerName)
    }
    
    ##Configure IIS Role and Move to alternate drive
    if ($RootDriveLetter -ne 'C')
    {
        ##Define Script to Move IIS
        $Script = {
            ##Import WebAdministration Module
            Get-Module -ListAvailable WebAdministration | Import-Module -ErrorAction SilentlyContinue
    
            ##Backup current configuration and stop services
            Backup-WebConfiguration -Name 'BeforeRootMove'
            Stop-Service W3SVC,WAS,WMSVC -Force -ErrorAction Continue
    
            ##Create New Root path and copy ACLs
            New-Item ('{0}:\InetPub' -f $RootDriveLetter) -ItemType Container
            Get-ACL -Path C:\InetPub | Set-ACL -Path ('{0}:\InetPub' -f $RootDriveLetter)
    
            ##Copy Files from C:\InetPub to new path
            $files = Get-ChildItem C:\InetPub -recurse
            ForEach ($file in $files)
            {
                Copy-Item -LiteralPath $file.FullName -Destination $file.FullName.Replace('C:',('{0}:' -f $RootDriveLetter))
                Get-Acl -Path $file.FullName | Set-Acl -Path $file.FullName.Replace('C:',('{0}:' -f $RootDriveLetter))
            }
    
            ##move source lcoation for IIS files
            Set-WebConfigurationProperty "/system.applicationHost/sites/siteDefaults" -name "traceFailedRequestsLogging.Directory" -Value "$RootDriveLetter:\InetPub\Logs\FailedRequestLogFiles"
            Set-WebConfigurationProperty "/system.applicationHost/sites/siteDefaults" -name "LogFile.Directory" -Value "$RootDriveLetter:\InetPub\Logs\LogFiles"
            Set-WebConfigurationProperty "/system.applicationHost/log" -name "centralBinaryLogFile.directory" -Value "$RootDriveLetter:\InetPub\Logs\LogFiles"
            Set-WebConfigurationProperty "/system.applicationHost/log" -name "centralW3CLogFile.directory" -Value "$RootDriveLetter:\InetPub\Logs\LogFiles"
            Set-WebConfigurationProperty "/system.applicationHost/configHistory" -name "Path" -Value "$RootDriveLetter:\InetPub\History"
            Set-WebConfigurationProperty "/system.webServer/asp" -name "cache.disktemplateCacheDirectory" -Value "$RootDriveLetter:\InetPub\Temp\ASP Compiled Templates"
            Set-WebConfigurationProperty "/system.webServer/httpCompression" -name "directory" -Value "$RootDriveLetter:\InetPub\Temp\IIS Temporary Compressed Files"
            Set-ItemProperty 'IIS:\Sites\Default Web Site' -Name 'PhysicalPath' -Value "$RootDriveLetter:\InetPub\WWWRoot"
            Set-WebConfigurationProperty  "/system.WebServer/HttpErrors/error[@statusCode='401']" -name "prefixLanguageFilePath" -Value "$RootDriveLetter:\InetPub\CustErr"
            Set-WebConfigurationProperty  "/system.WebServer/HttpErrors/error[@statusCode='403']" -name "prefixLanguageFilePath" -Value "$RootDriveLetter:\InetPub\CustErr"
            Set-WebConfigurationProperty  "/system.WebServer/HttpErrors/error[@statusCode='404']" -name "prefixLanguageFilePath" -Value "$RootDriveLetter:\InetPub\CustErr"
            Set-WebConfigurationProperty  "/system.WebServer/HttpErrors/error[@statusCode='405']" -name "prefixLanguageFilePath" -Value "$RootDriveLetter:\InetPub\CustErr"
            Set-WebConfigurationProperty  "/system.WebServer/HttpErrors/error[@statusCode='406']" -name "prefixLanguageFilePath" -Value "$RootDriveLetter:\InetPub\CustErr"
            Set-WebConfigurationProperty  "/system.WebServer/HttpErrors/error[@statusCode='412']" -name "prefixLanguageFilePath" -Value "$RootDriveLetter:\InetPub\CustErr"
            Set-WebConfigurationProperty  "/system.WebServer/HttpErrors/error[@statusCode='500']" -name "prefixLanguageFilePath" -Value "$RootDriveLetter:\InetPub\CustErr"
            Set-WebConfigurationProperty  "/system.WebServer/HttpErrors/error[@statusCode='501']" -name "prefixLanguageFilePath" -Value "$RootDriveLetter:\InetPub\CustErr"
            Set-WebConfigurationProperty  "/system.WebServer/HttpErrors/error[@statusCode='502']" -name "prefixLanguageFilePath" -Value "$RootDriveLetter:\InetPub\CustErr"
            Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\InetStp -Name PathWWWRoot -Value '$RootDriveLetter:\InetPub\wwwroot' -Force
            Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\InetStp -Name PathFTPRoot -Value '$RootDriveLetter:\InetPub\wwwroot' -Force
            Set-ItemProperty -Path HKLM:\system\CurrentControlSet\Services\was\Parameters -Name ConfigIsolationPath -Value '$RootDriveLetter:\InetPub\temp\AppPools' -Force
            If ([environment]::Is64BitOperatingSystem)
            {
                Set-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\InetStp -Name PathWWWRoot -Value '$RootDriveLetter:\InetPub\wwwroot' -Force
                Set-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\InetStp -Name PathFTPRoot -Value '$RootDriveLetter:\InetPub\wwwroot' -Force
            }
            Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name LoggingDirectory -Value '$RootDriveLetter:\InetPub\logs\WMSvc' -Force
            Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name EnableRemoteManagement -Value 1 -Force
    
            #### Start Services
            Start-Service W3SVC,WAS,WMSVC
            Set-Service wmsvc -StartupType Automatic

            ##Cleanup old path
            Remove-Item C:\Inetpub -Recurse
        }
        $result = Invoke-Command -ComputerName $ServerName -ScriptBlock $Script
        Write-Verbose ('Completed moving IIS')

        ##Configure SSL Cert for Remote Management
        try {
            $Script = {
                Stop-Service wmsvc -force
                Write-Verbose ('Updating Certificate for Web Mgmt Service')
                $cert = gci Cert:\LocalMachine\My | ?{$_.subject -like "*CN=" + $env:COMPUTERNAME + "*"}
                if ($cert)
                {
                    Write-Verbose ('Found Certificate to replace self signed')
                    Remove-Item IIS:\SSLBindings\0.0.0.0!8172
                    $Cert | New-Item IIS:\SSLBindings\0.0.0.0!8172
                    Write-Verbose ('Updated SSL Cert')
                }
                Start-Service wmsvc
            }
            $result = Invoke-Command -ComputerName $ServerName -ScriptBlock $Script -Credential $AdminCreds
            Write-Verbose ('Completed Updating SSL Certificate')
        }
        catch {
            write-warning ('A Problem occured trying to configure remote management service certificate: {0}' -f $error[0])
        }
            
        ##Remove Example Application Pools
        try {
            Write-Verbose ('Removing unused and sample AppPools...')
            $Script = {
                import-module webadministration
                remove-item iis:\apppools\*.net* -force -confirm:$false -recurse    
            }
            $result = Invoke-Command -ComputerName $ServerName -ScriptBlock $Script -Credential $AdminCreds
            Write-Verbose ('Completed AppPool Cleanup.')
        }
        catch {
            write-warning ('A problem occured cleaning up the apppools unused/examples: {0}' -f $error[0])
        }        
    }

    #endregion
}