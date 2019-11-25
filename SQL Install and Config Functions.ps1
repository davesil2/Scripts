#region SQL Supporting Functions
function Test-PSRemoting {
    [cmdletBinding()]
    Param(
        # Server to Create Remoting Session with
        [parameter(Mandatory=$true)]
        [string]
        $ServerName,

        # Credentials to connect to remote server
        [parameter(Mandatory=$false)]
        [PSCredential]
        $ServerCreds,

        # Return True or False based on success/failure
        [parameter(Mandatory=$false)]
        [switch]
        $Quiet
    )

    #region Create Session
    if ($ServerCreds) {
        $_Session = New-PSSession -ComputerName $ServerName -Credential $ServerCreds -Authentication Kerberos -ErrorAction SilentlyContinue
    } else {
        $_Session = New-PSSession -ComputerName $ServerName -Authentication Kerberos -ErrorAction SilentlyContinue
    }
    #endregion

    if ($_Session) {
        If ($Quiet) {
            return $true
        }
        return $_Session
    } else {
        if ($Quiet) {
            return $false
        }
        return $null
    }

    <#
    .SYNOPSIS

    Test PS Remoting Connection to server and return session object

    .DESCRIPTION

    Verify the Server Access with PS Remoting.  Quiet returns true false, otherwise the session is returned or nothing.

    .EXAMPLE

    $Creds = Get-Credential domain\user

    Test-PSRemoting -ServerName 'Server01' -ServerCreds $Creds
    #>
}

function Test-PSModuleInstalled {
    [cmdletBinding()]
    Param(
        # PS Session to use (get from test-psremoting)
        [Parameter(Mandatory=$true)]
        [pssession]
        $Session,

        # Name of PS Module to Check for
        [Parameter(Mandatory=$true)]
        [string]
        $ModuleName,

        # try to Install the module if not found (using Install-Module)
        [parameter(Mandatory=$false)]
        [switch]
        $Install
    )

    #region Check Session
    $_Session = $Session
    if (-Not $_Session -or $_Session.state -ne 'Opened') {
        Write-Error ('there is a problem with the Session provided') -ErrorAction Continue
        return $false
    }
    #endregion

    $GetModuleScript = ([scriptblock]::Create("Get-Module -ListAvailable $ModuleName"))

    if (-Not (Invoke-Command -Session $_Session -ScriptBlock $GetModuleScript -ErrorAction SilentlyContinue)) {
        if ($Install) {
            Invoke-Command -Session $_Session -ScriptBlock {
                Param($ModuleName)
                Install-Module -Name $ModuleName -Force -SkipPublisherCheck -Confirm:$false
            } -ArgumentList $ModuleName -ErrorAction SilentlyContinue

            Write-Verbose ('{0}: Installing PS Module "{1}" Found on Server "{2}"' -f (get-date).tostring(),$ModuleName,$Session.ComputerName)

            if (-Not (Invoke-Command -Session $_Session -ScriptBlock $GetModuleScript -ErrorAction SilentlyContinue)) {
                Write-Warning ('{0}: Failed to Install PS Module "{1}" Found on Server "{2}"' -f (get-date).tostring(),$ModuleName,$Session.ComputerName)
                return $false
            }
        }
        Write-Warning ('{0}: PS Module "{1}" NOT Found on Server "{2}"' -f (get-date).tostring(),$ModuleName,$Session.ComputerName)
        return $False
    }

    Write-Verbose ('{0}: PS Module "{1}" Found on Server "{2}"' -f (get-date).tostring(),$ModuleName,$Session.ComputerName)
    return $true

    <#
    .SYNOPSIS

    Check for PowerShell Module existing on Server Session

    .DESCRIPTION

    In order to be able to execute powershell functions, their modules are required.  This function will verify if the module exists on the remote server session and install if not there when specified.

    .EXAMPLE

    $_Session = Test-PSRemoting -ServerName 'Server01' -ServerCreds (Get-Credential)
    Test-PSModuleInstalled -Session $_Session -ModuleName SQLServer

    #>
}

function Test-SQLConnection {
    [cmdletBinding()]
    Param(
        # PS Remoting Session to use (get from Test-PSremoting function)
        [Parameter(Mandatory=$true)]
        [pssession]
        $Session,

        # Name of SQL Instance
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $SQLInstance = 'Default',

        # Return True or False only
        [Parameter(Mandatory=$false)]
        [switch]
        $Quiet
    )

    #region Verify Session
    $_Session = $Session
    if (-Not $_Session -or $_session.State -eq 'Opened') {
        Write-Error ('PS Session is invalid') -ErrorAction Continue
        if ($Quiet) {
            Return $false
        }
        return $null
    }
    #endregion

    #region Verify SQLServer PS Module
    if (-Not (Test-PSModuleInstalled -Session $_Session -ModuleName SQLServer)) {
        Write-Error ('PS Module SQLServer Not Found') -ErrorAction Continue
        if ($Quiet) {
            Return $false
        }
        return $null
    }
    #endregion

    #region Connect to SQL
    $Script = [scriptblock]::Create('$SQL = Get-Item "SQLSERVER:\SQL\{0}\{1}"' -f $_Session.ComputerName,$SQLInstance)
    Invoke-Command -Session $_Session -ScriptBlock $Script -ErrorAction SilentlyContinue | Out-Null
    $_Status = Invoke-Command -Session $_Session -ScriptBlock {$SQL.Status.ToString()} -ErrorAction SilentlyContinue
    #endregion

    #region Return results
    if ($_Status) {
        if ($Quiet) {
            Return $true
        }
        return $_Status
    } else {
        if ($Quiet) {
            Return $false
        }
        return 'Unavailable'
    }
    #endregion

    <#
    .SYNOPSIS

    Verify SQL Server is available through remote session

    .DESCRIPTION

    Validate SQL Server is available for connection

    .EXAMPLE

    $_Session = Test-PSremoting -ServerName 'Server01' -ServerCreds (Get-Credential)
    Test-SQLConnection -Session $_Session

    #>
}

function Test-SQLDBExists {
    [cmdletBinding()]
    Param(
        # PS Remoting Session to connect to server (use Test-PSRemoting function)
        [Parameter(Mandatory=$true)]
        [pssession]
        $Session,

        # Name of SQL Instance
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $SQLInstance = 'default',

        # Name of Database to test
        [parameter(Mandatory=$true)]
        [String]
        $DBName,

        # Return True/False only
        [Parameter(Mandatory=$false)]
        [switch]
        $Quiet
    )

    #region Verify Session
    $_Session = $Session
    if (-Not $_Session -or $_session.State -eq 'Opened') {
        Write-Error ('PS Session is invalid') -ErrorAction Continue
        if ($Quiet) {
            return $false
        }
        return $null
    }
    #endregion

    #region Verify SQLServer PS Module
    if (-Not (Test-PSModuleInstalled -Session $_Session -ModuleName SQLServer)) {
        Write-Error ('PS Module SQLServer Not Found') -ErrorAction Continue
        if ($Quiet) {
            return $false
        }
        return $null
    }
    #endregion

    #region Verify SQL Connection
    if (-Not (Test-SQLConnection -Session $_Session -SQLInstance $SQLInstance -Quiet)) {
        Write-Error ('Unable to connect to SQL Server') -ErrorAction Continue
        if ($Quiet) {
            return $false
        }
        return $null
    }
    #endregion

    #region Get Database from Server
    $_db = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create('$SQL.databases[{0}]' -f $DBName)) -ErrorAction SilentlyContinue
    #endregion

    #region return results
    if ($_db -and $_db.name -eq $dbname) {
        if ($Quiet) {
            return $true
        }
        return $db
    } else {
        if ($Quiet) {
            return $false
        }
        return $null
    }
    #endregion 

    <#
    .SYNOPSIS

    Test if SQL Database exists and return database or true/false

    .DESCRIPTION

    Check if a Database Exists on the remote Server.  Function uses PS Remoting to execute.

    .EXAMPLE

    $_Session = Test-PSRemoting -ServerName SERVER01 -ServerCreds (Get-Credential)
    Test-SQLDBExists -Session $_Session -DBName TestDB

    #>
}


#endregion

#region Generic Supporting functions
function Test-Credential {
    [CmdletBinding()]
    Param(
        # Username to Test
        [parameter(Mandatory=$true)]
        [string]
        $UserName,

        # Password in SecureString Format
        [parameter(Mandatory=$true)]
        [securestring]
        $Password,

        # System to Validate Username/Password
        [Parameter(Mandatory=$false)]
        [ValidateSet('Domain','Machine')]
        [String]
        $ContextType = 'Domain',

        # Domain Name
        [Parameter(Mandatory=$false)]
        [String]
        $Domain = (Get-ADDomain).NetBIOSName
    )

    if ($Username -notlike '*@*' -and $Username -notlike '*\*' -and $Domain) {
        $_UserName = ('{0}\{1}' -f $Domain,$Username)
    } else {
        $_UserName = $UserName
    }
    Write-Verbose ('{0}: Using UserName "{1}"' -f (get-date).ToString(),$_UserName)
    
    #region Convert Password to cleartext for use
    $_Password = [Runtime.interopservices.marshal]::Ptrtostringauto([runtime.interopservices.marshal]::SecureStringToBSTR($Password))
    #endregion

    #region Test credentials
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement | Out-Null
    $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($ContextType)
    if (-Not $DS.ValidateCredentials($_Username, $_Password)) {
        Write-Error ('Error validating Username "{0}" with provided password' -f $Username) -ErrorAction Continue
        return $null
    }

    Write-Verbose ('{0}: VALIDATED - Credentials Tested Successfully' -f (get-date).tostring())
    #endregion

    Return (New-object pscredential $_UserName,$Password)

    <#
    .SYNOPSIS

    Testing Credentials against domain or local computer

    .DESCRIPTION

    This function will validate the Username and Password provided to make sure they work.

    Return Result: PSCredentials Object

    Username is converted to <domain>\<username> if no domain is specified for username

    Username can be <username>@<domain UPN>, <domain>\<username> or <username>

    .EXAMPLE

    $pw = read-host -AsSecureString

    Test-Credential -Username 'Testuser' -Password $pw

    .EXAMPLE

    Test-Credential -UserName 'TestUser' -Password (Convertto-SecureString 'testpassword' -AsPlainText -Force)

    #>
}

function Install-SSLCertificate {
    [CmdletBinding()]
    Param(
        # Server to Create Remoting Session with
        [parameter(Mandatory=$true)]
        [string]
        $ServerName,

        # Credentials to connect to remote server
        [parameter(Mandatory=$true)]
        [PSCredential]
        $ServerCreds,

        # Path to PFX File to install
        [parameter(Mandatory=$true)]
        [string]
        $PFXFilePath,

        # Path to install Certificate
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $CertStorePath = 'Cert:\CurrentUser\My',

        # Password for PFX File to install
        [parameter(Mandatory=$true)]
        [securestring]
        $PFXPassword
    )

    #region Verify Server Connection
    $_Session = Test-PSRemoting -ServeName $ServerName -ServerCreds $ServerCreds
    if (-Not $_Session -or $_Session.State -ne 'Opened') {
        Write-Error ('problem connection to server') -ErrorAction Continue
        return $null
    }

    Write-Verbose ('{0}: VALIDATED - PS Session connected' -f (get-date).tostring())
    #endregion

    #region Convert PFXPassword to cleartext
    $_PFXPassword = [Runtime.interopservices.marshal]::Ptrtostringauto([runtime.interopservices.marshal]::SecureStringToBSTR($PFXPassword))
    #endregion

    #region Verify File Path
    if (-Not (Test-Path -Path $PFXFilePath -PathType leaf)) {
        Write-Error ('File "{0}" was not found' -f $PFXFilePath) -ErrorAction Continue
        return $null
    } 
    
    Write-Verbose ('{0}: VALIDATED - File "{0}" found' -f (get-date).tostring(),$PFXFilePath)
    #endregion

    #region Verify CertStor Path
    $_CertStorePath = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("Get-Item -Path $CertStorePath")) -ErrorAction SilentlyContinue
    if (-Not ($_CertStorePath) -and $_CertStorePath.PSDrive.Name -eq 'Cert') {
        Write-Error ('CertStore path "{0}" is invalid' -f $CertStorePath) -ErrorAction Continue
        return $null
    }

    Write-Verbose ('{0}: VALIDATED - CertStor Path "{1}" found' -f (get-date).tostring(),$_CertStorePath.fullname)
    #endregion

    #region Copy File to Server
    try {
        if ($ServerCreds) {
            New-PSDrive -Name $ServerName -PSProvider FileSystem -Root ('\\{0}\c$' -f $ServerName) -Credential $ServerCreds | Out-Null
            Copy-Item -Path $PFXFilePath -Destination ('{0}:\Windows\Temp\{0}.pfx' -f $ServerName) | Out-Null
        } else {
            Copy-Item -Path $PFXFilePath -Destination ('\\{0}\c$\Windows\Temp\{0}.pfx' -f $ServerName) | Out-Null
        }

        Write-Verbose ('{0}: File "{1}" copied to "C:\Windows\Temp\{2}.pfx' -f (get-date).tostring(),$PFXFilePath,$ServerName)
    } catch {
        Write-Error ('There was a problem copying file "{0}" to Server' -f $PFXFilePath) -ErrorAction Continue 
        return $null
    }
    #endregion

    #region Install Certificate on Server
    $_Action = [scriptblock]::Create("Import-PfxCertificate -CertStoreLocation '$CertStorePath' -FilePath 'C:\Windows\Temp\$ServerName.pfx' -Password (ConvertTo-SecureString -String '$_PFXPassword' -AsPlainText -Force)")
    $_Cert = Invoke-Command -Session $_Session -ScriptBlock $_Action
    #endregion

    if ($_Cert) {
        Return $_Cert
    } else {
        return $null
    }
    
    <#
    .SYNOPSIS

    Install SSL Certificate in PFX Format on Remote Server

    .DESCRIPTION

    This function installs the PFX File on the remote server with assigned password and CertStore path provided

    .EXAMPLE

    Install-SSLCertificate -Session $Session -PFXFilePath C:\Cert\Cert.pfx -PFXPassword (Convertto-SecureString 'testing' -AsPlainText -Force)

    ## Installs PFX file to default Cert:\CurrentUser\My Certificate Store and returns the Certificate Info

    #>
}

function Get-RandomPassword {
    [CmdletBinding()]
    Param(
        # Length of password
        [parameter(Mandatory=$false)]
        [int]
        $length = 24,
        
        # Characters to use in password
        [parameter(Mandatory=$false)]
        [string]
        $Characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!$%&/()=?*+#_',

        # Require 1 Upper, 1 Lower, 1 number and 1 symbol
        [parameter(Mandatory=$false)]
        [boolean]
        $Complex = $True
    )

    $_pwd = $null
    $_loop = $true
    $_Chars = ($Characters.ToCharArray() | Select-Object -Unique) -join ''

    if ($_Chars.length -lt $length -and $Complex) {
        Write-Warning ('Using "{0}" characters for password leave less than "{1}" to Create Complexity to that will be ignored' -f $_Chars,$length)
        $Complex = $false
    }

    if ($Complex -and $_Chars.length -ge $length) {
        if ($_Chars -match [regex]'[A-Za-z]' -and $_Chars -match [regex]'[0-9]' -and $_Chars -match [regex]'[!$%&/()=?*+#_]') {
            $Complex = $false

            Write-Verbose ('{0}: Using Complexity to Generate Password (requiring 1 Char, 1 Number, 1 Symbol)' -f (get-date).tostring())
        }
    }

    while ($_loop) {
        $_pwd = ([string]$_Chars[(1..$length | ForEach-Object {Get-Random -Maximum $_Chars.Length})]).Replace(' ','')
        if ($_pwd -match [regex]'[A-Za-z]' -and $_pwd -match [regex]'[0-9]' -and $_pwd -match [regex]'[!$%&/()=?*+#_]') {
            $_loop = $false
        }
        if (-Not $Complex) {
            $_loop = $false
        }
    }

    Write-Verbose ('{0}: Password Generated' -f (get-date).tostring())
    return $_pwd

    <#
    .SYNOPSIS

    Create a random password

    .DESCRIPTION

    Generate a Random password with configurable Characters, length and complexity requirements

    #>
}

function Test-Ping {
    Param(
        # Server or ComputerName or IP address to ping
        [Parameter(Mandatory=$true)]
        [String]
        $Server,

        # Number of pings to Server
        [Parameter(Mandatory=$false)]
        [Int]
        $Count=4,

        # Continuously Ping
        [Parameter(Mandatory=$false)]
        [Switch]
        $Continuous,

        # Return True or False for available
        [Parameter(Mandatory=$false)]
        [Switch]
        $Quiet
    )
    
    $_IP = $null
    $_HostEntry = $Null
    
    if (-Not ([System.Net.IPAddress]::TryParse($Server, [Ref] $_IP))) {
        try {
            $_HostEntry = [net.dns]::GetHostEntry($Server)

            Write-Verbose ('{0}: Resolved Server Name "{1}" to "{2}"' -f (get-date).tostring(),$Server,$_HostEntry.AddressList.IPAddressToString)
        } Catch {
            Write-Error ('Error Resolving the Host Name "{0}"' -f $Server) -ErrorAction Stop
        }
    } else {
        Write-Verbose ('{0}: Provide Server appears to be an IP Address "{1}"' -f (get-date).tostring(),$_IP.IPAddressToString)
    }

    if ($Quiet) {
        $Count = 1
        Write-Verbose ('{0}: Testing Ping of Server with quiet response' -f (get-date).tostring())
    }
    
    $_array = @()
    $_obj = New-Object PSObject

    While ($Count) {
        if ($_HostEntry) {
            $_obj = ((New-Object System.Net.NetworkInformation.Ping).Send($_HostEntry.AddressList[0].IPAddressToString) | Select-Object @{N='HostName';E={$_HostEntry.HostName}},Address,Status,RoundTripTime,@{N='TTL';E={$_.options.TTL}},@{N='Buffer';E={$_.Buffer.Count}})
            Write-Verbose ('{0}: Pinging Host Name "{1}"' -f (get-date).tostring(),$_HostEntry.HostName)
        }
        else {
            $_obj = ((New-Object System.Net.NetworkInformation.Ping).Send($_IP.IPAddressToString) | Select-Object @{N='HostName';E={$_IP.IPAddressToString}},Address,Status,RoundTripTime,@{N='TTL';E={$_.options.TTL}},@{N='Buffer';E={$_.Buffer.Count}})
            Write-Verbose ('{0}: Pinging IP Address "{1}"' -f (get-date).tostring(),$_IP.IPAddressToString)
        }
        
        $_array += $_obj
        if (-Not $Continuous) {
            $count -= 1
        }
        if (-Not $Quiet) {
            $_obj
        }
    }

    Write-Verbose ('{0}: Completed Count of Pings "{1}"' -f (get-date).tostring(),$Count)

    if ($Quiet) {
        Write-Verbose ('{0}: Returning True/False for result')
        if ($_obj.Status -eq 'Success') {
            return $true
        } else {
            return $true
        }
    }
    

    <#
    .SYNOPSIS
    
    Object Oriented Ping Testing
    
    .DESCRIPTION
    
    Ping tests if the remote server or ip address is responding to ICMP Ping

    Function supports:

        * Quiet Mode (true/false result)
        * Continuous Ping
        * Limited Ping Count (Default: 4)

    .EXAMPLE

    Test-Ping -Server SERVER01 -count 5

    .EXAMPLE

    Test-Ping -Server 10.0.0.5

    .EXAMPLE

    Test-Ping -Server www.google.com -Quiet
    #>
}

Function Test-Port {
    Param(
        # Name or IP of Server to test
        [Parameter(Mandatory=$true)]
        [String]
        $Server,

        # Port Number to Test Server
        [Parameter(Mandatory=$true)]
        [Int]
        $Port,

        # Timeout Value if not connecting
        [Parameter(Mandatory=$False)]
        [Int]
        $Timeout = 3000
    )
    
    $_IP = [net.dns]::Resolve($server).addresslist[0].ipaddresstostring      

    if ($_IP) {    
        [void] ($socket = New-Object net.sockets.tcpclient)
        $Connection = $socket.BeginConnect($server,$Port,$null,$null)
        [void] ($Connection.AsyncWaitHandle.WaitOne($TimeOut,$False))
        
        $hash = @{Server=$Server
                  IPAddress = $_IP
                  Port=$Port
                  Successful=($socket.connected)}
                  
        $socket.Close()
        
    } else {
        $hash = @{Server=$server
                  IPAddress = $null
                  Port=$Port
                  Successful=$null}
    }
    
    return (new-object PSObject -Property $hash) | Select-Object Server,IPAddress,Port,Successful

    <#
    .SYNOPSIS

    Test-Port allows you to test if a port is accessible
    
    .DESCRIPTION

    Using Test-Port you can find if a specified port is open on a machine.  The results are the original servername, Ipaddress, Port and if successful
    
    .Parameter Server
    The server parameter is the name of the machine you want to test, either FQDN or NetBIOS name
    .Parameter Port
    Use Port Parameter to specify the port to test
    .Parameter TimeOut
    Use Timeout value to specify how long to wait for connection in milliseconds
    .Example
    Test-Port -Server www.google.com -Port 80
    #>
}
#endregion

#region SQL Install Supporting Function
function New-SQLServiceAccount {
    Param(
        # Service Account Name to Create
        [parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]
        $svcAccountName,
        
        # Credentials for AD to Create Account
        [parameter(Mandatory=$false)]
        [pscredential]
        $DomainCreds,
        
        # Create Service Account (if false only updates to account)
        [parameter(Mandatory=$false)]
        [boolean]
        $CreateServiceAccount = $true,

        # Password to assign to Account (Creates password by default)
        [parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [securestring]
        $svcAccountPassword = (Convertto-Securestring (Get-RandomPassword) -asplaintext -force),

        # OU Path to Create Account in (reccommended to use 'OU=Service Accounts,OU=EnterpriseAdmin,DC=domain,DC=com')
        [parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]
        $svcAccountOUPath = ('OU=Service Accounts,OU=EnterpriseAdmin,{0}' -f (Get-ADDomain).DistinguishedName),
        
        # User Principal Name suffix
        [parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]
        $UPNDomain = (Get-ADDomain).DNSRoot,

        # Account will be trusted for delegation (kerberos)
        [parameter(Mandatory=$false)]
        [boolean]
        $TrustSvcAccountforDelegation = $true,

        # Configure SPN Suffixes (kerberos)
        [parameter(Mandatory=$false)]
        [boolean]
        $ConfigureSPN = $true,

        # SPN Suffixes to add
        [parameter(Mandatory=$false)]
        [string[]]
        $SPNSuffixes = ((Get-ADObject -Identity ('cn=Partitions,cn=Configuration,{0}' -f (Get-ADDomain).distinguishedname) -Properties upnsuffixes).upnsuffixes) + ((Get-ADDomain).Forest)
    )

    #region Validate Service Account
    $_svcAccount = Get-ADUser -Filter "name -eq '$svcAccountName'" -ErrorAction SilentlyContinue

    if ($CreateServiceAccount) {    
        $_svcAccountOUPath = Get-Item "AD:\$svcAccountOUPath" -ErrorAction SilentlyContinue
        
        if ($_svcAccount) {
            Write-Error ('Service Account "{0}" already exists' -f $svcAccountName) -ErrorAction Stop
        }

        If (-Not $_svcAccountOUPath) {
            Write-Error ('OU Path "{0}" invalid, Create user will fail' -f $svcAccountOUPath) -ErrorAction Stop
        }

        Write-Verbose ('{0}: VALIDATED - Service Account "{1}" Ready to Create in OUPath "{2}"' -f (get-date).tostring(),$svcAccountName,$svcAccountOUPath)
    } else {
        if (-Not $_svcAccount) {
            Write-Error ('Service Account "{0}" does not exist, CreateServiceAccount not selected' -f $svcAccountName) -ErrorAction Stop
        }

        Write-Verbose ('{0}: VALIDATED - Service Account "{1}" exists and ready for use' -f (get-date).tostring(),$svcAccountName)

        $_svcAccountCreds = Test-Credential -Username $svcAccountName -Password $svcAccountPassword

        if (-Not $_svcAccountCreds) {
            Write-Error ('Service Account "{0}" password is invalid' -f $svcAccountName) -ErrorAction Stop
        }

        Write-Verbose ('{0}: VALIDATED - Service Account "{1}" password validated successfully' -f (get-date).tostring(),$svcAccountName)
    }
    #endregion

    #region Create Service Account
    if ($CreateServiceAccount) {
        if ($DomainCreds) {
            New-ADUser -Name $svcAccountName -SamAccountName $svcAccountName -UserPrincipalName ('{0}@{1}' -f $svcAccountName,$UPNDomain) -PasswordNeverExpires $true -CannotChangePassword $true -Path $_svcAccountOUPath.DistinguishedName -Credential $DomainCreds -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 5
            
            $_svcAccount = Get-ADUser $svcAccountName -ErrorAction SilentlyContinue
            if (-Not $_svcAccount) {
                Write-Error ('Error Creating User Account, either failed or not found after creation') -ErrorAction Stop
            }

            $_svcAccount | Set-ADAccountPassword -NewPassword $svcAccountPassword -Credential $DomainCreds -ErrorAction SilentlyContinue | Out-Null
            $_svcAccount | Enable-ADAccount -Credential $DomainCreds -ErrorAction SilentlyContinue | Out-Null
        } else {
            New-ADUser -Name $svcAccountName -SamAccountName $svcAccountName -UserPrincipalName ('{0}@{1}' -f $svcAccountName,$UPNDomain) -PasswordNeverExpires $true -CannotChangePassword $true -Path $_svcAccountOUPath.DistinguishedName  -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 5
            
            $_svcAccount = Get-ADUser $svcAccountName -ErrorAction SilentlyContinue
            if (-Not $_svcAccount) {
                Write-Error ('Error Creating User Account, either failed or not found after creation') -ErrorAction Stop
            }

            Get-ADUser $svcAccountName | Set-ADAccountPassword -NewPassword $svcAccountPassword -ErrorAction SilentlyContinue | Out-Null
            Get-ADUser $svcAccountName | Enable-ADAccount -ErrorAction SilentlyContinue | Out-Null
        }

        Write-Verbose ('{0}: User "{1}" created with specified password and enabled' -f (get-date).tostring(),$svcAccountName)
    }
    #endregion

    #region Configure Delegation for account
    if ($TrustSvcAccountforDelegation -and ((Get-ADUser $svcAccountName -Properties TrustedforDelegation).TrustedforDelegation -eq 'False')) {
        if ($DomainCreds) {
            try {
                Get-ADUser $svcAccountName | Set-ADUser -TrustedforDelegation $true -Credential $DomainCreds
                Write-Verbose ('{0}: Enabled kerberos delegation for Account "{1}"' -f (get-date).tostring(),$svcAccountName)
            } catch {
                Write-Warning ('A problem occured Trusting Account "{0}" for deletation' -f $svcAccountName)
            }
            
        } else {
            try {
                Get-ADUser $svcAccountName | Set-ADUser -TrustedforDelegation $true -ErrorAction Stop
                Write-Verbose ('{0}: Enabled kerberos delegation for Account "{1}"' -f (get-date).tostring(),$svcAccountName)
            } catch {
                Write-Warning ('A problem occured Trusting Account "{0}" for deletation' -f $svcAccountName)
            }
        }
    }
    #endregion

    #region Configure Kerberos SPN's for Server
    if ($SPNSuffixes -and $ConfigureSPN) {
        $List = @()
        $List += (('MSSQLSvc/{0}' -f $ServerName),('MSSQLSvc/{0}:1433' -f $ServerName))
        $List += $SPNSuffixes | ForEach-Object {(('MSSQLSvc/{0}.{1}' -f $ServerName,$_),('MSSQLSvc/{0}.{1}:1433' -f $ServerName,$_))}
        foreach ($item in $list ){
            if ($DomainCreds) {
                try {
                    Get-ADUser $svcAccountName | Set-ADUser -ServicePrincipalNames @{Add=($item)} -Credential $DomainCreds
                    Write-Verbose ('{0}: Added suffix "{1}" to "{2}"' -f (get-date).tostring(),$item,$svcAccountName)
                } catch {
                    Write-Warning ('A problem occurred adding suffix "{0}" to "{1}"' -f $item,$svcAccountName)
                }
            } else {
                try {
                    Get-ADUser $svcAccountName | Set-ADUser -ServicePrincipalNames @{Add=($item)}
                    Write-Verbose ('{0}: Added suffix "{1}" to "{2}"' -f (get-date).tostring(),$item,$svcAccountName)
                } catch {
                    Write-Warning ('A problem occurred adding suffix "{0}" to "{1}"' -f $item,$svcAccountName)
                }
            }
        }
    }
    #endregion

    if (-Not $_svcAccountCreds) {
        return (Test-Credential $svcAccountName,$svcAccountPassword)
    } else {
        return $_svcAccountCreds
    }
}

function New-ADGroupforSQL {
    [CmdletBinding()]
    Param(
        # Name of Group to Create
        [parameter(Mandatory=$true)]
        [string]
        $GroupName,

        # optional credentials to use when creating the group
        [parameter(Mandatory=$false)]
        [pscredential]
        $DomainCreds,
        
        # OU Path to create group in
        [parameter(Mandatory=$true)]
        [string]
        $GroupOUPath,

        # Create or Just update Group Members
        [parameter(Mandatory=$false)]
        [boolean]
        $CreateGroup = $true,
        
        # Users or Groups to add to Group
        [parameter(Mandatory=$false)]
        [string[]]
        $GroupMembers,
        
        # Group Scope Type
        [parameter(Mandatory=$false)]
        [ValidateSet('DomainLocal','Global')]
        [string]
        $GroupScope = 'DomainLocal'
    )

    $ErrorActionPreference = 'Stop'

    #region Validate Group and OU Path
    $_Group = Get-ADGroup -Filter "name -eq '$GroupName'" -ErrorAction SilentlyContinue -Verbose:$false
    $_GroupOUPath = Get-Item "AD:\$GroupOUPath" -ErrorAction SilentlyContinue -Verbose:$false

    if ($CreateGroup) {
        if ($_Group) {
            Write-Error ('AD Group "{0}" already exists' -f $GroupName) -ErrorAction Continue
            return $null
        }

        Write-Verbose ('{0}: VALIDATED - AD Group "{1}" not found, ready to create!' -f (get-date).ToString(),$GroupName)

        if (-Not $_GroupOUPath -and ($GroupOUPath)) {
            Write-Error ('Group OU Path "{0}" does not exist as expected' -f $GroupOUPath) -ErrorAction Continue
            return $null
        }

        Write-Verbose ('{0}: VALIDATED - AD Group OUPath "{1}" exists as expected' -f (get-date).ToString(),$GroupOUPath)
    } else {
        if (-Not $_Group) {
            Write-Error ('AD Group "{0}" does NOT exist!' -f $GroupName) -ErrorAction Continue
            return $null
        }
        if ($_group.Count -gt 1) {
            Write-Error ('Group Name "{0}" returned "{1}" objects' -f $GroupName,$_group.Count) -ErrorAction Continue
            return $null
        }

        Write-Verbose ('{0}: VALIDATED - AD Group "{1}" found!' -f (get-date).ToString(),$GroupName)
    }
    #endregion

    #region Create Group
    if ($CreateGroup) {
        if ($DomainCreds) {
            New-ADGroup -Name $GroupName -SamAccountName $GroupName -GroupCategory 'Security' -GroupScope $GroupScope -path $_GroupOUPath.distinguishedname -ErrorAction SilentlyContinue -Credential $DomainCreds
        } else {
            New-ADGroup -Name $GroupName -SamAccountName $GroupName -GroupCategory 'Security' -GroupScope $GroupScope -path $_GroupOUPath.distinguishedname -ErrorAction SilentlyContinue
        }
        
        Start-Sleep -Seconds 5
        $_Group = Get-ADGroup -Filter "name -like '$GroupName'" -ErrorAction SilentlyContinue -Verbose:$false

        if (-Not ($_Group)) {
            Write-Error ('A problem occured creating AD Group') -ErrorAction Continue
            return $null
        }
        Write-Verbose ('{0}: AD Group "{1}" created' -f (get-date).tostring(),$GroupName)
    }
    #endregion

    #region Add Members to Group
    if ($GroupMembers -and $_Group) {
        foreach ($_GroupMember in $GroupMembers) {
            $_ADobject = Get-ADObject -filter "Name -like '$_GroupMember' -or SamAccountName -like '$_GroupMember'" -ErrorAction SilentlyContinue
            
            if (-Not $_ADobject) {
                Write-Warning ('ADObject "{0}" not found' -f $_GroupMember)
            } else {
                try {
                    if ($DomainCreds) {
                        Add-ADGroupMember -Identity $_Group.DistinguishedName -Members $_ADobject.distinguishedname -Credential $DomainCreds
                    } else {
                        Add-ADGroupMember -Identity $_Group.DistinguishedName -Members $_ADobject.distinguishedname
                    }

                    Write-Verbose ('{0}: Added AD Object "{1}" to Group "{2}"' -f (get-date).tostring(),$_ADobject.name,$_group.Name)
                } catch {
                    Write-Warning ('Adding ADObject "{0}" add to Group "{1}" failed' -f $_ADobject.Name,$_group.Name)
                }
            }
        }
    }
    #endregion

    return $_Group

    <#
    .SYNOPSIS

    Create AD Group in specified OU and add members

    .DESCRIPTION

    Create AD Group with several options and defaults.

        Default: Group Scope is Domain Local

        Optional: Add Members

        Required: OU Path to create
    #>
}

function Grant-ServerAccess {
    [CmdletBinding()]
    Param(
        # Server To connect to
        [parameter(Mandatory=$true)]
        [string]
        $ServerName,
        
        # Optional Credentials to provide connecting to server
        [parameter(Mandatory=$false)]
        [pscredential]
        $ServerCreds,

        # List of Groups to Add Member to
        [parameter(Mandatory=$true)]
        [string[]]
        $LocalGroups,

        # AD User or Group to Add to the LocalGroups List
        [parameter(Mandatory=$true)]
        [string]
        $Member
    )

    #region Verify Session
    $_Session = Test-PSRemoting -ServerName $ServerName -ServerCreds $ServerCreds
    
    if (-Not $_session -or $_session.state -ne 'Opened') {
        Write-Error ('problem with session') -ErrorAction Stop
    }
    #endregion

    #region Verify Groups on Server
    $_LocalGroups = Invoke-Command -Session $_Session -ScriptBlock {Get-LocalGroup} -ErrorAction SilentlyContinue

    if (-Not $_LocalGroups) {
        Write-Error ('No Local Groups Returned - error in connection') -ErrorAction Stop
    }

    $_LocalGroups = $_LocalGroups | Where-Object {$_.name -in $LocalGroups}

    if (-Not $_LocalGroups) {
        Write-Error ('No Groups from "{0}" were found on remote host "{1}"' -f ($LocalGroups -join ','),$Session.ComputerName) -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - Groups "{1}" on server "{2}"' -f (get-date).tostring(),($_LocalGroups -join ','),$_Session.ComputerName)
    #endregion

    #region Verify Member to add
    $_Member = Get-ADObject -Filter "name -like '$Member' -or samaccountname -like '$member'" -ErrorAction SilentlyContinue

    if (-Not $_Member) {
        Write-Error ('Member "{0}" not found' -f $Member) -ErrorAction Stop
    }

    if ($_Member.Count -gt 1) {
        Write-Error ('Member "{0}" returned "{1}" results' -f $Member,$_Member.Count) -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - AD Object "{1}" found to be added to Local Groups' -f (get-date).tostring(),$_Member.Name)
    #endregion

    foreach ($Group in $_LocalGroups) {
        $Action = [Scriptblock]::Create("Add-LocalGroupMember -Group '$Group' -Member '$Member' -ErrorAction SilentlyContinue")
        Invoke-Command -Session $_Session -ScriptBlock $Action
        $Action = [Scriptblock]::Create("Get-LocalGroupMember -Group '$Group' -Member '*$Member*' -ErrorAction SilentlyContinue")
        if (-Not (Invoke-Command -Session $_Session -ScriptBlock $Action)) {
            Write-Warning ('Member "{0}" was not added to Group "{1}"' -f $Member,$Group)
        } else {
            Write-Verbose ('{0}: Added "{1}" to local group "{2}"' -f (get-date).tostring(),$Member,$Group)
        }
    }
}

function Set-AccountLogon {
    Param(
        # Account To configure allowed servers
        [Parameter(Mandatory=$true)]
        [string]
        $svcAccountName,

        # Optional Domain Credentials
        [Parameter(Mandatory=$false)]
        [pscredential]
        $DomainCreds,

        # Array of Machines to allow Service Account to logon to
        [Parameter(Mandatory=$true)]
        [string[]]
        $AllowedMachines
    )

    #region Verify Service Account
    $_svcAccount = Get-ADUser -filter "name -eq '$svcAccountName'" -ErrorAction SilentlyContinue

    if (-not $_svcAccount) {
        Write-Error ('Account "{0}" does not exist' -f $svcAccountName)
        return $false
    }

    Write-Verbose ('{0}: VALIDATED - User Account "{1}" found in AD' -f (get-date).tostring(),$_svcAccount.Name)
    #endregion

    try {
        if ($DomainCreds) {
            $_svcAccount | Set-ADUser -LogonWorkstations ($AllowedMachines -Join ',') -Credential $DomainCreds -ErrorAction Stop
        } else {
            $_svcAccount | Set-ADUser -LogonWorkstations ($AllowedMachines -Join ',') -ErrorAction Stop
        }

        Write-Verbose ('{0}: configured "{1}" workstations for user "{2}"' -f (get-date).tostring(),($AllowedMachines -join ','),$svcAccountName)
    } catch {
        Write-Error ('A problem occurred when adding allowed workstations to user')

        return $false
    }
    
    return $true
}
#endregion

#region SQL Config Supporting functions
function Set-DBMail {
    param(
        # SQL Server to connect to with PS Remoting
        [parameter(Mandatory=$true)]
        [string]
        $ServerName,

        # Optional Credentials for connecting to server
        [parameter(Mandatory=$false)]
        [pscredential]
        $ServerCreds,

        # Install SQL Server PS Module if not already installed
        [parameter(Mandatory=$false)]
        [boolean]
        $InstallPSModuleifMissing = $true,

        # Name of SQL Server Instance
        [parameter(Mandatory=$false)]
        [string]
        $SQLInstanceName = 'Default',

        # Enable DBMail
        [parameter(Mandatory=$false)]
        [boolean]
        $EnableDBMail = $true,

        # Create DBMail Account
        [parameter(Mandatory=$false)]
        [boolean]
        $CreateDBMailAccount = $true,

        # Create DB Mail Profile
        [parameter(Mandatory=$false)]
        [boolean]
        $CreateDBMailProfile = $true,
        
        # Name of DBMail Profile
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $DBMailProfileName = 'Default Profile',
        
        # Name of DBMail Account
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $DBMailAccountName = 'Default Account',

        # From Email Address for SQL Server DBMail
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $DBMailAccountFromAddress = ('{0}@{1}' -f $ServerName,$env:USERDNSDOMAIN),

        # SMTP Relay IP or FQDN
        [Parameter(Mandatory=$true)]
        [string]
        $DBMailAccountSMTPRelay,

        # Principal Name for Profile
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $DBMailProfilePrincipalName = 'public',

        # Set Profile to Default for Public
        [Parameter(Mandatory=$false)]
        [boolean]
        $DBMailProfilePrincipalIsDefault = $true,

        # Enable Default Mail Profile for SQL Agent
        [Parameter(Mandatory=$false)]
        [boolean]
        $SetAgentDefaultProfile = $true
    )

    #region Check PS Session to Server and create
    $_Session = Test-PSRemoting -ServerName $ServerName -ServerCreds $ServerCreds

    if (-Not $_Session -or $_Session.State -eq 'Opened') {
        Write-Error ('Session Validation Failed') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - Session to Server Validated' -f (get-date).tostring())
    #endregion

    #region Check for PS Module
    if (-Not (Test-PSModuleInstalled -Session $_Session -ModuleName SQLServer -Install)) {
        Write-Error ('Missing PS Module on Server') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - SQLServer Module ready for use on Server' -f (get-date).tostring())
    #endregion

    #region Test SQL Connection
    if (-Not (Test-SQLConnection -Session $_Session -SQLInstance $SQLInstance)) {
        Write-Error ('A problem occured connecting to SQL Server') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - SQL Connection Validated' -f (get-date).tostring())
    #endregion

    #region Check DBMail status
    if ($EnableDBMail -and (Invoke-Command -Session $_Session -ScriptBlock {$SQL.Configuration.DatabaseMailEnabled.RunValue} -eq 1)) {
        Write-Warning ('----- DB Mail Already Enabled on "{0}" -----' -f $ServerName)
    }
    #endregion

    #region Check DBMail Account
    $_Account = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create('$SQL.Mail.Accounts[{0}]' -f $DBMailAccountName)) -ErrorAction SilentlyContinue
    
    if ($CreateDBMailAccount) {
        if ($_Account) {
            Write-Error ('Account "{0}" already exists and option to create was selected' -f $DBMailAccountName) -ErrorAction Stop
        }

        Write-Verbose ('{0}: VALIDATED - Ready to Create Account "{1}"' -f (get-date).tostring(),$DBMailAccountName)
    } else {
        if (-Not $_Account) {
            Write-Error ('Account "{0}" does not exist and option to create was NOT selected' -f $DBMailAccountName) -ErrorAction Stop
        }

        Write-Verbose ('{0}: VALIDATED - Ready to use Account "{1}"' -f (get-date).ToString(),$DBMailAccountName)
    }
    #endregion

    #region Check DBMail Profile
    $_Profile = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create('$SQL.Mail.Profiles[{0}]' -f $DBMailProfileName)) -ErrorAction SilentlyContinue
    
    if ($CreateDBMailProfile) {
        if ($_Profile) {
            Write-Error ('Profile "{0}" already exists and option to create was selected' -f $DBMailProfileName) -ErrorAction Stop
        }

        Write-Verbose ('{0}: VALIDATED - Ready to Create Profile "{1}"' -f (get-date).tostring(),$DBMailProfileName)
    } else {
        if (-Not $_Profile) {
            Write-Error ('Profile "{0}" does not exist and option to create was NOT selected' -f $DBMailProfileName) -ErrorAction Stop
        }

        Write-Verbose ('{0}: VALIDATED - Ready to use Profile "{1}"' -f (get-date).tostring(),$DBMailProfileName)
    }
    #endregion

    #region Enable DBMail on SQL Server
    Invoke-Command -Session $_Session -ScriptBlock {
        $SQL.Configuration.DatabaseMailEnabled.ConfigValue = 1
        $SQL.Configuration.Alter()
    } -ErrorAction Stop

    Write-Verbose ('{0}: DB Mail Enabled on Server "{1}"' -f (get-date).tostring(),$ServerName)
    #endregion

    #region Create DBMail Account
    Invoke-Command -Session $_Session -ScriptBlock {
        Param(
            $DBMailAccountName,
            $DBMailAccountFromAddress,
            $DBMailAccountSMTPRelay
        )

        if (-Not ($SQL.Mail.Accounts[$DBMailAccountName])) {
            $Account = New-Object -TypeName Microsoft.SqlServer.Management.SMO.Mail.MailAccount -Argumentlist $SQL.Mail, $DBMailAccountName, '', $SQL, $DBMailAccountFromAddress
            $account.Create()
        } else {
            $Account = $SQL.Mail.Accounts[$DBMailAccountName]
        }

        $Account.MailServers.Item(0).Rename($DBMailAccountSMTPRelay)
        $Account.Alter()
    } -ArgumentList $DBMailAccountName,$DBMailAccountFromAddress,$DBMailAccountSMTPRelay -ErrorAction Stop

    Write-Verbose ('{0}: DB Mail Account "{1}" setup with Relay "{2}" and from "{3}"' -f (get-date).tostring(),$DBMailAccountName,$DBMailAccountSMTPRelay,$DBMailAccountFromAddress)
    #endregion

    #region Create DBMail Profile
    Invoke-Command -Session $_Session -ScriptBlock {
        Param(
            $DBMailProfileName,
            $DBMailProfilePrincipalName,
            $DBMailProfilePrincipalIsDefault
        )
    
        if ($SQL.Mail.Profiles) {
            $Profile = New-Object -TypeName Microsoft.SqlServer.Management.SMO.Mail.MailProfile -ArgumentList $SQL.Mail,$DBMailProfileName,''
            $Profile.Create()
        } else {
            $Profile = $SQL.Mail.Profiles[$DBMailProfileName]
        }

        if (-Not ($DBMailAccountName -in $profile.EnumAccounts().AccountName)) {
            $Profile.AddAccount($DBMailAccountName,0)
        }
        if (-Not ($DBMailProfilePrincipalName -in $Profile.EnumPrincipals().PrincipalName)) {
            $Profile.AddPrincipal($DBMailProfilePrincipalName,$DBMailProfilePrincipalIsDefault)
        }

        $Profile.Alter()
    } -ArgumentList $DBMailProfileName,$DBMailProfilePrincipalName,$DBMailProfilePrincipalIsDefault -ErrorAction Stop

    Write-Verbose ('{0}: DB Mail Profile "{1}" Created' -f (get-date).tostring(),$DBMailProfileName)
    #endregion

    #region Set SQL Agent Profile
    if ($SetAgentDefaultProfile) {
        Invoke-Command -Session $_Session -ScriptBlock {
            $SQL.JobServer.AgentMailType = 'DatabaseMail'
            $SQL.JobServer.DatabaseMailProfile = $DBMailProfileName
            $SQL.JobServer.Alter()
        } -ErrorAction Stop

        Write-Verbose ('{0}: Set Job Server Default Mail Profile to "{1}"' -f $DBMailProfileName)
    }
    #endregion
}

function New-DBMailOperator {
    param(
        # SQL Server to connect to with PS Remoting
        [parameter(Mandatory=$true)]
        [string]
        $ServerName,

        # Optional Credentials for connecting to server
        [parameter(Mandatory=$false)]
        [pscredential]
        $ServerCreds,

        # Install SQL Server PS Module if not already installed
        [parameter(Mandatory=$false)]
        [boolean]
        $InstallPSModuleifMissing = $true,

        # Name of SQL Server Instance
        [parameter(Mandatory=$false)]
        [string]
        $SQLInstanceName = 'Default',

        # Name of Operator (ie. Server Team)
        [Parameter(Mandatory=$true)]
        [string]
        $OperatorName,

        # Email Address for Operator
        [Parameter(Mandatory=$true)]
        [string]
        $OperatorEmailAddress,

        # Enable Operator
        [Parameter(Mandatory=$false)]
        [boolean]
        $OperatorEnabled = $true,

        # Operator Pager Days
        [Parameter(Mandatory=$false)]
        [ValidateSet('EveryDay','WeekDays','Weekends','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday')]
        [string]
        $OperatorPagerDays = 'EveryDay',

        # Weekday Starting Time (default 00:00:00)
        [Parameter(Mandatory=$false)]
        [timespan]
        $OperatorWeekdayStartTime = '00:00:00',

        # Weekday End Time (default 11:59:59)
        [Parameter(Mandatory=$false)]
        [timespan]
        $OperatorWeekdayStopTime = '23:59:59',

        # Saturday Starting Time (default 00:00:00)
        [Parameter(Mandatory=$false)]
        [timespan]
        $OperatorSaturdayStartTime = '00:00:00',

        # Saturday End Time (default 11:59:59)
        [Parameter(Mandatory=$false)]
        [timespan]
        $OperatorSaturdayStopTime = '23:59:59',

        # Sunday Starting Time (default 00:00:00)
        [Parameter(Mandatory=$false)]
        [timespan]
        $OperatorSundayStartTime = '00:00:00',

        # Sunday End Time (default 11:59:59)
        [Parameter(Mandatory=$false)]
        [timespan]
        $OperatorSundayStopTime = '23:59:59',

        # Configure Operator as Failsafe Operator on SQL Agent
        [Parameter(Mandatory=$false)]
        [switch]
        $SetAsFailsafeOperator
    )

    #region Check PS Session to Server and create
    $_Session = Test-PSRemoting -ServerName $ServerName -ServerCreds $ServerCreds

    if (-Not $_Session -or $_Session.State -eq 'Opened') {
        Write-Error ('Session Validation Failed') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - Session to Server Validated' -f (get-date).tostring())
    #endregion

    #region Check for PS Module
    if (-Not (Test-PSModuleInstalled -Session $_Session -ModuleName SQLServer -Install)) {
        Write-Error ('Missing PS Module on Server') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - SQLServer Module ready for use on Server' -f (get-date).tostring())
    #endregion

    #region Test SQL Connection
    if (-Not (Test-SQLConnection -Session $_Session -SQLInstance $SQLInstance)) {
        Write-Error ('A problem occured connecting to SQL Server') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - SQL Connection Validated' -f (get-date).tostring())
    #endregion

    #region Create Operator
    Invoke-Command -Session $_Session -ScriptBlock {
        Param(
            $OperatorName,
            $OperatorEmailAddress,
            $OperatorEnabled,
            $OperatorPagerDays,
            $OperatorWeekdayStartTime,
            $OperatorWeekdayStopTime,
            $OperatorSaturdayStartTime,
            $OperatorSaturdayStopTime,
            $OperatorSundayStartTime,
            $OperatorSundayStopTime
        )

        $Operator = New-Object Microsoft.SqlServer.Management.Smo.Agent.Operator

        $Operator.Parent = $SQL.JobServer
        $Operator.Name = $OperatorName
        $Operator.Enabled = $OperatorEnabled
        $Operator.EmailAddress = $OperatorEmailAddress
        $Operator.PagerDays = $OperatorPagerDays
        $Operator.WeekdayPagerStartTime = $OperatorWeekdayStartTime
        $Operator.WeekdayPagerStopTime = $OperatorWeekdayStopTime
        $Operator.SaturdayPagerStartTime = $OperatorSaturdayStartTime
        $Operator.SaturdayPagerStopTime = $OperatorSaturdayStopTime
        $Operator.SundayPagerStartTime = $OperatorSundayStartTime
        $Operator.SundayPagerStopTime = $OperatorSundayStopTime
        $Operator.Create()

    } -ArgumentList $OperatorName,$OperatorEmailAddress,$OperatorEnabled,$OperatorPagerDays,$OperatorWeekdayStartTime,$OperatorWeekdayStopTime,$OperatorSaturdayStartTime,$OperatorSaturdayStopTime,$OperatorSundayStartTime,$OperatorSundayStopTime -ErrorAction Stop

    Write-Verbose ('{0}: Operator "{1}" Created' -f (get-date).tostring(),$OperatorName)
    #endregion

    #region Set Failsafe Operator
    if ($SetAsFailsafeOperator) {
        Invoke-Command -Session $_Session -ScriptBlock {
            param(
                $OperatorName
            )

            $SQL.JobServer.AlertSystem.FailSafeOperator = $OperatorName
            $SQL.JobServer.AlertSystem.NotificationMethod = 'NotifyEmail'
            $SQL.JobServer.AlertSystem.Alter()
        } -ArgumentList $OperatorName -ErrorAction SilentlyContinue

        Write-Verbose ('{0}: Updated Failsafe Operator to "{1}"' -f (get-date).ToString(),$OperatorName)
    }
    #endregion
}

function Set-DBConfig {
    Param(
        # SQL Server to connect to with PS Remoting
        [parameter(Mandatory=$true)]
        [string]
        $ServerName,

        # Optional Credentials for connecting to server
        [parameter(Mandatory=$false)]
        [pscredential]
        $ServerCreds,

        # Install SQL Server PS Module if not already installed
        [parameter(Mandatory=$false)]
        [boolean]
        $InstallPSModuleifMissing = $true,

        # Name of SQL Server Instance
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $SQLInstanceName = 'Default',

        # List of Databases (system db's by default)
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $DBNames = ('master','model','msdb'),

        # Recovery Model for Database(s)
        [Parameter(Mandatory=$false)]
        [ValidateSet('Simple','Full')]
        [string]
        $DBRecoveryModel = 'Simple',
        
        # File Size in KB
        [Parameter(Mandatory=$false)]
        [ValidateRange(1,10GB/1KB)]
        [int]
        $DBFileSize = (100MB/1KB),

        # File Growth Size in KB
        [Parameter(Mandatory=$false)]
        [ValidateRange(1,10GB/1KB)]
        [int]
        $DBFileGrowth = (100MB/1KB),

        # File Growth Type (default = KB)
        [Parameter(Mandatory=$false)]
        [ValidateSet('KB','Percent','None')]
        [string]
        $DBFileGrowthType = 'KB'
    )

    #region Check PS Session to Server and create
    $_Session = Test-PSRemoting -ServerName $ServerName -ServerCreds $ServerCreds

    if (-Not $_Session -or $_Session.State -eq 'Opened') {
        Write-Error ('Session Validation Failed') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - Session to Server Validated' -f (get-date).tostring())
    #endregion

    #region Check for PS Module
     if (-Not (Test-PSModuleInstalled -Session $_Session -ModuleName SQLServer -Install)) {
        Write-Error ('Missing PS Module on Server') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - SQLServer Module ready for use on Server' -f (get-date).tostring())
    #endregion

    #region Test SQL Connection
    if (-Not (Test-SQLConnection -Session $_Session -SQLInstance $SQLInstance)) {
        Write-Error ('A problem occured connecting to SQL Server') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - SQL Connection Validated' -f (get-date).tostring())
    #endregion

    #region Check if DB(s) exist
    foreach ($db in $DBNames) {
        if (Test-SQLDBExists -Session $_Session -SQLInstance $SQLInstanceName -DBName $DB -Quiet) {
            Write-Error ('Selected DB Name "{0}" does not exist on SQL Server' -f $db) -ErrorAction Stop
        }

        Write-Verbose ('{0}: VALIDATED - DB Name "{1}" was found on SQL Server' -f (get-date).ToString(),$db)
    }
    #endregion

    #region Set DB Recovery Model
    foreach ($db in $DBNames) {
        if ($db -ne 'tempdb') {
            Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create('$SQL.Databases[{0}].RecoveryModel = {1}' -f $db,$DBRecoveryModel)) -ErrorAction Stop
        }

        Write-Verbose ('{0}: Set DB "{1}" to Recovery Model "{2}"' -f (get-date).tostring(),$db,$DBRecoveryModel)
    }
    #endregion

    #region Set DB File Size/Growth
    foreach ($db in $DBNames) {
        Invoke-Command -Session $_Session -ScriptBlock {
            Param(
                $db,
                $DBFileGrowth,
                $DBFileSize,
                $DBFileGrowthType
            )

            foreach ($logfile in $SQL.Databases[$db].LogFiles) {
                $logfile.Growth = $DBFileGrowth
                $logfile.GrowthType = $DBFileGrowthType
                $logfile.Size = $DBFileSize
                $logfile.Alter()
                $logfile.Refresh()
            }
        } -ArgumentList $db,$DBFileGrowth,$DBFileSize,$DBFileGrowthType -ErrorAction Stop

        Invoke-Command -Session $_Session -ScriptBlock {
            Param(
                $db,
                $DBFileGrowth,
                $DBFileSize,
                $DBFileGrowthType
            )

            foreach ($filegroup in $SQL.Databases[$db].FileGroups) {
                foreach ($file in $filegroup.Files) {
                    $file.growth = $DBFileGrowth
                    $file.growthtype = $DBFileGrowthType
                    $file.size = $DBFileSize
                    $file.alter()
                    $file.refresh()
                }
            }
        } -ArgumentList $db,$DBFileGrowth,$DBFileSize,$DBFileGrowthType -ErrorAction Stop
    } 
    #endregion

}

function Add-DBExecRole {
    Param(
        # SQL Server to connect to with PS Remoting
        [parameter(Mandatory=$true)]
        [string]
        $ServerName,

        # Optional Credentials for connecting to server
        [parameter(Mandatory=$false)]
        [pscredential]
        $ServerCreds,

        # Install SQL Server PS Module if not already installed
        [parameter(Mandatory=$false)]
        [boolean]
        $InstallPSModuleifMissing = $true,

        # Name of SQL Server Instance
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $SQLInstanceName = 'Default',

        # List of Databases (system db's by default)
        [string[]]
        $DBNames = ('master','model','msdb')
    )

    #region Check PS Session to Server and create
    $_Session = Test-PSRemoting -ServerName $ServerName -ServerCreds $ServerCreds

    if (-Not $_Session -or $_Session.State -eq 'Opened') {
        Write-Error ('Session Validation Failed') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - Session to Server Validated' -f (get-date).tostring())
    #endregion

    #region Check for PS Module
     if (-Not (Test-PSModuleInstalled -Session $_Session -ModuleName SQLServer -Install)) {
        Write-Error ('Missing PS Module on Server') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - SQLServer Module ready for use on Server' -f (get-date).tostring())
    #endregion

    #region Test SQL Connection
    if (-Not (Test-SQLConnection -Session $_Session -SQLInstance $SQLInstance)) {
        Write-Error ('A problem occured connecting to SQL Server') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - SQL Connection Validated' -f (get-date).tostring())
    #endregion

    #region Check if DB(s) exist
    foreach ($db in $DBNames) {
        if (Test-SQLDBExists -Session $_Session -SQLInstance $SQLInstanceName -DBName $DB -Quiet) {
            Write-Error ('Selected DB Name "{0}" does not exist on SQL Server' -f $db) -ErrorAction Stop
        }

        Write-Verbose ('{0}: VALIDATED - DB Name "{1}" was found on SQL Server' -f (get-date).ToString(),$db)
    }
    #endregion

    #region Add db_exec role and grant stored procedure execute permissions
    foreach ($dbname in $dbnames) {
        Invoke-Command -Session $_Session -ScriptBlock {
            Param($dbname)

            $db = $SQL.Databases[$dbname]
            if (-Not ($db.Roles['db_exec'])) {
                $Role = New-Object Microsoft.SQLServer.Management.SMO.DatabaseRole
                $Role.Name = 'db_exec'
                $Role.Parent = $db
                $Role.Create()
            } else {
                $Role = $db.roles['db_exec']
            }

            $perms = New-Object Microsoft.SQLServer.Management.SMO.DatabasePermissionSet
            $perms.Execute = $true
            $db.Grant($perms,$Role.Name)

            $db.alter()
        } -ArgumentList $dbname

        Write-Verbose ('{0}: Added db_exec role on database "{1}"' -f (get-date).tostring(),$dbname)
    } 
    #endregion
}

function Set-SSLforSQLServer {
    Param(
        # SQL Server to connect to with PS Remoting
        [parameter(Mandatory=$true)]
        [string]
        $ServerName,

        # Optional Credentials for connecting to server
        [parameter(Mandatory=$false)]
        [pscredential]
        $ServerCreds,

        # Service Account Credentials for Cert Config
        [parameter(Mandatory=$false)]
        [pscredential]
        $svcAccountCreds,

        # Path to PFX File
        [Parameter(Mandatory=$false)]
        [string]
        $PFXFilePath,

        # Password for PFX File
        [Parameter(Mandatory=$false)]
        [securestring]
        $PFXPassword,

        # Thumbprint to use configuring SQL SSL
        [Parameter(Mandatory=$false)]
        [string]
        $SSLThumbprint,

        # Restart SQL after configuring
        [Parameter(Mandatory=$false)]
        [switch]
        $RestarSQLServer
    )

    #region Check PS Session to Server and create
    $_Session = Test-PSRemoting -ServerName $ServerName -ServerCreds $ServerCreds
    
    if (-Not $_Session -or $_Session.State -ne 'Opened') {
        Write-Error ('Session Validation Failed') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - Session to Server Validated' -f (get-date).tostring())
    #endregion

    #region Check PS Session to Server as service account and create
    $_svcAccountSession = Test-PSRemoting -ServerName $ServerName -ServerCreds $svcAccountCreds
    
    if (-Not $_svcAccountSession -or $_svcAccountSession -ne 'Opened') {
        Write-Error ('Service Account Session Validation Failed') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - Service Account Session to Server Validated' -f (get-date).tostring())
    #endregion

    #region Check for PS Module
    if (-Not (Test-PSModuleInstalled -Session $_Session -ModuleName SQLServer -Install -erroraction SilentlyContinue)) {
        Write-Error ('Missing PS Module on Server') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - SQLServer Module ready for use on Server' -f (get-date).tostring())
    #endregion

    #region Test SSL Thumbprint
    if ($SSLThumbprint) {
        $_Cert = Invoke-Command -Session $_svcAccountSession -ScriptBlock ([scriptblock]::Create("Get-Item Cert:\LocalMachine\My\$SSLThumbprint")) -ErrorAction Stop
    }
    #endregion

    #region Install Certificate
    if (-Not $SSLthumbprint) {
        $_Cert = Install-SSLCertificate -ServerName $ServerName -ServerCreds $svcAccountCreds -PFXFilePath $PFXFilePath -PFXPassword $PFXPassword -ErrorAction Stop
    }
    #endregion

    #region Configure Certificate for SQL
    if ($_Cert) {
        Invoke-Command -Session $_Session -ScriptBlock {
            Param($ThumbPrint)

            $SQLInstance = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\*MSSQL*' | Where-Object {$_.Property}

            Set-ItemProperty -Path ('\{0}\MSSQLServer\SuperSocketNetLib' -f $SQLInstance.PSPath) -Name Certificate -Value $Thumbprint
            Set-ItemProperty -Path ('\{0}\MSSQLServer\SuperSocketNetLib' -f $SQLInstance.PSPath) -Name ForceEncryption -Value 1
        } -ArgumentList $_Cert.Thumbprint -ErrorAction Stop
    } else {
        Write-Error ('Certificate Not Found on Server') -ErrorAction Stop
    }
    #endregion

    #region Restart SQL Server
    if ($RestarSQLServer) {
        Invoke-Command -Session $_Session -ScriptBlock {Restart-Service MSSQLSERVER -Force -Confirm:$false} -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
    }
    #endregion

    <#
    .SYNOPSIS

    Configure SSL for SQL Server

    .DESCRIPTION

    Either with a Certificate that is already Installed as the service account or with installing the PFX as the account

    .EXAMPLE


    #>
}

function Set-SQLMemConfig {
    Param(
        # SQL Server to connect to with PS Remoting
        [parameter(Mandatory=$true)]
        [string]
        $ServerName,

        # Optional Credentials for connecting to server
        [parameter(Mandatory=$false)]
        [pscredential]
        $ServerCreds,

        # Install SQL Server PS Module if not already installed
        [parameter(Mandatory=$false)]
        [boolean]
        $InstallPSModuleifMissing = $true,

        # Name of SQL Server Instance
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $SQLInstanceName = 'Default',

        # Use Default Memory values (Physical < 4G; Physical - 1G) (Physical > 4G < 16G; Physical - 2G) (Physical > 16G; Physical - 4G)
        [parameter(Mandatory=$false)]
        [boolean]
        $UseDefaultMemorySettings = $true,

        # Use the specified memory Limit in MB
        [parameter(Mandatory=$false)]
        [int]
        $MemoryLimitMB
    )

    #region Check PS Session to Server and create
    $_Session = Test-PSRemoting -ServerName $ServerName -ServerCreds $ServerCreds

    if (-Not $_Session -or $_Session.State -eq 'Opened') {
        Write-Error ('Session Validation Failed') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - Session to Server Validated' -f (get-date).tostring())
    #endregion

    #region Check for PS Module
     if (-Not (Test-PSModuleInstalled -Session $_Session -ModuleName SQLServer -Install)) {
        Write-Error ('Missing PS Module on Server') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - SQLServer Module ready for use on Server' -f (get-date).tostring())
    #endregion

    #region Test SQL Connection
    if (-Not (Test-SQLConnection -Session $_Session -SQLInstance $SQLInstance)) {
        Write-Error ('A problem occured connecting to SQL Server') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - SQL Connection Validated' -f (get-date).tostring())
    #endregion

    #region Set Memory
    if ($UseDefaultMemorySettings) {
        $_PhysicalMemory = Invoke-Command -Session $_Session -ScriptBlock {$SQL.PhysicalMemory}

        if ($_PhysicalMemory -lt 4GB/1MB) {
            $MemoryLimitMB = $_PhysicalMemory - 1GB/1MB
        } elseif ($_PhysicalMemory -gt 4GB/1MB -and $_PhysicalMemory -lt 16GB/1MB) {
            $MemoryLimitMB = $_PhysicalMemory - 2GB/1MB
        } else {
            $MemoryLimitMB = $_PhysicalMemory - 4GB/1MB
        }
    }

    if (-Not $MemoryLimitMB) { 
        Write-Error ('Value for Memory limit missing') -ErrorAction Stop
    }

    Invoke-Command -Session $_Session -ScriptBlock {
        Param($MemoryLimitMB)

        $SQL.Configuration.MaxServerMemory = $MemoryLimitMB
        $SQL.Configuration.Alter()
    } -ArgumentList $MemoryLimitMB

    Write-Verbose ('{0}: SQL Max Memory Configured as "{1}"' -f (get-date).tostring(),$MemoryLimitMB)
    #endregion
}

function Set-SQLBackupConfig {
    Param(
        # Server to Connect and configure SQL History
        [Parameter(Mandatory=$true)]
        [string]
        $ServerName,
        
        # Optional Credentials for connecting to Server
        [Parameter(Mandatory=$false)]
        [PSCredential]
        $ServerCreds,

        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $SQLInstance = 'Default',

        # Enable Backup Compression
        [Parameter(Mandatory=$false)]
        [boolean]
        $EnableBackupCompression = $true,

        # Path to set for backups default location
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $DefaultBackupPath,

        # Create folders in Backup Path if missing
        [Parameter(Mandatory=$false)]
        [boolean]
        $CreateFolderifMissing = $true
    )

    #region Check PS Session to Server and create
    $_Session = Test-PSRemoting -ServerName $ServerName -ServerCreds $ServerCreds

    if (-Not $_Session -or $_Session.State -eq 'Opened') {
        Write-Error ('Session Validation Failed') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - Session to Server Validated' -f (get-date).tostring())
    #endregion

    #region Check for PS Module
     if (-Not (Test-PSModuleInstalled -Session $_Session -ModuleName SQLServer -Install)) {
        Write-Error ('Missing PS Module on Server') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - SQLServer Module ready for use on Server' -f (get-date).tostring())
    #endregion

    #region Test SQL Connection
    if (-Not (Test-SQLConnection -Session $_Session -SQLInstance $SQLInstance)) {
        Write-Error ('A problem occured connecting to SQL Server') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - SQL Connection Validated' -f (get-date).tostring())
    #endregion

    #region Verify Backup Path
    $_Path = Get-Item -Path $DefaultBackupPath -ErrorAction SilentlyContinue
    if ($CreateFolderifMissing -and -Not $_Path) {
        $_Path = New-Item -Path $DefaultBackupPath -ItemType Directory
    }
    if (-Not $_Path) {
        Write-Error ('Path does not already exist and unable to create') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - Using Backup path "{1}"' -f (get-date).tostring(),$DefaultBackupPath)
    #endregion

    #region Configure Backup Settings
    if ($EnableBackupCompression) {
        Invoke-Command -Session $_Session -ScriptBlock {
            $SQL.Configuration.DefaultBackupCompression.ConfigValue = 1
            $SQL.Configuration.Alter()
        }
    }

    Write-Verbose ('{0}: Updated Backup Compression to be enabled' -f (get-date).tostring())
    
    Invoke-command -Session $_Session -ScriptBlock {
        Param($DefaultBackupPath)
        $SQL.BackupDirectory = $DefaultBackupPath
        $SQL.Alter()
    } -ArgumentList $_Path.FullName

    Write-Verbose ('{0}: Updated Default Backup Path to "{1}"' -f (get-date).tostring(),$_path.FullName)
    #endregion
}

function Set-SQLJobHistory {
    Param(
        # Server to Connect and configure SQL History
        [Parameter(Mandatory=$true)]
        [string]
        $ServerName,
        
        # Optional Credentials for connecting to Server
        [Parameter(Mandatory=$false)]
        [PSCredential]
        $ServerCreds,

        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $SQLInstance = 'Default',
        
        # Value to Set SQL Job History
        [Parameter(Mandatory=$false)]
        [Int]
        $JobHistoryMax = 10000,
        
        # Value to Set SQL History
        [Parameter(Mandatory=$false)]
        [Int]
        $HistoryMax = 1000
    )

    #region Check PS Session to Server and create
    $_Session = Test-PSRemoting -ServerName $ServerName -ServerCreds $ServerCreds

    if (-Not $_Session -or $_Session.State -eq 'Opened') {
        Write-Error ('Session Validation Failed') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - Session to Server Validated' -f (get-date).tostring())
    #endregion
 
    #region Check for PS Module
    if (-Not (Test-PSModuleInstalled -Session $_Session -ModuleName SQLServer -Install)) {
        Write-Error ('Missing PS Module on Server') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - SQLServer Module ready for use on Server' -f (get-date).tostring())
    #endregion

    #region Test SQL Connection
    if (-Not (Test-SQLConnection -Session $_Session -SQLInstance $SQLInstance)) {
        Write-Error ('A problem occured connecting to SQL Server') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - SQL Connection Validated' -f (get-date).tostring())
    #endregion

    #region Set History Settings
    Invoke-Command -Session $_Session -ScriptBlock {
        Param(
            $HistoryMax,
            $JobHistoryMax
        )

        $SQL.JobServer.MaximumHistoryRows = $HistoryMax
        $SQL.JobServer.MaximumJobHistoryRows = $JobHistoryMax

    } -ArgumentList $HistoryMax,$JobHistoryMax

    Write-Verbose ('{0}: Updated Job History to "{1}" and History to "{2}"' -f (get-date).tostring(),$JobHistoryMax,$HistoryMax)
    #endregion
}

function Set-SQLPSExecutionPolicy {
    Param(
        # Server to Connect and configure SQL History
        [Parameter(Mandatory=$true)]
        [string]
        $ServerName,
        
        # Optional Credentials for connecting to Server
        [Parameter(Mandatory=$false)]
        [PSCredential]
        $ServerCreds,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Unrestricted','RemoteSigned','AllSigned','Bypass','Default','Restricted')]
        [string]
        $ExecutionPolicy = 'Unrestricted'
    )

    #region Check PS Session to Server and create
    $_Session = Test-PSRemoting -ServerName $ServerName -ServerCreds $ServerCreds
    
    if (-Not $_Session -or $_Session.State -ne 'Opened') {
        Write-Error ('Session Validation Failed') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - Session to Server Validated' -f (get-date).tostring())
    #endregion

    Invoke-Command -Session $_Session -ScriptBlock {
        Param($ExecutionPolicy)

        $Items = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.SqlServer.Management.PowerShell.sqlps*'

        foreach ($item in $items) {
            $Item | Set-ItemProperty -Name 'ExecutionPolicy' -Value $ExecutionPolicy
        }
    } -ArgumentList $ExecutionPolicy -ErrorAction Stop

    Write-Verbose ('{0}: Updated Execution Policy for SQLPS to "{1}"' -f (get-date).tostring(),$ExecutionPolicy)
}

function Set-SQLListener {
    Param(
        # Server to Connect and configure SQL History
        [Parameter(Mandatory=$true)]
        [string]
        $ServerName,
        
        # Optional Credentials for connecting to Server
        [Parameter(Mandatory=$false)]
        [PSCredential]
        $ServerCreds,

        # configure TCP Listener
        [Parameter(Mandatory=$false)]
        [switch]
        $EnableTCP,

        # configure NamedPipes Listener
        [Parameter(Mandatory=$false)]
        [switch]
        $EnableNamedPipes,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $SQLServiceName = 'MSSQLSERVER',

        # Restart SQL Server After config
        [Parameter(Mandatory=$false)]
        [Switch]
        $RestartSQLServer
    )

    #region Check PS Session to Server and create
    $_Session = Test-PSRemoting -ServerName $ServerName -ServerCreds $ServerCreds
    
    if (-Not $_Session -or $_Session.State -eq 'Opened') {
        Write-Error ('Session Validation Failed') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - Session to Server Validated' -f (get-date).tostring())
    #endregion

    #region Compare Current State
    Invoke-Command -Session $_Session -ScriptBlock {
        [reflection.assembly]::LoadWithPartialName("Microsoft.SqlServer.Smo") | Out-Null
        [reflection.assembly]::LoadWithPartialName("Microsoft.SqlServer.SqlWmiManagement") | Out-Null

        $smo = New-Object ('Microsoft.SqlServer.Management.Smo.wmi.ManagedComputer')
    } -ErrorAction SilentlyContinue

    $SMOTCP = Invoke-Command -Session $_Session -ScriptBlock {
        $SMOTCP = $smo.GetSmoObject(($smo.ServerInstances.ServerProtocols | Where-Object {$_.name -like 'tcp'}).urn)
        $SMOTCP
    } -ErrorAction SilentlyContinue

    $SMONP = Invoke-Command -Session $_Session -ScriptBlock {
        $SMONP = $smo.GetSmoObject(($smo.ServerInstances.ServerProtocols | Where-Object {$_.name -like 'np'}).urn)
        $SMONP
    } -ErrorAction SilentlyContinue

    if (-Not $SMOTCP -or -Not $SMONP) {
        Write-Error ('Protocol(s) not found on server') -ErrorAction Stop
    }

    Write-Verbose ('{0}: Found SQL SMO Protocol Objects' -f (get-date).tostring())
    #endregion

    #region Check SQL Server Service
    if ($RestartSQLServer) {
        if (-Not (Invoke-Command -Session $_session -ScriptBlock ([scriptblock]::Create("Get-Service $SQLServiceName")))) {
            Write-Error ('SQL Server Service "{0}" not found on server' -f $SQLServiceName) -ErrorAction Stop
        }

        Write-Verbose ('{0}: SQL Server Service "{1}" found' -f (get-date).tostring(),$SQLServiceName)
    }
    #endregion

    #region Configure Listener
    if ($EnableTCP -ne $SMOTCP.IsEnabled) {
        Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create(('$SMOTCP.IsEnabled = {0}; $SMOTCP.Alter()' -f $EnableTCP))) -ErrorAction Stop
        Write-Verbose ('{0}: Updated TCP Protocol to "{1}"' -f (get-date).tostring(),$EnableTCP.ToString())
    }
    if ($EnableNamedPipes -ne $SMONP.IsEnabled) {
        Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create(('$SMONP.IsEnabled = {0}; $SMONP.Alter()' -f $EnableNamedPipes))) -ErrorAction Stop
        Write-Verbose ('{0}: Updated NamedPipes Protocol to "{1}"' -f (get-date).tostring(),$EnableNamedPipes.ToString())
    }

    if ($RestartSQLServer) {
        Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::create("Restart-Service $SQLServiceName -Force"))
        Write-Verbose ('{0}: Restarted SQL Server "{1}"' -f (get-date).tostring(),$SQLServiceName)
    }
    #endregion
}

function Grant-SQLServiceRights {
    Param(
        # Server to Connect and configure SQL History
        [Parameter(Mandatory=$true)]
        [string]
        $ServerName,
        
        # Optional Credentials for connecting to Server
        [Parameter(Mandatory=$false)]
        [PSCredential]
        $ServerCreds,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $ServiceNames = ('MSSQLSERVER','SQLSERVERAGENT','SQLBROWSER','MSSQLFDLauncher'),

        # Permission Level to assign
        [Parameter(Mandatory=$false)]
        [ValidateSet('Full','ReadOnly')]
        [String]
        $PermissionLevel = 'Full',

        # Group Name to add permissions
        [Parameter(Mandatory=$true)]
        [String]
        $GroupName
    )

    #region Check PS Session to Server and create
    $_Session = Test-PSRemoting -ServerName $ServerName -ServerCreds $ServerCreds
    
    if (-Not $_Session -or $_Session.State -eq 'Opened') {
        Write-Error ('Session Validation Failed') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - Session to Server Validated' -f (get-date).tostring())
    #endregion

    #region Verify Services Exist
    foreach ($_ServiceName In $ServiceNames) {
        $_Service = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("Get-Service -Name $_ServiceName")) -ErrorAction SilentlyContinue
    
        if (-Not $_Service) {
            Write-Error ('Service "{0}" not Found on Server' -f $_ServiceName) -ErrorAction Stop
        }

        if ($_Service.Count -gt 1) {
            Write-Error ('More than one Service Resturned for "{0}"' -f $_ServiceName) -ErrorAction Stop
        }

        Write-Verbose ('{0}: VALIDATED - Found Service "{1}" on Server "{2}"' -f (get-date).tostring(),$_ServiceName,$_Session.ComputerName)
    }
    #endregion

    #region Verify Group Exists 
    $_Group = Get-ADGroup -filter "name -eq '$GroupName'" -ErrorAction SilentlyContinue

    if (-Not $_Group) {
        Write-Error ('Group "{0}" not found in AD' -f $GroupName)
    }
    if ($_Group.Count -gt 1) {
        Write-Error ('Group "{0}" returned more than one object' -f $GroupName)
    }

    $_SID = ((New-Object System.Security.Principal.NTAccount($GroupName)).Translate([Security.Principal.SecurityIdentifier]).Value)

    if (-Not $_SID) {
        Write-Error ('Error getting SID for Group {0}' -f $GroupName)
    }

    Write-Verbose ('{0}: VALIDATED - AD Group "{1}" Found and ready for use with SID "{2}"' -f (get-date).tostring(),$_group.name,$_SID)
    #endregion

    #region Grant scmanager Access to users remotely
    $_scManagerCurrent = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create('sc.exe sdshow scmanager | Where-object {$_}'))
    if ($_scManagerCurrent.Contains('(A;;CC;;;AU)')) {
        $_scManagerNew = $_scManagerCurrent.Replace('(A;;CC;;;AU)','(A;;CCLCSWRPRC;;;AU)')
    }

    $_scManagerResult = Invoke-Command -Session $_session -ScriptBlock ([scriptblock]::Create("sc.exe sdset scmanager '$_scManagerNew'")) -ErrorAction SilentlyContinue

    if ($_scManagerResult -notlike '*SUCCESS') {
        Write-Error ('A problem occured updating "scmanager" from "{0}" to "{1}", you may need to manually revert with sc.exe' -f $_scManagerCurrent, $_scManagerNew) -ErrorAction Stop
    }

    Write-Verbose ('{0}: Updated "scmanager" service SDDL from "{1}" to "{2}"' -f (get-date).tostring(),$_scManagerCurrent,$_scManagerNew)
    #endregion

    #region Grant Group access to Services
    if ($PermissionLevel -eq 'Full') {
        $_SDDLRights = "(A;;CCLCSWRPWPDTLOCRRC;;;$_SID)"
    } else {
        $_SDDLRights = "(A;;CCLCSWLOCRRC;;;$_SID)"
    }

    Write-Verbose ('{0}: Adding "{1}" to SDDL Rights on Services "{2}"' -f (get-date).tostring(),$_SDDLRights,($ServiceNames -join ','))

    foreach ($_s in $ServiceNames) {
        $_ServiceCurrent = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("sc.exe sdshow $_s")) -ErrorAction SilentlyContinue | Where-Object {$_}
        
        if (-Not $_ServiceCurrent) {
            Write-Error ('Unable to get SDDL rights for Service "{0}"' -f $_s) -ErrorAction Stop
        }

        Write-Verbose ('{0}: Current SDDL Rights for Service "{1}" is "{2}"' -f (get-date).tostring(),$_s,$_ServiceCurrent)

        if ($_ServiceCurrent -notlike "*$_SDDLRights*") {
            $_IndexofS = $_ServiceCurrent.IndexOf('S:')
            $_ServiceNew = ($_ServiceCurrent[0..($_IndexofS -1)] -Join '') + $_SDDLRights + ($_ServiceCurrent[($_IndexofS)..($_ServiceCurrent.length -1)] -Join '')
    
            Write-Verbose ('{0}: New SDDL Rights for Service "{1}" is "{2}"' -f (get-date).tostring(),$_s,$_ServiceNew)
    
            $_ServiceResult = $null
            $_ServiceResult = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("sc.exe sdset $_s '$_ServiceNew'")) -ErrorAction SilentlyContinue
    
            if (-Not $_ServiceResult) {
                Write-Error ('Unable to Set SDDL Rights for Service "{0}"' -f $_s)
            }
    
            Write-Verbose ('{0}: Service "{1}" Rights Updated' -f (get-date).tostring(),$_s)
        } else {
            Write-Warning ('SDDL Rights "{0}" already Exist on Service "{1}"' -f $_SDDLRights, $_s)
        }
    }
    #endregion
}

function Enable-FSRMforSQL {
    Param(
        # Server to Connect and configure SQL History
        [Parameter(Mandatory=$true)]
        [string]
        $ServerName,
        
        # Optional Credentials for connecting to Server
        [Parameter(Mandatory=$false)]
        [PSCredential]
        $ServerCreds,

        # Install FSRM Feature
        [Parameter(Mandatory=$false)]
        [boolean]
        $InstallFSRM = $true,

        # Incude FSRM Management Tools
        [Parameter(Mandatory=$false)]
        [boolean]
        $IncludeManagementTools = $true,

        # Include Subfeatures for FSRM
        [Parameter(Mandatory=$false)]
        [boolean]
        $IncludeAllSubFeatures = $true,
        
        # FQDN or IP of SMTP Server
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $SMTPRelay,

        # FSRM Admin Email Address
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $AdminEmailAddress,

        # FSRM Action EMail To for File Screen
        [Parameter(Mandatory=$false)]
        [string]
        $ActionMailTo = '[Admin Email]',

        # FSRM Action Subject for File Screen
        [Parameter(Mandatory=$false)]
        [String]
        $ActionSubject = 'Unauthorized file from the [Violated File Group] file group detected',

        # FSRM Action Body for File Screen
        [Parameter(Mandatory=$false)]
        [string]
        $ActionBody = 'User [Source Io Owner] attempted to save [Source File Path] to [File Screen Path] on the [Server] server. This file is in the [Violated File Group] file group, which is not permitted on the server.',

        # File Screen exclusion Pattern for Backups
        [Parameter(Mandatory=$false)]
        [string[]]
        $BackupsPattern = ('*.bak','*.trn','*.ckp'),

        # File Screen exclusion Pattern for Logs
        [Parameter(Mandatory=$false)]
        [string[]]
        $LogsPattern = ('*.ldf*'),

        # File Screen exclusion Patter for Data
        [Parameter(Mandatory=$false)]
        [string[]]
        $DataPattern = ('*.mdf*','*.ndf*'),

        # File Screen exclusion Pattern for Root/MSSQL
        [Parameter(Mandatory=$false)]
        [string[]]
        $RootPattern = ('*.cer*','*.mdf*','*.ndf*','*.ldf*'),

        # Paths for Backups to apply file Screen
        [Parameter(Mandatory=$false)]
        [string[]]
        $BackupPaths = ('E:\Backups'),

        # Paths for Data to apply file screen
        [Parameter(Mandatory=$false)]
        [string[]]
        $DataPaths = ('E:\SQLDATA01','E:\TDBDATA01'),

        # Paths for Logs to apply file screen
        [Parameter(Mandatory=$false)]
        [string[]]
        $LogPaths = ('E:\SQLLOGS01','E:\TDBLOGS01')
    )

    #region Check PS Session to Server and create
    $_Session = Test-PSRemoting -ServerName $ServerName -ServerCreds $ServerCreds
    
    if (-Not $_Session -or $_Session.State -eq 'Opened') {
        Write-Error ('Session Validation Failed') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - Session to Server Validated' -f (get-date).tostring())
    #endregion

    #region Test SQL Connection
    if (-Not (Test-SQLConnection -Session $_Session -SQLInstance $SQLInstance)) {
        Write-Error ('A problem occured connecting to SQL Server') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - SQL Connection Validated' -f (get-date).tostring())
    #endregion

    #region Validate Paths
    $_Paths = $BackupPaths + $DataPaths + $LogPaths

    foreach ($_Path in $_Paths) {
        $_PathResult = $null
        $_PathResult = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("Get-Item -Path $_Path -ErrorAction SilentlyContinue"))

        if (-Not $_PathResult) {
            Write-Error ('Path "{0}" not found on "{1}"' -f $_Path, $_Session.ComputerName) -ErrorAction Stop
        }

        Write-Verbose ('{0}: VALIDATED - Path "{1}" Found on "{2}"' -f (get-date).tostring(),$_PathResult.fullname,$_Session.ComputerName)
    }
    #endregion

    #region Verify SMTP Relay
    if (-not (Test-Ping -Server $SMTPRelay -Quiet)) {
        Write-Error ('SMTP Relay Server "{0}" does not respond to ping' -f $SMTPRelay)
    }

    Write-Verbose ('{0}: VALIDATED - SMTP Relay "{1}" resolves and responds to ping' -f (get-date).tostring(),$SMTPRelay)

    if (-Not (Test-Port -Server $SMTPRelay -Port 25).Successful) {
        Write-Error ('SMTP Relay "{0}" not responding on port "25"' -f $SMTPRelay)
    }

    Write-Verbose ('{0}: VALIDATED - SMTP Relay "{1}" responds on port "25"' -f (get-date).tostring(),$SMTPRelay)
    #endregion

    #region Verify Not already Installed
    $_FSRMState = Invoke-Command -Session $_Session -ScriptBlock {(Get-WindowsFeature FS-Resource-Manager).InstallState}
    if ($InstallFSRM -eq 'Installed') {
        if ($_FSRMState) {
            Write-Warning ('FSRM is already installed on Server')
        } else {
            Write-Verbose ('{0}: FSRM Ready to install on Server' -f (get-date).tostring())
        }
    } Else {
        if (-Not $_FSRMState -eq 'Installed') {
            Write-Error ('FSRM is Not installed on Server') -ErrorAction Stop
        }

        Write-Verbose ('{0}: FSRM is installed on Server' -f (get-date).tostring())
    }
    #endregion

    #region Install FSRM Feature
    if ($InstallFSRM) {
        $_InstallResult = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("Add-WindowsFeature FS-Resource-Manager -IncludeManagementTools:$IncludeManagementTools -IncludeAllSubfeature:$IncludeAllSubFeatures")) -ErrorAction SilentlyContinue

        if (-Not $_InstallResult.Success) {
            Write-Error ('Install of FSRM feature did not succeed') -ErrorAction Stop
        }

        Write-Verbose ('{0}: Installed FSRM Feature Successfully')

        Invoke-Command -Session $_Session -ScriptBlock {Import-Module FileServerResourceManager; Restart-Service srmsvc} -ErrorAction SilentlyContinue | Out-Null
    }
    #endregion

    #region Configure FSRM Settings
    $_FSRMSettings = Invoke-Command -Session $_Session -ScriptBlock {Get-FsrmSetting}

    if ($_FSRMSettings.SMTPServer -ne $SMTPRelay){
        Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("Set-FSRMSetting -SMTPServer $SMTPRelay")) -ErrorAction Stop

        Write-Verbose ('{0}: Updated SMTP Server Relay to "{1}"' -f (get-date).tostring(),$SMTPRelay)
    }
    if ($_FSRMSettings.AdminEmailAddress -ne $AdminEmailAddress -and $AdminEmailAddress) {
        Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("Set-FSRMSetting -AdminEmailAddress $AdminEmailAddress")) -ErrorAction Stop

        Write-Verbose ('{0}: Updated Admin Email Address to "{1}"' -f (get-date).tostring(),$AdminEmailAddress)
    }
    #endregion

    #region Configure Screening Patterns
    $_FileGroups = Invoke-Command -Session $_Session -ScriptBlock {Get-FSRMFileGroup -ErrorAction SilentlyContinue}

    if ('SQL Backup Files' -notin $_FileGroups.Name) {
        $_BackupsPatternResult = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("New-FSRMFileGroup -Name 'SQL Backup Files' -IncludePattern '*.*' -ExcludePattern '$($backupsPattern -join ',')'")) -ErrorAction SilentlyContinue

        if (-Not $_BackupsPatternResult) {
            Write-Error ('Error Occurred createing "SQL Backup Files" with exlusion Pattern "{0}"' -f ($BackupsPattern -join ',')) -ErrorAction Stop
        }

        Write-Verbose ('{0}: Created File Group "SQL Backup Files" with pattern "{1}"' -f (get-date).tostring(),($backupPattern -join ','))
    }
    if ('SQL Log Files' -notin $_FileGroups.Name) {
        $_LogsPatternResult = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("New-FSRMFileGroup -Name 'SQL Log Files' -IncludePattern '*.*' -ExcludePattern '$($LogsPattern -join ',')'")) -ErrorAction Stop
        
        if (-Not $_LogsPatternResult) {
            Write-Error ('Error Occured Creating "SQL Log Files" with exclusion Pattern "{0}"' -f ($LogsPattern -join ',')) -ErrorAction Stop
        }

        Write-Verbose ('{0}: Created File Group "SQL Log Files" with pattern "{1}"' -f (get-date).tostring(),($LogsPattern -join ','))
    }
    if ('SQL Data Files' -notin $_FileGroups.Name) {
        $_DataPatternResult = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("New-FSRMFileGroup -Name 'SQL Data Files' -IncludePattern '*.*' -ExcludePattern '$($DataPattern -join ',')'")) -ErrorAction Stop

        if (-Not $_DataPatternResult) {
            Write-Error ('Error Occured Creating "SQL Data Files" with exclusion Pattern "{0}"' -f ($DataPattern -join ',')) -ErrorAction Stop
        }

        Write-Verbose ('{0}: Created File Group "SQL Data Files" with pattern "{1}"' -f (get-date).tostring(),($DataPattern -join ','))
    }
    if ('SQL All Files' -notin $_FileGroups.Name) {
        $_RootPatternResult = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("New-FSRMFileGroup -Name 'SQL All Files' -IncludePattern '*.*' -ExcludePattern '$($RootPattern -join ',')'")) -ErrorAction Stop

        if (-Not $_RootPatternResult) {
            Write-Error ('Error Occured Creating "SQL All Files" with exclusion Pattern "{0}"' -f ($RootPattern -join ',')) -ErrorAction Stop
        }

        Write-Verbose ('{0}: Created File Group "SQL All Files" with pattern "{1}"' -f (get-date).tostring(),($RootPattern -join ','))
    }
    #endregion

    #region Configure Screening Paths and Action
    Invoke-Command -Session $_Session -ScriptBlock {
        Param(
            $ActionMailTo,
            $ActionSubject,
            $ActionBody
        )

        $FSRMAction = New-FSRMAction -Type Email -MailTo $ActionMailTo -Subject $ActionSubject -Body $ActionBody
    } -ArgumentList $ActionMailTo,$ActionSubject,$ActionBody
    #endregion

    #region Create File Screen for Backups
    $_FSRMScreens = Invoke-Command -Session $_Session -ScriptBlock {Get-FSRMFileScreen} -ErrorAction SilentlyContinue
    foreach ($_Path in $BackupPaths) {
        if ($_Path -notin $_FSRMScreens.Path) {
            $_FileScreenResult = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create('New-FSRMFileScreen -Path {0} -IncludeGroup "SQL Backup Files" -Active -Notification $FSRMAction' -f $_Path))
            
            if (-not $_FileScreenResult) {
                Write-Error ('Error creating File Screen for path "{0}"' -f $_Path) -ErrorAction Stop
            }
            Write-Verbose ('{0}: Created File Screen for "{1}"' -f (get-date).tostring(),$_Path)
        }
    }
    #endregion

    #region Create File Screen for Data Paths
    foreach ($_Path in $DataPaths) {
        if ($_Path -notin $_FSRMScreens.Path) {
            $_FileScreenResult = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create('New-FSRMFileScreen -Path {0} -IncludeGroup "SQL Data Files" -Active -Notification $FSRMAction' -f $_Path))
            
            if (-not $_FileScreenResult) {
                Write-Error ('Error creating File Screen for path "{0}"' -f $_Path) -ErrorAction Stop
            }
            Write-Verbose ('{0}: Created File Screen for "{1}"' -f (get-date).tostring(),$_Path)
        }
    }
    #endregion

    #region Create File Screen for Log Paths
    foreach ($_Path in $LogPaths) {
        if ($_Path -notin $_FSRMScreens.Path) {
            $_FileScreenResult = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create('New-FSRMFileScreen -Path {0} -IncludeGroup "SQL Log Files" -Active -Notification $FSRMAction' -f $_Path))
            
            if (-not $_FileScreenResult) {
                Write-Error ('Error creating File Screen for path "{0}"' -f $_Path) -ErrorAction Stop
            }
            Write-Verbose ('{0}: Created File Screen for "{1}"' -f (get-date).tostring(),$_Path)
        }
    }
    #endregion

    #region Create File Screen for MSSQL Data Path
    $_AllPatterResult = Invoke-Command -Session $_Session -ScriptBlock {New-FsrmFileScreen -Path $sql.MasterDBPath -IncludeGroup 'SQL All Files' -Active -Notification $FSRMAction}

    if (-Not $_AllPatterResult) {
        Write-Error ('Error creating File Screen for path "{0}"' -f $_Path) -ErrorAction Stop
    }

    Write-Verbose ('{0}: Created File Screen for "{1}"' -f (get-date).tostring(),$_Path)
    #endregion

}
#endregion

function Install-SQLServer {
    Param(
        [parameter(Mandatory=$true)]
        [string]    
        $ServerName,
        
        [parameter(Mandatory=$false)]
        [pscredential]
        $ServerCreds,

        [parameter(Mandatory=$true)]
        [string]
        $SQLISOPath,

        [parameter(Mandatory=$true)]
        [string]
        $SQLInstallKey,

        [Parameter(Mandatory=$true)]
        [PSCredential]
        $svcAccountCreds,

        [Parameter(Mandatory=$true)]
        [String]
        $SysAdminGroup,

        [Parameter(Mandatory=$false)]
        [String]
        $FileShareGroup,

        [Parameter(Mandatory=$false)]
        [boolean]
        $ConfigureFileShare = $true,

        [Parameter(Mandatory=$false)]
        [string]
        $FileShareName = 'DataAccess$',

        [parameter(Mandatory=$false)]
        [ValidateSet('SQLEngine','Replication','FullText','Conn')]
        [string[]]
        $SQLServerFeatures = ('SQLEngine','Replication','FullText','Conn'),
        
        [parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]
        $SQLInstanceName = 'MSSQLSERVER',

        # Base Directory/Location for SQL Instance (needs to be <drive>:\\ with two backslashes for the root)
        [parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]
        $SQLInstanceDir = 'E:\\',

        # Location where script files will be located
        [parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]
        $ScriptsDir = 'E:\Scripts',

        # Location Where software will be located
        [parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]
        $SoftwareDir = 'E:\Software',

        # Location where the SQL MSSQL folder will be placed (needs to be <drive>: without any slashes for the root)
        [parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]
        $InstallSQLDataDir = 'E:',

        # Default location for Backups
        [parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]
        $SQLBackupDir='E:\Backups',

        # Default Location for SQL User DB Data Files
        [parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]
        $SQLUserDBDataDir='E:\SQLDATA01',

        # Default Location for SQL User DB Log Files
        [parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]
        $SQLUserDBLogsDir='E:\SQLLOGS01',

        # Default Location for TempDB Data Files
        [parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]
        $SQLTempDBDataDir='E:\TDBDATA01',

        # Default Location for TempDB Log Files
        [parameter(Mandatory=$false)]
        [ValidateNotNullorEmpty()]
        [string]
        $SQLTempDBLogsDir='E:\TDBLOGS01',

        # TempDB File Count for 2016 and newer
        [Parameter(Mandatory=$false)]
        [int]
        $SQLTempDBFileCount = 1,

        # TempDB File Growth Size for 2016 and newer
        [Parameter(Mandatory=$false)]
        [int]
        $SQLTempDBFileGrowth = 100,

        # TempDB File Size for 2016 and newer
        [Parameter(Mandatory=$false)]
        [int]
        $SQLTempDBFileSize = 100,

        # TempDB Log File Size for 2016 and newer
        [Parameter(Mandatory=$false)]
        [int]
        $SQLTempDBLogFileSize = 100,

        # TempDB Log File Growth for 2016 and newer
        [Parameter(Mandatory=$false)]
        [int]
        $SQLTempDBLogFileGrowth = 100,

        # Install Management Studio on Server
        [parameter(Mandatory=$false)]
        [switch]
        $InstallMgmtStudio,

        # Set to create Directories if they don't exist
        [Parameter(Mandatory=$false)]
        [switch]
        $CreateMissingDirectories
    )

    #region Check PS Session to Server and create
    $_Session = Test-PSRemoting -ServerName $ServerName -ServerCreds $ServerCreds

    if (-Not $_Session -or $_Session.State -eq 'Opened') {
        Write-Error ('Session Validation Failed') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - Session to Server Validated' -f (get-date).tostring())
    #endregion

    #region Check Directories
    $_ScriptsDir = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("Get-Item $ScriptsDir")) -ErrorAction SilentlyContinue
    $_SoftwareDir = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("Get-Item $SoftwareDir")) -ErrorAction SilentlyContinue
    $_SQLBackupDir = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("Get-Item $SQLBackupDir")) -ErrorAction SilentlyContinue
    $_SQLUserDBDataDir = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("Get-Item $SQLUserDBDataDir")) -ErrorAction SilentlyContinue
    $_SQLUserDBLogsDir = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("Get-Item $SQLUserDBLogsDir")) -ErrorAction SilentlyContinue
    $_SQLTempDBDataDir = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("Get-Item $SQLTempDBDataDir")) -ErrorAction SilentlyContinue
    $_SQLTempDBLogsDir = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("Get-Item $SQLTempDBLogsDir")) -ErrorAction SilentlyContinue
    $_SQLInstanceDir = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("Get-Item $SQLInstanceDir")) -ErrorAction SilentlyContinue
    $_InstallSQLDataDir = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("Get-Item $InstallSQLDataDir")) -ErrorAction SilentlyContinue
    
    if (-Not $CreateMissingDirectories) {
        if (-Not ($_ScriptsDir)) {
            Write-Error ('Script Directory "{0}" was not found on Server "{1}"' -f $ScriptsDir,$_session.ComputerName) -ErrorAction Stop
        }
        Write-Verbose ('{0}: VALIDATED - Scripts Directory "{1}" Found on Server' -f (get-date).tostring(),$_ScriptsDir)

        if (-Not ($_SoftwareDir)) {
            Write-Error ('Software Directory "{0}" not found on server "{1}"' -f $SoftwareDir,$_Session.ComputerName) -ErrorAction Stop
        }
        Write-Verbose ('{0}: VALIDATED - Software Directory "{1}" Found on Server' -f (get-date).tostring(),$_SoftwareDir)

        if (-Not ($_SQLBackupDir)) {
            Write-Error ('SQL Backup Directory "{0}" not found on server "{1}"' -f $SQLBackupDir,$_Session.ComputerName) -ErrorAction Stop
        }
        Write-Verbose ('{0}: VALIDATED - Backup Directory "{1}" Found on Server' -f (get-date).tostring(),$_SQLBackupDir)
        
        if (-Not ($_SQLUserDBDataDir)) {
            Write-Error ('SQL UserDB Data Directory "{0}" not found on server "{1}"' -f $SQLUserDBDataDir,$_Session.ComputerName) -ErrorAction Stop
        }
        Write-Verbose ('{0}: VALIDATED - UserDB Data Directory "{1}" Found on Server' -f (get-date).tostring(),$_SQLUserDBDataDir)

        if (-Not ($_SQLUserDBLogsDir)) {
            Write-Error ('SQL UserDB Logs Directory "{0}" not found on server "{1}"' -f $SQLUserDBLogsDir,$_Session.ComputerName) -ErrorAction Stop
        }
        Write-Verbose ('{0}: VALIDATED - UserDB Logs Directory "{1}" Found on Server' -f (get-date).tostring(),$_SQLUserDBLogsDir)

        if (-Not ($_SQLTempDBDataDir)) {
            Write-Error ('SQL TempDB Data Directory "{0}" not found on server "{1}"' -f $SQLTempDBDataDir,$_Session.ComputerName) -ErrorAction Stop
        }
        Write-Verbose ('{0}: VALIDATED - TempDB Data Directory "{1}" Found on Server' -f (get-date).tostring(),$_SQLTempDBDataDir)

        if (-Not ($_SQLTempDBLogsDir)) {
            Write-Error ('SQL TempDB Logs Directory "{0}" not found on server "{1}"' -f $SQLTempDBLogsDir,$_Session.ComputerName) -ErrorAction Stop
        }
        Write-Verbose ('{0}: VALIDATED - TempDB Logs Directory "{1}" Found on Server' -f (get-date).tostring(),$_SQLTempDBLogsDir)

        if (-Not ($_InstallSQLDataDir)) {
            Write-Error ('Install SQL Data Directory "{0}" not found on server "{1}"' -f $InstallSQLDataDir,$_Session.ComputerName) -ErrorAction Stop
        }
        Write-Verbose ('{0}: VALIDATED - Install SQL Directory "{1}" Found on Server' -f (get-date).tostring(),$_InstallSQLDataDir)

        if (-Not ($_SQLInstanceDir)) {
            Write-Error ('SQL Instance Directory "{0}" not found on server "{1}"' -f $SQLInstanceDir,$_Session.ComputerName) -ErrorAction Stop
        }
        Write-Verbose ('{0}: VALIDATED - SQL Directory "{1}" Found on Server' -f (get-date).tostring(),$_InstallSQLDataDir)
    } else {
        if (-Not ($_ScriptsDir)) {
            $_ScriptsDir = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("New-Item -Path $ScriptsDir -ItemType Container")) -ErrorAction Stop
            Write-Verbose ('{0}: VALIDATED - Created Scripts Directory "{1}"' -f (get-date).tostring(),$ScriptsDir)
        }

        if (-Not ($_SoftwareDir)) {
            $_SoftwareDir = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("New-Item -Path $SoftwareDir -ItemType Container")) -ErrorAction Stop
            Write-Verbose ('{0}: VALIDATED - Created Scripts Directory "{1}"' -f (get-date).tostring(),$SoftwareDir)
        }

        if (-Not ($_SQLBackupDir)) {
            $_SQLBackupDir = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("New-Item -Path $SQLBackupDir -ItemType Container")) -ErrorAction Stop
            Write-Verbose ('{0}: VALIDATED - Created Scripts Directory "{1}"' -f (get-date).tostring(),$SQLBackupDir)
        }
        
        if (-Not ($_SQLUserDBDataDir)) {
            $_SQLUserDBDataDir = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("New-Item -Path $SQLUserDBDataDir -ItemType Container")) -ErrorAction Stop
            Write-Verbose ('{0}: VALIDATED - Created Scripts Directory "{1}"' -f (get-date).tostring(),$SQLUserDBDataDir)
        }

        if (-Not ($_SQLUserDBLogsDir)) {
            $_SQLUserDBLogsDir = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("New-Item -Path $SQLUserDBLogsDir -ItemType Container")) -ErrorAction Stop
            Write-Verbose ('{0}: VALIDATED - Created Scripts Directory "{1}"' -f (get-date).tostring(),$SQLUserDBLogsDir)
        }

        if (-Not ($_SQLTempDBDataDir)) {
            $_SQLTempDBDataDir = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("New-Item -Path $SQLTempDBDataDir -ItemType Container")) -ErrorAction Stop
            Write-Verbose ('{0}: VALIDATED - Created Scripts Directory "{1}"' -f (get-date).tostring(),$SQLTempDBDataDir)
        }

        if (-Not ($_SQLTempDBLogsDir)) {
            $_SQLTempDBLogsDir = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("New-Item -Path $SQLTempDBLogsDir -ItemType Container")) -ErrorAction Stop
            Write-Verbose ('{0}: VALIDATED - Created Scripts Directory "{1}"' -f (get-date).tostring(),$SQLTempDBLogsDir)
        }

        if (-Not ($_InstallSQLDataDir)) {
            $_InstallSQLDataDir = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("New-Item -Path $InstallSQLDataDir -ItemType Container")) -ErrorAction Stop
            Write-Verbose ('{0}: VALIDATED - Created Scripts Directory "{1}"' -f (get-date).tostring(),$InstallSQLDataDir)
        }

        if (-Not ($_SQLInstanceDir)) {
            $_SQLInstanceDir = Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("New-Item -Path $SQLInstanceDir -ItemType Container")) -ErrorAction Stop
            Write-Verbose ('{0}: VALIDATED - Created Scripts Directory "{1}"' -f (get-date).tostring(),$SQLInstanceDir)
        }
    }
    #endregion

    #region Validate ISO Path and key exist
    Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("Mount-DiskImage -ImagePath $SQLISOPath")) -ErrorAction SilentlyContinue
    Invoke-command -Session $_Session -ScriptBlock {Set-Location ((Get-Volume | where-object {$_.FileSystem -eq "CDFS"} | Select-Object -first 1).DriveLetter + ":")} -ErrorAction SilentlyContinue
    
    $SetupFile = Invoke-Command -Session $_session -ScriptBlock {(Get-Item .\Setup.exe).VersionInfo} -ErrorAction SilentlyContinue

    if (-Not ($SetupFile)) {
        Write-Error ('Problem Mounting the ISO File and getting setup version info')
    } else {
        $_SQLServerVersion = $setupfile.FileVersion.Split('.')[0]
    }
    
    if (-Not $SQLInstallKey) {
        Write-Error ('No Install key specified for SQL Server') -ErrorAction Stop -Verbose:$false
    }
    #endregion

    #region Validate Service Account Creds
    $_svcAccountCreds = Test-Credential -UserName $svcAccountCreds.UserName -Password $svcAccountCreds.Password
    if (-Not ($_svcAccountCreds)) {
        Write-Error ('Service Account Credentials Failed to Validate') -ErrorAction Stop
    }
    Write-Verbose ('{0}: VALIDATED - Service Account Credentials Validated')
    #endregion

    #region Validate SysAdmin AD Group
    $_SysAdminGroup = Get-ADGroup -Filter "name -eq '$SysAdminAgroup'" -ErrorAction SilentlyContinue

    if (-Not $_SysAdminGroup) {
        Write-Error ('SysAdmin Group Not Found') -ErrorAction Stop
    }

    if ($_SysAdminGroup.Count -gt 1) {
        Write-Error ('SysAdmin Group Search returned more than one Group') -ErrorAction Stop
    }

    Write-Verbose ('{0}: VALIDATED - Ready to use Sys Admin Group "{1}"' -f (get-date).tostring(),$_SysAdminGroup.Name)
    #endregion

    #region Validate File Share Group
    if ($ConfigureFileShare) {
        $_FileShareGroup = Get-ADGroup -Filter "name -eq '$FileShareGroup'" -ErrorAction SilentlyContinue

        if (-Not $_FileShareGroup) {
            Write-Error ('File Share Group Not Found') -ErrorAction Stop
        }

        if ($_FileShareGroup.Count -gt 1) {
            Write-Error ('File Share Group Search returned more than one Group') -ErrorAction Stop
        }

        Write-Verbose ('{0}: VALIDATED - Ready to use Sys Admin Group "{1}"' -f (get-date).tostring(),$_FileShareGroup.Name)
    }
    #endregion

    #region Configure File Share Access
    if ($ConfigureFileShare) {
        Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("New-SMBShare -Name '$FileShareName' -Path '$InstallSQLDataDir' -ChangeAccess '$FileShareGroup' -FullAccess 'Domain Admins' -FolderEnumerationMode AccessBased")) -ErrorAction Stop
        
        $_folders = ($_SQLBackupDir.FullName,$_SQLUserDBDataDir.FullName,$_SQLUserDBLogsDir.FullName,$_SQLTempDBDataDir.FullName,$_SQLTempDBLogsDir.FullName,$_InstallSQLDataDir.FullName)

        Invoke-Command -Session $_Session -ScriptBlock {
            $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $_Group,'Modify','ContainerInherit,ObjectInherit','None','Allow'
        }

        $_folders += Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("Get-ChildItem $SQLInstanceDir\MSSQL*\mssql* -Directory ")) -Erroraction SilentlyContinue
        
        #Add Rights to Folders
        foreach ($_folder in $_folders) {
            Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create('$ACL = ' + "Get-ACL $_folder")) -ErrorAction SilentlyContinue
            Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create('$Acl.RemoveAccessRule(($Acl.Access | Where-Object {$_.IdentityReference -eq "Creator Owner"}))')) -ErrorAction SilentlyContinue
            Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create('$acl.AddAccessRule($AccessRule)')) -ErrorAction SilentlyContinue
            Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create('$Acl | Set-ACL $folder | Out-Null')) -ErrorAction Stop
        }
    }
    #endregion

    #region Create Install Script
    $Script =  ('##Mount ISO Image from Provided Path' + [environment]::NewLine)
    $Script += ('#Mount-DiskImage -ImagePath "{0}"' -f $SQLISOPath) + [environment]::NewLine
    $Script += ('##Change working Directory to mounted ISO Drive') + [environment]::NewLine
    $Script += ('#Set-Location ((Get-Volume | ?{$_.FileSystem -eq "CDFS"} | select -first 1).DriveLetter + ":")') + [environment]::NewLine
    $Script += ('##Set environment variables for User/Group/Password' + [environment]::NewLine)
    $Script += ('$User = "{0}"' -f $_svcAccountCreds.UserName) + [environment]::NewLine
    $Script += ('$Group = "{0}"' -f $SysAdminGroupName) + [environment]::NewLine
    $Script += ('$PW = '+"'{0}'" -f $_svcAccountCreds.GetNetworkCredential().Password) + [environment]::NewLine
    $Script += ('$SPW = (Convertto-SecureString $PW -AsPlainText -Force)')
    $Script += ('##Execute Install of Software with options' + [environment]::NewLine)
    $Script += ('.\setup.exe /Quiet="True" /IndicateProgress /iAcceptSQLServerLicenseTerms /Action="Install" /UpdateEnabled="False" /TCPEnabled=1 /X86="False" /AGTSVCSTARTUPTYPE="Automatic" ')
    $Script += (' /PID="{0}" ' -f $SQLInstallKey)
    $Script += (' /Features={0} ' -f ($SQLServerFeatures -join ','))
    $Script += (' /INSTANCENAME="{0}" ' -f $SQLInstanceName)
    $Script += (' /INSTANCEID="{0}" ' -f $SQLInstanceName)
    $Script += (' /INSTANCEDIR="{0}" ' -f $SQLInstanceDir)
    $Script += (' /AGTSVCACCOUNT="{0}" ' -f $_svcAccountCreds.UserName)
    $Script += (' /SQLSVCACCOUNT="{0}" ' -f $_svcAccountCreds.Username)
    $Script += (' /SQLSYSADMINACCOUNTS="{0}" ' -f $SysAdminGroupName)
    $Script += (' /INSTALLSQLDATADIR="{0}" ' -f $InstallSQLDataDir)
    $SCript += (' /SQLBACKUPDIR="{0}" '-f $_SQLBackupDir.FullName) 
    $Script += (' /SQLUSERDBDIR="{0}" ' -f $_SQLUserDBDataDir.FullName)
    $Script += (' /SQLUSERDBLOGDIR="{0}" ' -f $_SQLUserDBLogsDir.FullName)
    $Script += (' /SQLTEMPDBDIR="{0}" ' -f $_SQLTempDBDataDir.FullName)
    $Script += (' /SQLTEMPDBLOGDIR="{0}" ' -f $_SQLTempDBLogsDir.FullName)
    if ($_SQLServerVersion -ge '2016') {$Script += (' /SQLTEMPDBFILECOUNT={0}' -f $SQLTempDBFileCount)}
    if ($_SQLServerVersion -ge '2016') {$Script += (' /SQLTEMPDBFILESIZE={0}' -f $SQLTempDBFileSize)}
    if ($_SQLServerVersion -ge '2016') {$Script += (' /SQLTEMPDBFILEGROWTH={0}' -f $SQLTempDBFileGrowth)}
    if ($_SQLServerVersion -ge '2016') {$Script += (' /SQLTEMPDBLOGFILESIZE={0}' -f $SQLTempDBLogFileSize)}
    if ($_SQLServerVersion -ge '2016') {$Script += (' /SQLTEMPDBLOGFILEGROWTH={0}' -f $SQLTempDBLogFileGrowth)}
    if ($_SQLServerVersion -ge '2016') {$Script += (' /SQLSVCINSTANTFILEINIT={0}' -f $SQLTempDBLogFileGrowth)}
    if ($_SQLServerVersion -ge '2017') {
        $Script += (' /SQLSVCPASSWORD=$SPW ' -f $_svcAccountCreds.GetNetworkCredential().password) 
        $Script += (' /AGTSVCPASSWORD=$SPW ' -f $_svcAccountCreds.GetNetworkCredential().password) + [environment]::NewLine    
    } else {
        $Script += (' /SQLSVCPASSWORD="{0}" ' -f $_svcAccountCreds.GetNetworkCredential().password) 
        $Script += (' /AGTSVCPASSWORD="{0}" ' -f $_svcAccountCreds.GetNetworkCredential().password) + [environment]::NewLine
    }
    if ($InstallMgmtStudio) {
        ##Download and install SSMS
        $Script += ('Invoke-WebRequest -Uri https://go.microsoft.com/fwlink/?linkid=2014306 -OutFile {0}\SSMS.exe' -f $_SoftwareDir.FullName)
        $Script += ('{0}\SSMS.exe /quiet' -f $_SoftwareDir.FullName) 
    }

    Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("Set-Content -Value $Script -Path $ScriptsDir\Install.ps1 -Force")) -ErrorAction Stop    
    #endregion

    #region Execute Install Script
    Invoke-Command -Session $_Session -ScriptBlock ([scriptblock]::Create("Get-Content '$($_ScriptsDir.FullName)\Install.ps1' | Invoke-Expression"))
    #endregion
}

