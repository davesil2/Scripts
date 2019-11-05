<#
##########################################################
 Purpose:
   The intention for this Script is to be used as a global
   load for all engineers 
###########################################################
 Usage:

   Open your Local Profile with the following command:
      notepad $profile.allusersallhosts

   Place the following into your local profile:

    $fileContents = [string]::join([environment]::newline, (get-content -path '\\domain.com\netlogon\globalfunctions.ps1'))
    invoke-expression $fileContents 

	Or

	Invoke-Expression ((gc '\\domain.com\netlogon\GlobalFunctions.ps1') -join [environment]::Newline)

###########################################################
#>

function Test-Ping {
    [CmdletBinding()]
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
    [CmdletBinding()]
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

Function Get-ActiveTCPListeners{
    
    return [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTCPListeners() | Select-Object Address,Port

    <#
    .SYNOPSIS
    
    List the Active TCP Listeners like netstat
    
    .DESCRIPTION
    
    This allows you to list all Port/Addresses on the machine that are listening.  Similar to using netstat but returned in an object array list that you can use
    
    .EXAMPLE
    
    Get-ActiveTCPListeners
    
    #>
}

Function Get-ActiveTCPConnections{

    return [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTCPConnections() | Select-Object LocalEndPoint,RemoteEndPoint,State
    
    <#
    .SYNOPSIS
    
    List the Active TCP Connections like netstat
    
    .DESCRIPTION
    
    This allows you to list all Port/Addresses on the machine that are Connected.  Similar to using netstat but returned in an object array list that you can use
    
    .EXAMPLE

    Get-ActiveTCPConnections

    #>
}

Function Get-ActiveUDPListeners {

    return [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveUDPListeners() | Select-Object Address,Port

    <#
    .SYNOPSIS
    
    List the Active UDP Listeners like netstat
    
    .DESCRIPTION
    
    This allows you to list all Port/Addresses on the machine that are Listening.  Similar to using netstat but returned in an object array list that you can use
    
    .EXAMPLE
    
    Get-ActiveUDPListeners
    
    #>
}

Function Start-TCPListener {
    [CmdletBinding()]
    Param
	(
        # Port to Listen on
        [Parameter(Mandatory=$true)]
        [ValidateRange(1,65535)]
        [int]
        $Port,

        # IP Address to listen on
        [Parameter(Mandatory=$False)]
        [String]
        $IPAddress = '0.0.0.0'
	)
    
    if (-Not ([system.net.ipaddress]::TryParse($IPAddress, [ref]$_IPAddress))) {
        Write-Error ('IP Address appears to be invalid')
    }

    $_Listener = New-Object Net.Sockets.TcpListener $_IPAddress,$Port -ErrorAction SilentlyContinue

    if (-Not $_Listener) {
        Write-Error ('Unable to create Listener on Port "{0}" with IP "{1}"' -f $Port, $IPAddress.ipaddresstostring)
    }
    Write-Verbose ('{0}: Listener Created' -f (get-date).tostring())

    $_Listener.Start()
    Read-Host -Prompt 'Press Enter to Stop Listner...'
    $_Listener.Stop()

    Write-Verbose ('{0}: Listener Stopped' -f (get-date).tostring())

    <#
    .SYNOPSIS

    Start-TCPListener allows you to start a TCP listener on a specified port
    
    .DESCRIPTION

    Use this function in combination with the Test-Port function to verify if firewall ports are open between endpoints
    
    .EXAMPLE

    Start-TCPListener -Port 4022
    
    #>
}

Function Get-ActivePSSessions {
    [CmdletBinding()]
    Param
	(
        # Server to Get Active Power Shell Sessions
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Server = $env:computername,

        # Credentials to use to connect to server
        [Parameter(Mandatory=$false)]
        [PSCredential]
        $Credential
	)
    
    if ($Credential) {
        #Test Credentials
        if (-Not (Test-Credential -Username $Credential.UserName -Password $Credential.Password)) {
            Write-Error ('Credentials are invalid') -ErrorAction Stop
        }

        if (-Not (Test-WSMan -ComputerName $Server -Credential $Credential -Authentication Kerberos -ErrorAction SilentlyContinue)) {
            Write-Error ('unable to connect to wsman') -ErrorAction Stop
        }

        $_Sessions = Get-WSManInstance -ConnectionURI ("http://{0}:5985/wsman" -f $server) -ResourceURI Shell -Enumerate -Credential $Credential -ErrorAction SilentlyContinue    
    } Else {
        if (-Not (Test-WSMan -ComputerName $Server -Credential $Credential -Authentication Kerberos -ErrorAction SilentlyContinue)) {
            Write-Error ('unable to connect to wsman') -ErrorAction Stop
        }

        $_Sessions = Get-WSManInstance -ConnectionURI ("http://{0}:5985/wsman" -f $server) -ResourceURI Shell -Enumerate -ErrorAction SilentlyContinue
    }

    if (-Not $_Sessions) {
        Write-Error ('No Sessions Returned') -ErrorAction Stop
    }

    Return $_Sessions | Select-Object Name,Owner,ClientIP,ProcessID,State,MemoryUsed,ShellInactivity,ShellRunTime

    <#
    .SYNOPSIS

    Get-ActivePSSessions provides you with a list of active sessions on a specified host (default is current host)
    
    .DESCRIPTION
    
    Funciton provides a list of active sessions on the current or remote server
    
    .EXAMPLE
    
    Get-ActivePSSessions

    .EXAMPLE
    
    Get-ActivePSSessions MyComputer.domain.local

    .EXAMPLE
    
    Get-ActivePSSessions -Server MyComputer -Credential (get-credential)

    .EXAMPLE

    $Credential = Get-Credential DOMAIN\<samaccountname>
    Get-ActivePSSessions -Server MyComputer -Credential $Credential
    
    #>
}

Function Get-Uptime {
    [CmdletBinding()]
    Param(
        # Server to connect to and retrieve uptime
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('ServerName','Server')]
        [String]
        $ComputerName="localhost",

        [Parameter(Mandatory=$false)]
        [switch]
        $TimeSpan
    )

    # Get Uptime Value from Performance Counter
    $_UpTime = New-Object System.Diagnostics.PerformanceCounter "System", "System Up Time", "", $ComputerName -ErrorAction SilentlyContinue
    
    if (-Not $_Uptime) {
        Write-Error ('Unable to retrieve Performance counter from server "{0}"' -f $ComputerName) -ErrorAction Stop
    }

    # Dump initial value (generally is null)
    [void]($_Uptime.NextValue())
    
    if ($TimeSpan) {
        Return [TimeSpan]::FromSeconds($_UpTime.NextValue())
    } else {
        Return [TimeSpan]::FromSeconds($_UpTime.NextValue()) | Select-Object Days,Hours,Minutes,Seconds,milliseconds
    }


    <#
    .SYNOPSIS

    Get-Uptime provides the uptime of the server you are currently on be default
    
    .DESCRIPTION

    this function polls the Performance Counter System Up Time and get the current value returning as a timespan output
    
    .EXAMPLE

    Get-Uptime

    .EXAMPLE

    Get-uptime MyComputer.domain.local

    .EXAMPLE

    Get-Uptime -ComputerName MyComputer

    .EXAMPLE

    Get-Uptime -TimeSpan

    #>
}

Function Get-LocalGroup {
	[CmdletBinding()]
	PARAM(
		[Parameter(Position=1,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[alias("CN","__SERVER","Computer","IPAddress")]
		[STRING[]]$ComputerName = $ENV:COMPUTERNAME,
		
		[Parameter(Position=0)]
		[alias("Grp")]
		[STRING]$GroupName = "*",

        [Parameter(Mandatory=$false)]
        [alias()]
        [PSCredential]$Credential
	)

	Process {
		Foreach($ComputerItem in $ComputerName){
			Try {
                if ($Credential) {
                    $Computer = New-Object System.DirectoryServices.DirectoryEntry "WinNT://$ComputerItem,Computer",$Credential.UserName,$Credential.GetNetworkCredential().Password
                } else {
				    $Computer = [adsi]"WinNT://$ComputerItem,Computer"
                }				
                if($Computer.Path) {
					$Computer.Children| Where-Object{$_.SchemaClassName -eq "group" -and $_.name -like $GroupName} |foreach{
						New-Object PSObject -Property @{
							ComputerName = $ComputerItem
							GroupName = $_.Properties.name.Value
							Description = $_.Properties.Description.Value
						} | Select-Object ComputerName,GroupName,Description
					}
				} Else {
					Write-Error "Computer : $ComputerItem : The network path was not found."
				}
			} Catch {
				Write-Error "Computer : $ComputerItem : $_"
			}
		}
    }
    
    <#
    .SYNOPSIS
            Get local group account information from a local or remote system.
        
    .DESCRIPTION
            Enables an administrator to get local group account information from a local or remote system.
        
    .PARAMETER ComputerName
            This parameter is required.
            Specifies the target computers. Type the computer names or IP addresses(Comma separeted). Wildcard characters are not permitted.This parameter does not rely on Windows PowerShell remoting. You can use the ComputerName parameter even if your computer is not configured to run remote commands.
    
    .PARAMETER GroupName
            This parameter is required.
            Specifies the target Groups. Type the Group names(Comma separeted), Wildcard characters are permitted.
            
    .EXAMPLE       

        Get-LocalGroup
        
        Description
        -----------
        Get all local groups from local computer
        
    .EXAMPLE       

        Get-LocalGroup MyGroup
        
        Description
        -----------
        Get local group MyGroup, from local computer
        
    .EXAMPLE       

        Get-LocalGroup -GroupName My*
        
        Description
        -----------
        Get ,from local computer, all local groups which their names stats with 'My' 	
        
    .EXAMPLE       

        Get-LocalGroup -GroupName YourGroup -ComputerName Server1
        
        Description
        -----------
        Get local group YourGroup, from remote computer Server1	
        
    .EXAMPLE       

        Get-LocalGroup -GroupName HouseofMontague,HouseofCapulet -ComputerName Romeo,Juliet 
        
        Description
        -----------
        Get local groups HouseofMontague & HouseofCapulet, from remote computers Romeo and Juliet	
        
    .EXAMPLE       

        Get-Contact d:\ServerList.txt | Get-LocalGroup 
        
        Description
        -----------
        Get a list computers from ServerList.txt file and get their local groups 
        
	#>
}

Function Get-LocalGroupMembers {
	[CmdletBinding()]
	PARAM(
		[Parameter(Position=1,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[alias("CN","__SERVER","Computer","IPAddress")]
		[STRING[]]$ComputerName = $ENV:COMPUTERNAME,
		
		[Parameter(Position=0,Mandatory = $true,ValueFromPipelineByPropertyName=$true)]
		[alias("Group","Grp")]
		[STRING[]]$GroupName,
		
		[SWITCH]$NestedGroup,

        [Parameter(Mandatory=$false)]
        [alias()]
        [PSCredential]$Credential
		
	)
	
	Process{
		Foreach($ComputerItem in $ComputerName) {
			Foreach($GroupItem in $GroupName) {
				Try {
			        Write-Verbose "Getting group $GroupItem on computer $ComputerItem"
                    if ($Crednetial) {
                        $Group = New-Object System.DirectoryServices.DirectoryEntry "WinNT://$ComputerItem/$GroupItem,group",$Credential.UserName,$Credential.GetNetworkCredential().Password
                    } else {
				        $Group = [ADSI]"WinNT://$ComputerItem/$GroupItem,group"
                    }						

					Write-Verbose "Getting $GroupItem group members on computer $ComputerItem"
					$Group.Members()| ForEach-Object {
						if(($_.GetType().InvokeMember("Adspath", 'GetProperty', $null, $_, $null)) -match $ComputerItem){
								$UserType = "Local"
						} Else {
								$UserType = "Domain"
                        }
                        
						Try {
							New-Object PSObject -Property @{
								ComputerName = $ComputerItem
								GroupName = $GroupItem
								Identity = $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
								UserType = $UserType
								ObjectType = $_.GetType().InvokeMember("Class", 'GetProperty', $null, $_, $null) 
							} | Select-Object ComputerName,GroupName,Identity,UserType,ObjectType,@{Name='Date';Expression={Get-Date}}
						} Catch {
							Write-Error "Computer : $ComputerItem : $_"
						}
					}
				} Catch{
					Write-Error "Computer : $ComputerItem : $_"
				}					
			}
		}
    }
    
    <#
    .SYNOPSIS
            Get local group members from a local or remote system.
        
    .DESCRIPTION
            Enables an administrator to get local group members from a local or remote system.
        
    .PARAMETER ComputerName
            This parameter is required.
            Specifies the target computers. Type the computer names or IP addresses(Comma separeted). Wildcard characters are not permitted.This parameter does not rely on Windows PowerShell remoting. You can use the ComputerName parameter even if your computer is not configured to run remote commands.
    
    .PARAMETER GroupName
            This parameter is required.
            Specifies the target Groups. Type the Group names(Comma separeted), Wildcard characters are not permitted.

    .PARAMETER NestedGroup
            Gets the members in the specified group and in its nested groups.

                        
    .EXAMPLE       

        Get-LocalGroupMembers Administrators
        
        Description
        -----------
        Get Administrators from local computer
        
    .EXAMPLE       

        Get-LocalGroupMembers -GroupName Administrators,Users
        
        Description
        -----------
        Get the members of Administrators & Users local groups, form local computer 	
        
    .EXAMPLE       

        "Server1" | Get-LocalGroupMembers -GroupName YourGroup
        
        Description
        -----------
        Get the members of local group YourGroup, from remote computer Server1 	
        
    .EXAMPLE       

        Get-LocalGroupMembers -GroupName HouseofMontague,HouseofCapulet -ComputerName Verona 
        
        Description
        -----------
        Get the members of local groups HouseofMontague & HouseofCapulet, from remote computer Verona	
        
    .EXAMPLE       

        Get-Contact d:\ServerList.txt | Get-LocalGroupMembers -GroupName Administrators | Format-Table
        
        Description
        -----------
        Get a list of computers from ServerList.txt file and get their local Administrators, display the results in table format 
	#>
}

Function Get-GroupMemberShip {
    Param(
        [Parameter(Mandatory=$true)]
        [Alias()]
        [String]
        $GroupName,

        [Parameter(Mandatory=$false)]
        [Alias()]
        [String]
        $ParentGroup
    )

    $ds = New-Object System.DirectoryServices.DirectorySearcher
    $ds.Filter = ("(samaccountname={0})" -f $GroupName)

    $de = $ds.FindOne().GetDirectoryEntry()

    if ($de) {
        $Array = @()
        $Members = $de.Member

        foreach ($member in $members) {
            if ($member) {
                $member = [adsi]('LDAP://' + $member)

                if ($member.objectClass.contains('person')) {
                    if ($ParentGroup -and $ParentGroup.Substring(0,1) -ne '/')
                    {
                        $ParentGroup = '/' + $ParentGroup
                    }
                    
                    $array += New-Object PSObject -Property @{Name=$member.displayName.toString();Group=$GroupName;GroupPath=($ParentGroup + '/' + $GroupName);sAMAccountName=$Member.samaccountname.toString();AccountDisabled=$member.invokeGet('AccountDisabled').ToString()}    
                }

                if ($member.objectClass.contains('group')) {
                    $array += Get-GroupMemberShip -GroupName $member.samaccountname -ParentGroup $GroupName
                }
            } Else {
                Write-Warning ("Member Value Returned is null!")
            }
        }

        Return $array
    } else {
        Write-Warning ("Group {0} was not found in Active Directory!" -f $GroupName)
    }
}

Function Add-LocalGroupMembers {
    PARAM(
		[Parameter(Position=1,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[alias("CN","__SERVER","Computer","IPAddress")]
        [STRING[]]
        $ComputerName = $ENV:COMPUTERNAME,
		
		[Parameter(Position=0,Mandatory=$True)]
		[alias("Grp","Group","GroupName")]
        [STRING]
        $LocalGroupName,

        [Parameter(Mandatory=$True)]
        [Alias("User")]
        [String]
        $AccountObject,

        [Parameter(Mandatory=$false)]
        [Alias("Local")]
        [Switch]
        $AccountObjectIsLocal,

        [Parameter(Mandatory=$false)]
        [Alias("IsUser")]
        [Switch]
        $AccountObjectIsUser,

        [Parameter(Mandatory=$false)]
        [alias("Cred")]
        [PSCredential]
        $Credential
	)
    
    ForEach ($Computer in $ComputerName) {
        If (!$Credential) {
            $Group = New-Object System.DirectoryServices.DirectoryEntry "WinNT://$Computer/$LocalGroupName,group"
        } Else {
            $Group = New-Object System.DirectoryServices.DirectoryEntry "WinNT://$Computer/$LocalGroupName,group",$Credential.UserName,$Credential.GetNetworkCredential().Password
        }

        If ($AccountObjectIsUser) {
            $AccountObjectType = 'User' 
        } Else {
            $AccountObjectType = 'Group'
        }

        if ($AccountObjectIsLocal) {
            $Account = [adsi]"WinNT://$Computer/$AccountObject,$AccountObjectType"
        } Else {
            $Account = [adsi]"WinNT://$($ENV:USERDOMAIN)/$AccountObject,$AccountObjectType"
        }

        if ($Account) {
            try {
                $Group.Add($Account.ADSPath)
                Write-Host ("Account {0} was added to Group {1} successfully!" -f $AccountObject,$LocalGroupName)
            } catch {
                Write-Warning ("An Error occured adding Account {0} to Group {1}!" -f $AccountObject,$LocalGroupName)
            }
        } else {
            Write-Warning ("Account {0} was not Added to Group {1} because the Account could not be found!" -f $AccountObject,$LocalGroupName)
        }
    }
}

Function Add-MicrosoftUpdates {
    try {
        $ServiceManager = New-Object -ComObject Microsoft.Update.ServiceManager
        $ServiceManager.ClientApplicationID = "Microsoft Update"

        [void]($ServiceManager.AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,""))
    
        Write-Host ("Successfully added Microsoft Update Service!")
    } Catch {
        Write-Warning ("Failed to add Microsoft Update Service!")
    }
}

Function Get-SQLIndexFragmentation {
    Param(
        # SQL Servers to Get Fragmentation From
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $SQLServers = 'localhost',

        # Indexes to get Fragmentation of
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Indexes = '*',

        # Tables to get Indexes From
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Tables = '*',
        
        # Databases to get Tables From
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Databases = '*'
    )

    Try
    {
        ##Import SQL Libraries
        [Void]([System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO'))

        $Array = @()

        ForEach ($SQLServer in $SQLServers) {
            ##TODO: Test Server

            ##Connect to SQL Server Instance
            $SMO = New-Object Microsoft.SQLServer.Management.SMO.Server $SQLServer

            ##Get Server Databases
            If (($Databases | Out-String).contains('*') -and $Databases.Count -eq 1) {
                $DBs = $SMO.Databases
            } Else {
                $DBs = $Databases | ForEach-Object {try {$SMO.Databases[$_]} Catch {$null}} | Where-Object {$_ -ne $null}
            }

            ForEach ($DB in $DBs) {
                If (($Tables | Out-String).Contains('*') -and $Tables.Count -eq 1) {
                    $Tbls = $DB.Tables
                } Else {
                    $Tbls = $Tables | ForEach-Object {Try {$DB.Tables[$_]} Catch {$null}} | Where-Object {$_ -ne $null}
                }

                ForEach ($Table in $Tbls) {
                    If (($Indexes | Out-String).Contains('*') -and $Indexes.Count -eq 1) {
                        $Indxs = $Table.Indexes
                    } Else {
                        $Indxs = $Indexes | ForEach-Object {Try {$Tables.Indexes[$_]} Catch {$Null}} | Where-Object {$_ -ne $null}
                    }

                    ForEach ($Index in $Indxs) {
                        $Fragmentation = $Index.EnumFragmentation() | Select-Object *

                        $obj = [PSCustomObject]@{
                            SQLServer=$SQLServer;
                            Database=$DB.Name;
                            Table=$Table.Name;
                            TableRowCount=$Table.RowCount; 
                            Index=$Index.Name; 
                            Fragmentation=$Fragmentation.AverageFragmentation
                        }

                        $obj

                        $Array += $obj
                    }
                }
            }
        }
    } Catch {
        Write-Warning ("Process Ended - An Error occured: {0}" -f $Error[0].Exception)   
    }
}

Function Test-Resolve {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [Alias('DNSName','Server')]
        [String]
        $ComputerName,

        [Parameter(Mandatory=$False)]
        [Switch]
        $Quiet
    )

    $_result = try {[net.dns]::Resolve($ComputerName)} catch {}

    if (-Not $_result) {
        if ($Quiet) {
            return $false
        } else {
            Write-Error ('{0} was not resolvable' -f $ComputerName) -ErrorAction Stop
        }
    }

    if ($Quiet) {
        return $true
    }

    return $_result
}

Function Play-Phrase {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Phrase
    )

    $_Speaker = New-Object -ComObject SAPI.SpVoice -ErrorAction Stop
    [Void]($_Speaker.Speak($Phrase))
}

Function Get-WWN {
    [CmdletBinding()]
    Param(
        # Computer to get WWN FC infomation from
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName=($env:ComputerName),

        # Credential to connect to computer
        [Parameter(Mandatory=$false)]
        [Alias('Cred')]
        [PSCredential]
        $Credential
    )

    $_Class = 'MSFC_FibrePortNPIVAttributes'
    $_NameSpace = 'root/WMI'

    if ($Credential) {
        $_result = Get-WmiObject -Class $_Class -Namespace $_NameSpace -ComputerName $ComputerName -Credential $Credential -ErrorAction SilentlyContinue
    } else {
        $_result = Get-WmiObject -Class $_Class -Namespace $_NameSpace -ComputerName $ComputerName -ErrorAction SilentlyContinue
    }

    if (-Not $_result) {
        Write-Error ('No Result returned from system for class "{0}"' -f $_Class) -ErrorAction Stop
    }

    $_Array = @()

    ForEach ($WWN in $result) {  
        $_obj = [PSCustomObject]@{
            ComputerName=$ComputerName;
            WWPN=($wwn.wwpn | ForEach-Object {("{0:x}" -f $_).PadLeft(2,'0')}) -join ':'; 
            WWNN=($wwn.wwnn | ForEach-Object {("{0:x}" -f $_).PadLeft(2,'0')}) -join ':';
        }
        
        $_Array += $_obj
    }

    return $_Array
}

function New-SymbolicLink {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        $OriginalPath,

        [Parameter(Mandatory=$true)]
        $MirroredPath,

        [ValidateSet('File', 'Directory')]
        $Type='Directory'

    )
    
    if(!([bool]((whoami /groups) -match "S-1-16-12288") )) {
        Write-Warning 'Must be an admin'
        break
    }

    $signature = '
        [DllImport("kernel32.dll")]
        public static extern bool CreateSymbolicLink(string lpSymlinkFileName, string lpTargetFileName, int dwFlags);
        '
    Add-Type -MemberDefinition $signature -Name Creator -Namespace SymbolicLink 

    $Flags = [Int]($Type -eq 'Directory')
    [SymbolicLink.Creator]::CreateSymbolicLink($MirroredPath, $OriginalPath, $Flags)
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

function Set-PageFile {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        # The page file's fully qualified file name (such as C:\pagefile.sys)
        [Parameter(Mandatory=$true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        # The page file's initial size [MB]
        [Parameter(Mandatory=$true,Position=1)]
        [ValidateNotNullOrEmpty()]
        [Int]

        # The page file's maximum size [MB]
        $InitialSize,
        [Parameter(Mandatory=$true,Position=2)]
        [ValidateNotNullOrEmpty()]
        [Int]
        $MaximumSize
    )
     
    Set-PSDebug -Strict
 
    $ComputerSystem = $null
    $CurrentPageFile = $null
    $Modified = $false
 
    # Disables automatically managed page file setting first
    $ComputerSystem = Get-WmiObject -Class Win32_ComputerSystem -EnableAllPrivileges

    if ($ComputerSystem.AutomaticManagedPagefile) {
        $ComputerSystem.AutomaticManagedPagefile = $false
        if ($PSCmdlet.ShouldProcess("$($ComputerSystem.Path.Server)", "Disable automatic managed page file")) {
            $ComputerSystem.Put()
        }
    }
 
    $CurrentPageFile = Get-WmiObject -Class Win32_PageFileSetting
    if ($CurrentPageFile.Name -eq $Path) {
        # Keeps the existing page file
        if ($CurrentPageFile.InitialSize -ne $InitialSize) {
            $CurrentPageFile.InitialSize = $InitialSize
            $Modified = $true
        }

        if ($CurrentPageFile.MaximumSize -ne $MaximumSize) {
            $CurrentPageFile.MaximumSize = $MaximumSize
            $Modified = $true
        }

        if ($Modified) {
            if ($PSCmdlet.ShouldProcess("Page file $Path", "Set initial size to $InitialSize and maximum size to $MaximumSize")) {
                $CurrentPageFile.Put()
            }
        }
    } else {
        # Creates a new page file
        if ($PSCmdlet.ShouldProcess("Page file $($CurrentPageFile.Name)", "Delete old page file")) {
            $CurrentPageFile.Delete()
        }

        if ($PSCmdlet.ShouldProcess("Page file $Path", "Set initial size to $InitialSize and maximum size to $MaximumSize")) {
            Set-WmiInstance -Class Win32_PageFileSetting -Arguments @{Name=$Path; InitialSize = $InitialSize; MaximumSize = $MaximumSize}
        }
    }

    <#
    .SYNOPSIS
    
    Sets Page File to custom size
 
    .DESCRIPTION
    
    Applies the given values for initial and maximum page file size.
 
    .EXAMPLE

    C:\PS> Set-PageFile "C:\pagefile.sys" 4096 6144

    #>
}

Function Create-MyPSDrive {
	Param(
		[String]$Root = ('\\il-svr-fs01\users\{0}' -f (($env:USERNAME).Trim('a_'))),
		[String]$Drive = (($env:USERNAME).Trim('a_'))
	)

	If (Test-Path -Path $Root) {
		New-PSDrive -Name $Drive -Root $Root -PSProvider FileSystem -Scope Global
	}
}

Function Add-TokenPrivilege {
 
    $code = @"
using System;
using System.Runtime.InteropServices;


namespace CosmosKey.Utils
{
 public class TokenManipulator
 {


  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
  ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);


  [DllImport("kernel32.dll", ExactSpelling = true)]
  internal static extern IntPtr GetCurrentProcess();


  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr
  phtok);


  [DllImport("advapi32.dll", SetLastError = true)]
  internal static extern bool LookupPrivilegeValue(string host, string name,
  ref long pluid);


  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal struct TokPriv1Luid
  {
   public int Count;
   public long Luid;
   public int Attr;
  }


  internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;


  public const string SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";
  public const string SE_AUDIT_NAME = "SeAuditPrivilege";
  public const string SE_BACKUP_NAME = "SeBackupPrivilege";
  public const string SE_CHANGE_NOTIFY_NAME = "SeChangeNotifyPrivilege";
  public const string SE_CREATE_GLOBAL_NAME = "SeCreateGlobalPrivilege";
  public const string SE_CREATE_PAGEFILE_NAME = "SeCreatePagefilePrivilege";
  public const string SE_CREATE_PERMANENT_NAME = "SeCreatePermanentPrivilege";
  public const string SE_CREATE_SYMBOLIC_LINK_NAME = "SeCreateSymbolicLinkPrivilege";
  public const string SE_CREATE_TOKEN_NAME = "SeCreateTokenPrivilege";
  public const string SE_DEBUG_NAME = "SeDebugPrivilege";
  public const string SE_ENABLE_DELEGATION_NAME = "SeEnableDelegationPrivilege";
  public const string SE_IMPERSONATE_NAME = "SeImpersonatePrivilege";
  public const string SE_INC_BASE_PRIORITY_NAME = "SeIncreaseBasePriorityPrivilege";
  public const string SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";
  public const string SE_INC_WORKING_SET_NAME = "SeIncreaseWorkingSetPrivilege";
  public const string SE_LOAD_DRIVER_NAME = "SeLoadDriverPrivilege";
  public const string SE_LOCK_MEMORY_NAME = "SeLockMemoryPrivilege";
  public const string SE_MACHINE_ACCOUNT_NAME = "SeMachineAccountPrivilege";
  public const string SE_MANAGE_VOLUME_NAME = "SeManageVolumePrivilege";
  public const string SE_PROF_SINGLE_PROCESS_NAME = "SeProfileSingleProcessPrivilege";
  public const string SE_RELABEL_NAME = "SeRelabelPrivilege";
  public const string SE_REMOTE_SHUTDOWN_NAME = "SeRemoteShutdownPrivilege";
  public const string SE_RESTORE_NAME = "SeRestorePrivilege";
  public const string SE_SECURITY_NAME = "SeSecurityPrivilege";
  public const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";
  public const string SE_SYNC_AGENT_NAME = "SeSyncAgentPrivilege";
  public const string SE_SYSTEM_ENVIRONMENT_NAME = "SeSystemEnvironmentPrivilege";
  public const string SE_SYSTEM_PROFILE_NAME = "SeSystemProfilePrivilege";
  public const string SE_SYSTEMTIME_NAME = "SeSystemtimePrivilege";
  public const string SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege";
  public const string SE_TCB_NAME = "SeTcbPrivilege";
  public const string SE_TIME_ZONE_NAME = "SeTimeZonePrivilege";
  public const string SE_TRUSTED_CREDMAN_ACCESS_NAME = "SeTrustedCredManAccessPrivilege";
  public const string SE_UNDOCK_NAME = "SeUndockPrivilege";
  public const string SE_UNSOLICITED_INPUT_NAME = "SeUnsolicitedInputPrivilege";        


  public static bool AddPrivilege(string privilege)
  {
   try
   {
    bool retVal;
    TokPriv1Luid tp;
    IntPtr hproc = GetCurrentProcess();
    IntPtr htok = IntPtr.Zero;
    retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
    tp.Count = 1;
    tp.Luid = 0;
    tp.Attr = SE_PRIVILEGE_ENABLED;
    retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
    retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    return retVal;
   }
   catch (Exception ex)
   {
    throw ex;
   }


  }
  public static bool RemovePrivilege(string privilege)
  {
   try
   {
    bool retVal;
    TokPriv1Luid tp;
    IntPtr hproc = GetCurrentProcess();
    IntPtr htok = IntPtr.Zero;
    retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
    tp.Count = 1;
    tp.Luid = 0;
    tp.Attr = SE_PRIVILEGE_DISABLED;
    retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
    retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    return retVal;
   }
   catch (Exception ex)
   {
    throw ex;
   }


  }
 }
}
"@

    Add-Type $code

    [void][CosmosKey.Utils.TokenManipulator]::AddPrivilege([CosmosKey.Utils.TokenManipulator]::SE_RESTORE_NAME)
}

Function Get-PublicIP {
    return (new-object psobject -Property @{PublicAddress=((Invoke-WebRequest -uri "http://ifconfig.me/ip").content.Trim())})
}

function Restart-RemoteService{
    Param
    (
        [Parameter(Mandatory = $true)][String]$Server,
        [Parameter(Mandatory = $true)][String]$ServiceName,
	    #[Parameter(Mandatory = $true)][Boolean]$Force,
        [System.Management.Automation.PSCredential]$Credential
    )

    try {
        if ($Credential) {
            $svc = Get-WMIObject -Class Win32_Service -ComputerName $Server -Filter ("Name='$ServiceName'") -Credential $Credential
        } Else {
            $svc = Get-WMIObject -Class Win32_Service -ComputerName $Server -Filter ("Name='$ServiceName'")
        }

        $svc.StopService() | Out-Null
        Write-Host ('Service {0} Stopped on Server {1}' -f $ServiceName,$Server)
        $svc.StartService() | Out-Null
        Write-Host ('Service {0} Started on Server {1}' -f $ServiceName,$Server)
    } catch {
        Write-Error ('Error Restarting Service')
    }
}

function New-SSLCertificate {
    param(
        #Certificate name (usually the short name)    
        [parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('ServerName,ComputerName')]
        [string]
        $Name,

        #Domain Name for request (combined with Name to get FQDN)
        [parameter(Mandatory = $false)]
        [string]
        $DomainName = ($env:USERDNSDOMAIN),

        #Common Name (set to FQDN by default)
        [parameter(Mandatory = $false)]
        [string]
        $CommonName = ('{0}.{1}' -f $Name, $DomainName),
    
        #IPAddress for FQDN
        [parameter(Mandatory = $false)]
        [string]
        $IPAddress = ([net.dns]::GetHostEntry($CommonName).AddressList.IPAddresstoString),
    
        #Subject Alternative Name to apply
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [string[]]
        $SubjectAlternativeNames = $null,
    
        #Server that is your Certificate Authority
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [string]
        $CAServer = ((certutil -ADCA | select-string dnshostname | Select-Object -first 1).tostring().split('=')[1]).Trim(),
    
        #Certificate Authority Name
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [string]
        $CAName = ((certutil -ADCA | select-string displayName | Select-Object -first 1).tostring().split('=')[1]).Trim(),
    
        #Name of Template in Certificate Authority
        [parameter(Mandatory = $True, ValueFromPipelineByPropertyName)]
        [string]
        $TemplateName,
    
        #Password assigned to PFX file
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [string]
        $PFXPassword = 'testpassword',
    
        #Path to Certificate Chain (will download from CA if not specified)
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [string]
        $ChainPath,
    
        #Country to be used by Certificate Request (uses public IP to determine country)
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [string]
        $Country = (Invoke-RestMethod -Method Get -Uri "https://ipinfo.io/$((Invoke-WebRequest -uri 'http://ifconfig.me/ip' -verbose:$false).Content)" -Verbose:$false).country,
    
        #State to be used by Certificiate Request (uses public IP to determine State)
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [string]
        $State = (Invoke-RestMethod -Method Get -Uri "https://ipinfo.io/$((Invoke-WebRequest -uri 'http://ifconfig.me/ip' -verbose:$false).Content)" -Verbose:$false).region,
    
        #Locality or City for CSR (uses public IP to determine city/locality)
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [string]
        $Locality = (Invoke-RestMethod -Method Get -Uri "https://ipinfo.io/$((Invoke-WebRequest -uri 'http://ifconfig.me/ip' -verbose:$false).Content)" -Verbose:$false).city,
    
        #Organization for CSR
        [parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [ValidateNotNullorEmpty()]
        [string]
        $Organization,
    
        #Organization Unit for CSR
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [string]
        $OrganizationalUnit = 'n/a',
    
        #Path to OpenSSL executable (must be available)
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [string]
        $OpenSSLPath = (Get-command openssl*).Source,
    
        #Path to create folder and files for Certificate Request
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [string]
        $OutputPath = "$((get-location).path)\$Name.$DomainName",
    
        #Overwrite existing Certificate (renames folder to backup-<date>)
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [boolean]
        $OverwriteExisting = $false,
    
        #Regenerate Certificate (unused)
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [boolean]
        $Regenerate = $false,
    
        #Adds default SAN Names to Request (DNS: short name, DNS: FQDN, DNS: <ipaddresss>, IP: <ipaddress>)
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [boolean]
        $UseDefaultSAN = $true,
    
        #self sign the certificate
        [parameter(Mandatory = $false, ValueFromPipelineByPropertyName)]
        [boolean]
        $SelfSignCertificate = $false
    )

    $ErrorActionPreference = 'Stop'

    $Name = $Name.ToUpper()
    $DomainName = $DomainName.ToUpper()
    $FQDN = ('{0}.{1}' -f $Name, $DomainName)

    #region Test Path for Openssl
    If (-Not (Test-Path -Path $OpenSSLPath)) {
        Write-Error ('Path to OpenSSL not Found') -ErrorAction Stop
    }
    Write-Verbose ('{0}: VALIDATED - OpenSSL executable found at "{1}"' -f (get-date).tostring(), $OpenSSLPath)
    #endregion

    #region Validate Path is available)
    if ((Test-Path -Path $OutputPath) -and -Not $OverwriteExisting) {
        Write-Error ('Output path already exists and overwrite is not selected!') -ErrorAction Stop
    }
    Write-Verbose ('{0}: VALIDATED - Output path "{1}" not available to created' -f (get-date).tostring(), $OutputPath)
    #endregion

    #region Backup existing if overwriting
    if ($OverwriteExisting -and (Test-Path $OutputPath)) {
        try {
            Move-Item -Path $OutputPath -Destination ('{0}-Backup_{1}' -f $OutputPath, (get-date).ToString('yyyy.MM.dd_hh.mm.ss'))
        }
        catch {
            Write-Error ('Error Moving Folder!') -ErrorAction Stop
        }
    }
    Write-Verbose ('{0}: Renamed Existing Folder from "{1}" to "{1}-Backup_{2}"' -f (get-date).tostring(), $outputpath, (get-date).tostring('yyyy.MM.dd_hh.mm.ss'))
    #endregion

    #region Create Output Folder
    if (-Not (Test-Path -Path $OutputPath)) {
        try {
            New-Item $OutputPath -ItemType container | Out-Null
        }
        catch {
            Write-Error ('Unable to create Output Path location!') -ErrorAction Stop
        }

        Write-Verbose ('{0}: Created Output Folder "{1}"' -f (get-date).tostring(), $OutputPath)
    }
    #endregion

    #region Get Certificate Chain if not provided
    if (-Not $ChainPath) {
        try {
            Invoke-Expression ("certutil -'ca.chain' -config '{0}\{1}' {2}\chain.der" -f $CAServer, $CAName, $OutputPath) | Out-Null
            Write-Verbose ('{0}: Certutil CA Chain Exported from "{1}\{2}" to "{3}\chain.der"' -f (get-date).tostring(), $CAServer, $CAName, $OutputPath)
            Invoke-Expression ("certutil -encode '{0}\chain.der' '{0}\chain.p7b'" -f $OutputPath) | Out-Null
            Write-Verbose ('{0}: Converted Encoding of CA Chain to "{1}\chain.p7b"' -f (get-date).tostring(), $OutputPath)
            Invoke-Expression ("&'{0}' pkcs7 -print_certs -in '{1}\chain.p7b' -out '{1}\chain.pem'" -f $OpenSSLPath, $OutputPath) | Out-Null
            Write-Verbose ('{0}: Converted P7B file to PEM at "{1}\chain.pem"' -f (get-date).tostring(), $OutputPath)
        }
        catch {
            Write-Warning ('A problem occured retrieving the Certificate Chain from CA, PFX will not be created')
        }
    }
    else {
        if (-Not (Test-Path -Path $ChainPath)) {
            Write-Warning ('Provided Certificate Chain Path is not valid!')
        }
        else {
            Copy-Item -Path $ChainPath -Destination "$OutputPath\chain.pem"
            Write-Verbose ('{0}: Copied Certificate Chain from "{1}" to "{2}\chain.pem"' -f (get-date).tostring(), $ChainPath, $OutputPath)
        }
    }
    #endregion

    #region Generate Request File
    $Template = '[ req ]' + [environment]::NewLine
    $Template += "default_bits = 2048" + [environment]::newline
    $Template += "default_keyfile = rui.key" + [environment]::newline
    $Template += "distinguished_name = req_distinguished_name" + [environment]::newline
    $Template += "encrypt_key = no" + [environment]::newline
    $Template += "prompt = no" + [environment]::newline
    $Template += "string_mask = nombstr" + [environment]::newline
    $Template += "req_extensions = v3_req" + [environment]::newline
    $Template += "[ v3_req ]" + [environment]::newline
    $Template += "basicConstraints = CA:FALSE" + [environment]::newline
    $Template += "keyUsage = digitalSignature, keyEncipherment, dataEncipherment" + [environment]::newline
    $Template += "extendedKeyUsage = serverAuth, clientAuth" + [environment]::newline
    $Template += "subjectAltName = "
    ## Check if Default SANs should be used
    if ($UseDefaultSAN) {
        $Template += "DNS: $name, DNS: $FQDN, DNS: $IPAddress, IP: $IPAddress"
    }
    else {
        $Template += "DNS: $CommonName"
    }
    ## Add any additional SANs provided
    $SubjectAlternativeNames | Where-Object { $_ } | ForEach-Object { if ($_ -notlike '*:*') { $Template += ",DNS:$_" } else { $Template += ",$_" } }

    $Template += [environment]::NewLine + [environment]::newline
    $Template += "[ req_distinguished_name ]" + [environment]::newline
    $Template += "countryName = $Country" + [environment]::newline
    $Template += "stateOrProvinceName = $State" + [environment]::newline
    $Template += "localityName = $Locality" + [environment]::newline
    $Template += "0.organizationName = $Organization" + [environment]::newline
    $Template += "organizationalUnitName = $OrganizationalUnit" + [environment]::newline
    $Template += "commonName = $CommonName" + [environment]::newline

    $Template | Set-Content -Path "$OutputPath\$name.cfg" -Encoding Ascii

    Write-Verbose ('{0}: Generated Config File Template at "{1}\{2}.cfg"' -f (get-date).tostring(), $OutputPath, $name)
    Get-Content "$OutputPath\$name.cfg" | ForEach-Object { Write-Verbose ("{0}:`t`t{1}" -f (get-date).tostring(), $_) }

    #endregion

    #region Generate CSR and Key
    #Create CSR and DSA version of Private key
    Write-Verbose ('{0}: Starting Generation of Certificate Files...' -f (get-date).tostring())
    $ErrorActionPreference = 'silentlycontinue'
    Invoke-Expression ("& '{0}' req -new -nodes -out '{1}\{2}.csr' -keyout '{1}\{2}-orig.key' -config '{1}\{2}.cfg' -sha256 {3}" -f $OpenSSLPath, $OutputPath, $name, '2>&1 | out-null')
    $ErrorActionPreference = 'Stop'
    if (-Not (Test-Path -Path "$outputpath\$name-orig.key")) { Write-Error ('A problem occured Generating the DSA key file') -ErrorAction Stop }
    if (-Not (Test-Path -Path "$OutputPath\$Name.csr")) { Write-Error ('A problem occured Generating the CSR file') -ErrorAction Stop }
    Write-Verbose ('{0}: CSR and DSA Key Generated' -f (get-date).tostring())
    #Create RSA version
    $ErrorActionPreference = 'silentlycontinue'
    Invoke-Expression ("& '{0}' rsa -in '{1}\{2}-orig.key' -out '{1}\{2}.key' {3}" -f $OpenSSLPath, $OutputPath, $name, '2>&1 | out-null')
    $ErrorActionPreference = 'stop'
    if (-Not (Test-Path -Path "$outputpath\$name.key")) { Write-Error ('A problem occured Generating the RSA key file') -ErrorAction Stop }
    Write-Verbose ('{0}: RSA Key created from DSA Key' -f (get-date).tostring())
    #endregion

    #region Submit Signing request
    if ($SelfSignCertificate) {
        Invoke-Expression ("& '{0}' req x509 -sha256 -days 365 -key '{1}\{2}.key' -'{1}\{2}.csr' -out '{1}\{2}.crt' {3}" -f $OpenSSLPath, $OutputPath, $Name, '2>&1 | out-null') -ErrorAction Stop | Out-Null
        Write-Verbose ('{0}: CSR Signed by Self')
    }
    else {
        Invoke-Expression ("certreq.exe -submit -config '{0}\{1}' -attrib 'CertificateTemplate:{2}' '{3}\{4}.csr' '{3}\{4}.crt' {5}" -f $CAServer, $CAName, $TemplateName, $OutputPath, $Name, '2>&1 | out-null') -ErrorAction Stop | Out-Null
        Write-Verbose ('{0}: CSR Signed by CA "{1}\{2}"' -f (get-date).tostring(), $caserver, $CAName)
    }
    #endregion

    #region Create PFX
    if ((Test-Path -Path "$OutputPath\Chain.pem") -and -Not $SelfSignCertificate) {
        Invoke-Expression ("& '{0}' pkcs12 -export -in '{1}\{2}.crt' -inkey '{1}\{2}.key' -certfile '{1}\chain.pem' -name '{3}' -passout pass:'{4}' -out '{1}\{2}.pfx' {5}" -f $OpenSSLPath, $OutputPath, $Name, $FQDN, $PFXPassword, '2>&1 | out-null') -ErrorAction Continue | Out-Null
        Write-Verbose ('{0}: PFX File Generated' -f (get-date).tostring())
    }
    #endregion

    <#
.SYNOPSIS
Creates Certificate Request and signs with internal CA or self

.DESCRIPTION
This function attempts to pre-populate parameters to allow a relatively quick Certificate Creation Process.

Minimum Required Values = Name,TemplateName,Organization (assuming only one CA in environment)

OpenSSL.exe is used to execute most commands except the signing process since certutil is the best path for Windows CA.

If you do not have OpenSSL, we recommend using choco to install openssl.light or download to your computer appropriately through the web.

.EXAMPLE

Minimum Options Used Below:

New-SSLCertificate -Name SERVER01 -TemplateName WebServer -Organization Constoso

**Note: This Assumes you have: 
    1.) openssl in your command path under powershell, 
    2.) one CA on your network
    3.) you want the local path for output
    4.) PublicIP is correct for country, state and city/locality
    5.) FQDN resolves to IP address
    6.) domain name is the same as for the computer you are current running command

.EXAMPLE

All Options being Set Below:

New-SSLCertificate -Name SERVER01 `
    -Domain 'contoso.local' `
    -IPAddress '10.0.0.5' `
    -CAServer 'CASERVER01' `
    -CAName 'CASERVER01-CA' `
    -TemplateName WebServer `
    -PFXPassword 'supersecure' `
    -ChainPath 'C:\chain.pem' `
    -Country US -State TX `
    -Locality Austin `
    -Organization 'Contoso' `
    -OpenSSLPath 'C:\openssl\openssl.exe' `
    -OutputPath 'c:\Certs\SERVER01.contoso.local'

**Note: generally this it is not necessary to specify ALL options

.EXAMPLE

$Array = @()
$Array += New-Object psobject -Property @{Name='SERVER01';
    TemplateName='WebServer';
    Organization='Contoso';
    OpenSSLPath='C:\Program Files\OpenSSL\bin\openssl.exe';
    OverwriteExisting=$true}

$Array | foreach-object {New-SSLCertificate -Name $_.Name -TemplateName $_.TemplateName -Organization $_.Organization -OpenSSLPath $_.OpenSSLPath -OverwriteExisting $_.OverwriteExisting}

**Note: The above can be used to create multiple Certificates quickly

#>
}

function New-CertificateSigning {
    [CmdletBinding()]
    param(
        #Certificate name (usually the short name)    
        [parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]
        $CSRPath,
        
        #Path to create folder and files for Certificate Request
        [parameter(Mandatory = $false, 
            ValueFromPipelineByPropertyName = $true)]
        [string]
        $OutputFile = (Get-Item $CSRPath).FullName.Replace('.csr','.crt'),

        #Server that is your Certificate Authority
        [parameter(Mandatory = $false, 
            ValueFromPipelineByPropertyName = $true)]
        [string]
        $CAServer = ((certutil -ADCA | select-string dnshostname | Select-Object -first 1).tostring().split('=')[1]).Trim(),
    
        #Certificate Authority Name
        [parameter(Mandatory = $false, 
            ValueFromPipelineByPropertyName = $true)]
        [string]
        $CAName = ((certutil -ADCA | select-string displayName | Select-Object -first 1).tostring().split('=')[1]).Trim(),
    
        #Name of Template in Certificate Authority
        [parameter(Mandatory = $True, 
            ValueFromPipelineByPropertyName = $true)]
        [string]
        $TemplateName,
    
        #Subject Alternative Name to apply
        [parameter(Mandatory = $false, 
            ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $SubjectAlternativeNames = $null,
    
        #Overwrite existing Certificate (renames folder to backup-<date>)
        [parameter(Mandatory = $false, 
            ValueFromPipelineByPropertyName = $true)]
        [switch]
        $OverwriteExisting
    )

    $ErrorActionPreference = 'Stop'
    $_CSRFileExists = Test-Path -Path $CSRPath -PathType Leaf
    $_OutputFileExists = Test-Path -Path $OutputFile -PathType Leaf

    #region Validate CSR File Path
    if (-Not ($_CSRFileExists)) {
        Write-Error ('File "{0}" not found' -f $CSRPath)
    }
    Write-Verbose ('{0}: VALIDATED - CSR File Exists at "{1}"' -f (get-date).tostring(),$CSRPath)
    #endregion

    #region Validate SAN option
    if ($SubjectAlternativeNames) {
        if (-Not (certutil.exe -getreg -config "$CAServer\$CAName" policy | select-string EDITF_ATTRIBUTESUBJECTALTNAME2).tostring().trim()) {
            Write-Error ('Certificate Authority does not allow Subject Alternative Names Override!') -ErrorAction Stop
        }
        Write-Verbose ('{0}: VALIDATED - Edit Subject Alternative Name option enabled on Certificate Authority' -f (get-date).tostring())
    }
    #endregion

    #region Validate File Output
    if (-Not $OverwriteExisting) {
        if (($_OutputFileExists)) {
            Write-Error ('File "{0}" already exists' -f $OutputFile) -ErrorAction Stop
        }
        Write-Verbose ('{0}: VALIDATED - File "{1}" ready to be created' -f (get-date).tostring(),$OutputFile)
    } else {
        if (-Not ($_OutputFileExists)) {
            Write-Warning ('Overwrite existing selected but file does not exist.')
        }
        Write-Verbose ('{0}: VALIDATED - File "{1}" will be renamed' -f (get-date).ToString(),$OutputFile)
    }
    #endregion

    #region Rename OutputFile
    if ($OverwriteExisting -and ($_OutputFileExists)) {
        $_File = Get-item $OutputFile
        $_NewName = ("{0}\{1}-{2}{3}" -f $_file.Directory.FullName,$_file.BaseName,(get-date).tostring('yyyy.MM.dd_hh.mm.ss'),$_file.Extension)
        Rename-Item -Path $_file.FullName -NewName $_NewName
        if (-Not (Test-Path -Path $_NewName -PathType Leaf)) {
            Write-Error ('Rename of file "{0}" to "{1}" failed' -f $OutputFile,$_NewName) -ErrorAction Stop
        }
        Write-Verbose ('{0}: Renamed File "{1}" to "{2}"' -f (get-date).tostring(),$OutputFile,$_NewName)
    }
    #endregion

    #region Submit Signing request
    $_Command = ''
    $_Command += "certreq.exe -submit -config '$CAServer\$CAName' "
    $_Command += " -attrib 'CertificateTemplate:$TemplateName"
    if ($SubjectAlternativeNames) {
        $_Command += '\nSAN:' + (($SubjectAlternativeNames | ForEach-Object {if ($_ -notlike 'dns=*' -and $_ -notlike 'ipaddress=*') {('dns=' + $_)} else {$_}}) -join '&')    
    }
    $_Command += "' '$CSRPath' '$OutputFile'"
    #$_Command += ' 2>&1 | out-null'
    Write-Verbose ('{0}: Using Command - "{1}"' -f (get-date).tostring(),$_Command)

    Invoke-Expression -Command $_Command -ErrorAction Stop | Out-Null
    Write-Verbose ('{0}: CSR Signed by CA "{1}\{2}"' -f (get-date).tostring(), $caserver, $CAName)
    #endregion

    <#
    .SYNOPSIS

    Signs a CSR File with AD Domain Certificate Authority

    .DESCRIPTION
    
    This function provides a quick way to sign a CSR file with the AD Domain Certificate authority.

    .EXAMPLE

    New-CertificateSigning -CSRPath C:\Certs\server01.csr -Template WebServer

    .EXAMPLE

    New-CertificateSigning -CSRPath .\server01.csr `
        -Template WebServer

    **Note: Command uses the minimum amount of info to sign a CSR

    .EXAMPLE

    New-CertificateSigning -CSRPath .\Server01 `
        -Template WebServer
        -SubjectAlternativeNames ('server01.domain.com','10.0.0.5','ipaddress=10.0.0.5','dns=server.domain.com')
        -OverwriteExisting

    **Note: Above example overrides any Subject Alterntive names and renames the crt file if it exists.

    #>
}

function Test-SQLDatabase 
{
    param( 
    [Parameter(Position=0, Mandatory=$True, ValueFromPipeline=$True)] [string] $Server,
    [Parameter(Position=1, Mandatory=$True)] [string] $Database,
    [Parameter(Position=2, Mandatory=$True, ParameterSetName="SQLAuth")] [string] $Username,
    [Parameter(Position=3, Mandatory=$True, ParameterSetName="SQLAuth")] [string] $Password,
    [Parameter(Position=2, Mandatory=$True, ParameterSetName="WindowsAuth")] [switch] $UseWindowsAuthentication
    )

    # connect to the database, then immediatly close the connection. If an exception occurrs it indicates the conneciton was not successful. 
    process { 
        $dbConnection = New-Object System.Data.SqlClient.SqlConnection
        if (!$UseWindowsAuthentication) {
            $dbConnection.ConnectionString = "Data Source=$Server; uid=$Username; pwd=$Password; Database=$Database;Integrated Security=False"
            $authentication = "SQL ($Username)"
        }
        else {
            $dbConnection.ConnectionString = "Data Source=$Server; Database=$Database;Integrated Security=True;"
            $authentication = "Windows ($env:USERNAME)"
        }
        try {
            $connectionTime = measure-command {$dbConnection.Open()}
            $Result = @{
                Connection = "Successful"
                ElapsedTime = $connectionTime.TotalSeconds
                Server = $Server
                Database = $Database
                User = $authentication}
        }
        # exceptions will be raised if the database connection failed.
        catch {
                $Result = @{
                Connection = "Failed"
                ElapsedTime = $connectionTime.TotalSeconds
                Server = $Server
                Database = $Database
                User = $authentication}
        }
        Finally{
            # close the database connection
            $dbConnection.Close()
            #return the results as an object
            $outputObject = New-Object -Property $Result -TypeName psobject
            write-output $outputObject 
        }
    }
}

Function Get-ExpiredCerts
{
    Param(
        [int]$DueDays = 60,
        [String]$CALocation =  (certutil | select-string config:).tostring().split(':')[1].trim().replace('`',"'")
    )

  $certs = @()
  $now = get-Date;
  $expirationdate = $now.AddDays($duedays)
  $CaView = New-Object -Com CertificateAuthority.View.1
  [void]$CaView.OpenConnection($CAlocation)
  $CaView.SetResultColumnCount(6)
  $index0 = $CaView.GetColumnIndex($false, "Issued Common Name")
  $index1 = $CaView.GetColumnIndex($false, "Certificate Expiration Date")
  $index2 = $CaView.GetColumnIndex($false, "Issued Email Address")
  $index3 = $CaView.GetColumnIndex($false, "Certificate Template")
  $index4 = $CaView.GetColumnIndex($false, "Request Disposition")
  $index5 = $CaView.GetColumnIndex($false, "Requester Name")
  $index0, $index1, $index2, $index3, $index4, $index5 | %{$CAView.SetResultColumn($_) }

  # CVR_SORT_NONE 0
  # CVR_SEEK_EQ  1
  # CVR_SEEK_LT  2
  # CVR_SEEK_GT  16


  $index1 = $CaView.GetColumnIndex($false, "Certificate Expiration Date")
  $CAView.SetRestriction($index1,16,0,$now)
  $CAView.SetRestriction($index1,2,0,$expirationdate)

  # brief disposition code explanation:
  # 9 - pending for approval
  # 15 - CA certificate renewal
  # 16 - CA certificate chain
  # 20 - issued certificates
  # 21 - revoked certificates
  # all other - failed requests
  $CAView.SetRestriction($index4,1,0,20)

  $RowObj= $CAView.OpenView() 

  while ($Rowobj.Next() -ne -1){
    $Cert = New-Object PsObject
    $ColObj = $RowObj.EnumCertViewColumn()
    [void]$ColObj.Next()
    do {
      $current = $ColObj.GetName()
      $Cert | Add-Member -MemberType NoteProperty $($ColObj.GetDisplayName()) -Value $($ColObj.GetValue(1)) -Force  
    } until ($ColObj.Next() -eq -1)
    Clear-Variable ColObj
    $datediff = New-TimeSpan -Start ($now) -End ($cert."Certificate Expiration Date")
    
       
    "Certificate " + $cert."Issued Common Name" + " will expire in " + $dateDiff.Days + " days at " + $cert."Certificate Expiration Date" + " - Requested By: " +$cert."Requester Name"
    #"Send email to : " + $cert."Issued Email Address"
    "------------------------"
  }
  $RowObj.Reset()
  $CaView = $null
  [GC]::Collect()
}

function Test-PendingReboot {
    Param(
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName = 'localhost'
    )

    $ErrorActionPreference = 'Ignore'

    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('localmachine',$ComputerName)
    if ($reg.opensubkey("Software\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\RebootPending").GetValueNames()) {return $true}
    if ($reg.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired").GetValueNames()) {return $true}
    if ($reg.OpenSubKey("SYSTEM\CurrentControlSet\Control\Session Manager").GetValue('PendingFileRenameOperations')) {return $true}
    try { 
        $util = [wmiclass]"\\$Computername\root\ccm\clientsdk:CCM_ClientUtilities"
        $status = $util.DetermineIfRebootPending()
        if(($status -ne $null) -and $status.RebootPending) {
            return $true
        }
    } catch {

    }
 
    return $false
}

function Get-ADUserMembership {
    Param(
        [String]
        $ADUserName
    )

    $_dn = (Get-ADUser $ADUserName -ErrorAction SilentlyContinue).DistinguishedName

    if (-Not $_dn) {
        Write-Error ('AD user Not found') -ErrorAction Stop
    }

    $_result = Get-ADGroup -LDAPFilter "(member:1.2.840.113556.1.4.1941:=$_)" -ErrorAction SilentlyContinue

    if (-Not $_result) {
        Write-Error ('No result returned for AD User Membership')
    }

    return $_result
}

function Show-Alien {
    Param(
        [consolecolor]
        $Color
    )

    $block = @"
 
.     .       .  .   . .   .   . .    +  .
  .     .  :     .    .. :. .___---------___.
       .  .   .    .  :.:. _".^ .^ ^.  '.. :"-_. .
    .  :       .  .  .:../:            . .^  :.:\.
        .   . :: +. :.:/: .   .    .        . . .:\
 .  :    .     . _ :::/:               .  ^ .  . .:\
  .. . .   . - : :.:./.                        .  .:\
  .      .     . :..|:                    .  .  ^. .:|
    .       . : : ..||        .                . . !:|
  .     . . . ::. ::\(                           . :)/
 .   .     : . : .:.|. ######              .#######::|
  :.. .  :-  : .:  ::|.#######           ..########:|
 .  .  .  ..  .  .. :\ ########          :######## :/
  .        .+ :: : -.:\ ########       . ########.:/
    .  .+   . . . . :.:\. #######       #######..:/
      :: . . . . ::.:..:.\           .   .   ..:/
   .   .   .  .. :  -::::.\.       | |     . .:/
      .  :  .  .  .-:.":.::.\             ..:/
 .      -.   . . . .: .:::.:.\.           .:/
.   .   .  :      : ....::_:..:\   ___.  :/
   .   .  .   .:. .. .  .: :.:.:\       :/
     +   .   .   : . ::. :.:. .:.|\  .:/|
     .         +   .  .  ...:: ..|  --.:|
.      . . .   .  .  . ... :..:.."(  ..)"
 .   .       .      :  .   .: ::/  .  .::\
 
"@
 
    Write-Host $block -ForegroundColor $Color
}

function Write-ZeroFile {
    [CmdletBinding()]
    Param(
        # Drive Letter to Create Zero File
        [Parameter(Mandatory=$false)]
        [Char]
        $DriveLetter = 'C',

        # Name of File to create
        [Parameter(Mandatory=$false)]
        [string]
        $FileName = 'ZeroFile.tmp',

        # Free Space to leave on Drive (1-100)
        [Parameter(Mandatory=$false)]
        [ValidateRange(1,100)]
        [Int]
        $PercentFree = 5
    )

    #region Validate Volume
    $_Volume = Get-WmiObject -Class win32_Volume -Filter "Name like '$DriveLetter%'" -ErrorAction SilentlyContinue -Verbose:$false
    
    if (-Not $_Volume) {
        Write-Error ('Drive Letter "{0}" not found' -f $DriveLetter) -ErrorAction Stop
    }
    Write-Verbose ('{0}: VALIDATED - Drive Letter "{1}" Found!' -f (get-date).tostring(),$DriveLetter)
    #endregion

    #region Validate Space
    $_SpaceToLeave = $_Volume.Capacity * ($PercentFree/100)

    if ($_SpaceToLeave -ge $_volume.FreeSpace) {
        Write-Error ('PercentFree "{0}" is smaller than current free space "{1}"' -f $_SpaceToLeave,$_volume.FreeSpace) -ErrorAction Stop
    }
    Write-Verbose ('{0}: VALIDATED - Free Space is greater than "{1}"' -f (get-date).tostring(),$_SpaceToLeave)
    #endregion

    #region Validate Path
    $_FilePath = $_Volume.Name + $FileName

    if (Test-Path $_FilePath) {
        Write-Error ('ZeroFile "{0}" already exists' -f ($_volume.name + $FileName)) -ErrorAction Stop
    }
    Write-Verbose ('{0}: VALIDATED - File "{1}" does not exist, ready to create' -f (get-date).ToString(), $_FilePath)
    #endregion

    #region Write Zeroed File
    $_ArraySize = 64kb
    $_FileSize = $_Volume.FreeSpace - $_SpaceToLeave
    $_ZeroArray = New-Object byte[]($_ArraySize)

    try {
        $_Stream = [io.file]::OpenWrite($_FilePath)
        Write-Verbose ('{0}: Created File Stream @ "{1}"' -f (get-date).tostring(),$_FilePath)
        $_CurFileSize = 0
        While ($_CurFileSize -lt $_FileSize) {
            $_Stream.Write($_ZeroArray,0,$_ZeroArray.Length)
            Write-Verbose ('{0}: "{1}" Bytes Written to File "{2}"' -f (get-date).tostring(),$_ArraySize.length,$_FilePath)
            $_CurFileSize += $_ZeroArray.Length
        }
    } finally {
        if ($_Stream) {
            $_Stream.Close()
            Write-Verbose ('{0}: File Stream Closed' -f (get-date).tostring())
        }
    }
    #endregion

    #region File Cleanup
    if (Test-Path $_FilePath) {
        Remove-Item -Path $_FilePath -Force -Confirm:$false -ErrorAction SilentlyContinue
        if (Test-Path $_FilePath) {
            Write-Error ('Unable to Delete File "{0}"' -f $_FilePath) -ErrorAction Continue
        } else {
            Write-Verbose ('{0}: Removed File "{1}"' -f (get-date).tostring(),$_FilePath)
        }
    }
    #endregion

    <#
    .SYNOPSIS

    Writes a Large File using zeroes to a volume.

    .DESCRIPTION

    Creates a File (Default is ZeroFile.tmp) on the Specified Drive filling up to the specified PercentFree (Default 5%).

    This is intended to help with space reclamation similar to sdelete

    .EXAMPLE

    Write-ZeroFile

    **Note: Writes a file to C:\ZeroFile.tmp leaving 5% free disk space

    #>
}
