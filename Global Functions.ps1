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

function Test-Ping
{
<#
.Synopsis
    Powershell Version of Ping
.Description
    This is meant to be used as an alternative to the ping option in an object result
.Parameter Server
    Specify the server or IP address
.Parameter Count
    Specify how many times it should ping (defautl is 1)
.Example
    Test-Ping -Server b1-pnetcs01 -count 5
#>
    Param(
        [Parameter(Mandatory=$true)][String]$Server,
        [Parameter(Mandatory=$false)][Int]$Count=4,
        [Parameter(Mandatory=$false)][Switch]$Continuous=$false,
        [Parameter(Mandatory=$false)][Switch]$Quiet=$false
    )
    
    $result = @()

    $IP = $null
    $HostEntry = $Null
    
    if (![System.Net.IPAddress]::TryParse($Server, [Ref] $IP))
    {
        try
        {
            $HostEntry = [net.dns]::GetHostEntry($Server)
        }
        Catch
        {
            Write-Host 'Error Resolving the Host Name!' -ForegroundColor Red
        }
    }

    if (!$Quiet)
    {
        $array = @()
        $obj = New-Object PSObject

        While ($Count)
        {
            if ($HostEntry)
            {
                $obj = ((New-Object System.Net.NetworkInformation.Ping).Send($HostEntry.AddressList[0].IPAddressToString) | Select @{N='HostName';E={$HostEntry.HostName}},Address,Status,RoundTripTime,@{N='TTL';E={$_.options.TTL}},@{N='Buffer';E={$_.Buffer.Count}})
            }
            else
            {
                $obj = ((New-Object System.Net.NetworkInformation.Ping).Send($IP.IPAddressToString) | Select @{N='HostName';E={$IP.IPAddressToString}},Address,Status,RoundTripTime,@{N='TTL';E={$_.options.TTL}},@{N='Buffer';E={$_.Buffer.Count}})
            }
            $obj
            
            $array += $obj
            if (!$Continuous)
            {
                $count -= 1
            }
        }
    }
    Else
    {
        if ($HostEntry)
        {
            $obj = ((New-Object System.Net.NetworkInformation.Ping).Send($HostEntry.AddressList[0].IPAddressToString) | Select @{N='HostName';E={$HostEntry.HostName}},Address,Status,RoundTripTime,@{N='TTL';E={$_.options.TTL}},@{N='Buffer';E={$_.Buffer.Count}})
        }
        else
        {
            $obj = ((New-Object System.Net.NetworkInformation.Ping).Send($IP.IPAddressToString) | Select @{N='HostName';E={$IP.IPAddressToString}},Address,Status,RoundTripTime,@{N='TTL';E={$_.options.TTL}},@{N='Buffer';E={$_.Buffer.Count}})
        }

        if ($obj.status -eq 'Success')
        {
            return $true
        }
        else
        {
            return $false
        }
    }
}

Function Test-Port
{
<#
.Synopsis
   Test-Port allows you to test if a port is accessible
.Description
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
    Param(
        [Parameter(Mandatory=$true)][String]$Server,
        [Parameter(Mandatory=$true)][Int]$Port,
        [Parameter(Mandatory=$False)][Int]$Timeout = 3000
    )
    
    $IP = [net.dns]::Resolve($server).addresslist[0].ipaddresstostring      

    if ($IP)
    {    
        [void] ($socket = New-Object net.sockets.tcpclient)
        $Connection = $socket.BeginConnect($server,$Port,$null,$null)
        [void] ($Connection.AsyncWaitHandle.WaitOne($TimeOut,$False))
        
        #
        #[void] ($socket.connect($server,$port))
        $hash = @{Server=$Server
                  IPAddress = $IP
                  Port=$Port
                  Successful=($socket.connected)}
                  
        $socket.Close()
        
    }
    else
    {
        $hash = @{Server=$server
                  IPAddress = $null
                  Port=$Port
                  Successful=$null}
    }
    
    return (new-object PSObject -Property $hash) | select Server,IPAddress,Port,Successful
}

Function Get-ActiveTCPListeners
{
<#
.Synopsis
    List the Active TCP Listeners like netstat
.Description
    This allows you to list all Port/Addresses on the machine that are listening.  Similar to using netstat but returned in an object array list that you can use
.Example
    Get-ActiveTCPListeners
#>
    
    return [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTCPListeners() | Select Address,Port
}

Function Get-ActiveTCPConnections
{
<#
.Synopsis
    List the Active TCP Connections like netstat
.Description
    This allows you to list all Port/Addresses on the machine that are Connected.  Similar to using netstat but returned in an object array list that you can use
.Example
    Get-ActiveTCPConnections
#>

    return [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTCPConnections() | Select LocalEndPoint,RemoteEndPoint,State
}

Function Get-ActiveUDPListeners
{
<#
.Synopsis
    List the Active UDP Listeners like netstat
.Description
    This allows you to list all Port/Addresses on the machine that are Listening.  Similar to using netstat but returned in an object array list that you can use
.Example
    Get-ActiveUDPListeners
#>

    return [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveUDPListeners() | Select Address,Port
}

Function Start-TCPListener
{
<#
.Synopsis
    Start-TCPListener allows you to start a TCP listener on a specified port
.Description
    Use this function in combination with the Test-Port function to verify if firewall ports are open between endpoints
.Parameter Port
    Use Port Parameter to specifiy the port the TCP listener will use
.Parameter IPAddress
    Use IP address Parameter to specify which IP address to listen on.  By default this function will listen on all IP addresses.
.Example
    Start-TCPListener -Port 4022
#>
    Param
	(
		[Parameter(Mandatory=$true)]$Port,
		[Parameter(Mandatory=$False)][String]$IPAddress = '0.0.0.0'
	)
	
    if([int]::tryparse($Port,[ref]$null) -and [System.Net.IPAddress]::TryParse($IPAddress, [ref]$IPAddress))
    {
        if((1..65535) -contains $Port)
        {    
            Try
            {
                $Listener = New-Object Net.Sockets.TcpListener $IPAddress, $Port
                $Listener.Start()
                Write-Host "Press Enter to stop listener" -ForegroundColor Green
                Read-Host | Out-Null
                $Listener.Stop()
                Write-Host "Listener stopped" -ForegroundColor Green 
            }
            Catch
            {
				Write-Host "Port is currently in use." -ForegroundColor Red
            }
        }
        else
        {
            Write-Host "Port specificed is not within the valid range." -ForegroundColor Red
            Write-Host "Please specifiy a port between 1 and 65535" -ForegroundColor Red
        }
    }
    else
    {
        Write-Host "$Port is not a valid Port.  Please enter a numeric value between 1 and 65535" -ForegroundColor Red
    }
}

Function Get-ActivePSSessions
{
<#
.Synopsis
    Get-ActivePSSessions provides you with a list of active sessions on a specified host (default is current host)
.Description
    
.Parameter Server
    Specify the Server to get active PowerShell Session on
.Example
    Get-ActivePSSessions

.Example
    Get-ActivePSSessions MyComputer.domain.local

.Example
    Get-ActivePSSessions -Server MyComputer -Credential (get-credential)

.Example
    $Credential = Get-Credential DOMAIN\<samaccountname>
    Get-ActivePSSessions -Server MyComputer -Credential $Credential
#>

    Param
	(
		[Parameter(Mandatory=$false)]$Server=$env:computername,
        [Parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential
	)
    
    if ($Credential)
    {
        #Test Credentials
        if ($Credential.GetNetworkCredential().Domain -ne $Server)
        {
            $Authtype = 'Domain'
            [void](Add-Type -AssemblyName System.DirectoryServices.AccountManagement)
            $pc = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($Authtype)
        }
        Else
        {
            [void](Add-Type -AssemblyName System.DirectoryServices.AccountManagement)
            $pc = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($Authtype,$Server)
            $AuthType = 'Machine'
        }

        if ($pc.ValidateCredentials($Credential.GetNetworkCredential().UserName,$Credential.GetNetworkCredential().Password))
        {
            #Test Remote Host
            if (Test-WSMan -ComputerName $server -Credential $Credential -Authentication Negotiate)
            {
                #Get Session info
                $Sessions = Get-WSManInstance -ConnectionURI ("http://{0}:5985/wsman" -f $server) -ResourceURI Shell -Enumerate -Credential $Credential
                
                if ($Sessions)
                {
                    Return $Sessions	
                }
                Else
                {
                    Write-Host ("No active Sessions found on Host {0}" -f $server)
                }
            }
            Else
            {
                Write-Error ("Failed testing Remote Host connection to {0} with user {1}" -f $Server, $Credential.UserName)
                $sessions = $null
            }
        }
        Else
        {
            Write-Error ("Credentials Invalid")
        }
    }
    Else
    {
        If (Test-WSMan -ComputerName $server -Authentication Negotiate -ErrorAction SilentlyContinue)
        {
            $Sessions = Get-WSManInstance -ConnectionURI ("http://{0}:5985/wsman" -f $server) -ResourceURI Shell -Enumerate

            if ($Sessions)
            {
                Return $Sessions	
            }
            Else
            {
                Write-Host ("No active Sessions found on Host {0}" -f $server)
            }
        }
        else
        {
            Write-Error ("Failed testing Remote Host connection to {0} with Integrated User account {1}" -f $Server, $env:USERNAME)
            $sessions = $null
        }
    }
}

Function Get-Uptime
{
<#
.Synopsis
    Get-Uptime provides the uptime of the server you are currently on be default
.Description
    this function polls the Performance Counter System Up Time and get the current value returning as a timespan output
.Parameter ComputerName
    Specify the Server to get uptime for
.Example
    Get-Uptime

.Example
    Get-uptime MyComputer.domain.local

.Example
    Get-Uptime -ComputerName MyComputer
#>

    Param(
        [Parameter(Mandatory=$False)]
        [Alias('ServerName','Server')]
        [String]$ComputerName="localhost"
    )

    $UpTime = New-Object System.Diagnostics.PerformanceCounter "System", "System Up Time", "", $ComputerName
    [void]($Uptime.NextValue())
    Return [TimeSpan]::FromSeconds($UpTime.NextValue()) | ft
}

Function Get-LocalGroup
{

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
        [System.Management.Automation.PSCredential]$Credential
	)

	Process{
		Foreach($ComputerItem in $ComputerName){
			Try{
                if ($Credential)
                {
                    $Computer = New-Object System.DirectoryServices.DirectoryEntry "WinNT://$ComputerItem,Computer",$Credential.UserName,$Credential.GetNetworkCredential().Password
                }
                else
                {
				    $Computer = [adsi]"WinNT://$ComputerItem,Computer"
                }				
                if($Computer.Path){
					$Computer.Children| Where-Object{$_.SchemaClassName -eq "group" -and $_.name -like $GroupName} |foreach{
						New-Object PSObject -Property @{
							ComputerName = $ComputerItem
							GroupName = $_.Properties.name.Value
							Description = $_.Properties.Description.Value
						} | Select-Object ComputerName,GroupName,Description
					}
				}Else{
					Write-Error "Computer : $ComputerItem : The network path was not found."
				}
			}
			Catch{
				Write-Error "Computer : $ComputerItem : $_"
			}
		}
	}
}

Function Get-LocalGroupMembers
{

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
        [System.Management.Automation.PSCredential]$Credential
		
	)
	
	Process{
		Foreach($ComputerItem in $ComputerName){
			Foreach($GroupItem in $GroupName){
				Try{
			        Write-Verbose "Getting group $GroupItem on computer $ComputerItem"
                    if ($Crednetial)
                    {
                        $Group = New-Object System.DirectoryServices.DirectoryEntry "WinNT://$ComputerItem/$GroupItem,group",$Credential.UserName,$Credential.GetNetworkCredential().Password
                    }
                    else
                    {
				        $Group = [ADSI]"WinNT://$ComputerItem/$GroupItem,group"
                    }						

					Write-Verbose "Getting $GroupItem group members on computer $ComputerItem"
					$Group.Members()| ForEach-Object {
						if(($_.GetType().InvokeMember("Adspath", 'GetProperty', $null, $_, $null)) -match $ComputerItem){
								$UserType = "Local"
						}Else{
								$UserType = "Domain"
						}
						Try{
							New-Object PSObject -Property @{
								ComputerName = $ComputerItem
								GroupName = $GroupItem
								Identity = $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
								UserType = $UserType
								ObjectType = $_.GetType().InvokeMember("Class", 'GetProperty', $null, $_, $null) 
							} | Select-Object ComputerName,GroupName,Identity,UserType,ObjectType,@{Name='Date';Expression={Get-Date}}
						}
						Catch{
							Write-Error "Computer : $ComputerItem : $_"
						}
					}
				}
				Catch{
					Write-Error "Computer : $ComputerItem : $_"
				}					
			}
		}
	}
}

Function Get-GroupMemberShip
{
    Param(
        [Parameter(Mandatory=$true)]
        [Alias()]
        [String]$GroupName,
        [Parameter(Mandatory=$false)]
        [Alias()]
        [String]$ParentGroup
    )

    $ds = New-Object System.DirectoryServices.DirectorySearcher
    $ds.Filter = ("(samaccountname={0})" -f $GroupName)

    $de = $ds.FindOne().GetDirectoryEntry()

    if ($de)
    {
        $Array = @()
        $Members = $de.Member

        foreach ($member in $members)
        {
            if ($member)
            {
                $member = [adsi]('LDAP://' + $member)

                if ($member.objectClass.contains('person'))
                {
                    if ($ParentGroup -and $ParentGroup.Substring(0,1) -ne '/')
                    {
                        $ParentGroup = '/' + $ParentGroup
                    }
                    
                    
                    $array += New-Object PSObject -Property @{Name=$member.displayName.toString();Group=$GroupName;GroupPath=($ParentGroup + '/' + $GroupName);sAMAccountName=$Member.samaccountname.toString();AccountDisabled=$member.invokeGet('AccountDisabled').ToString()}    
                }

                if ($member.objectClass.contains('group'))
                {
                    $array += Get-GroupMemberShip -GroupName $member.samaccountname -ParentGroup $GroupName
                }
            }
            Else
            {
                Write-Warning ("Member Value Returned is null!")
            }
        }

        Return $array
    }
    else
    {
        Write-Warning ("Group {0} was not found in Active Directory!" -f $GroupName)
    }
}

Function Add-LocalGroupMembers
{
    PARAM(
		[Parameter(Position=1,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[alias("CN","__SERVER","Computer","IPAddress")]
		[STRING[]]$ComputerName = $ENV:COMPUTERNAME,
		
		[Parameter(Position=0,Mandatory=$True)]
		[alias("Grp","Group","GroupName")]
		[STRING]$LocalGroupName,

        [Parameter(Mandatory=$True)]
        [Alias("User")]
        [String]$AccountObject,

        [Parameter(Mandatory=$false)]
        [Alias("Local")]
        [Switch]$AccountObjectIsLocal,

        [Parameter(Mandatory=$false)]
        [Alias("IsUser")]
        [Switch]$AccountObjectIsUser,

        [Parameter(Mandatory=$false)]
        [alias("Cred")]
        [System.Management.Automation.PSCredential]$Credential
	)
    
    ForEach ($Computer in $ComputerName)
    {
        If (!$Credential)
        {
            $Group = New-Object System.DirectoryServices.DirectoryEntry "WinNT://$Computer/$LocalGroupName,group"
        }
        Else
        {
            $Group = New-Object System.DirectoryServices.DirectoryEntry "WinNT://$Computer/$LocalGroupName,group",$Credential.UserName,$Credential.GetNetworkCredential().Password
        }

        If ($AccountObjectIsUser)
        {
            $AccountObjectType = 'User' 
        }
        Else
        {
            $AccountObjectType = 'Group'
        }

        if ($AccountObjectIsLocal)
        {
            $Account = [adsi]"WinNT://$Computer/$AccountObject,$AccountObjectType"
        }
        Else
        {
            $Account = [adsi]"WinNT://$($ENV:USERDOMAIN)/$AccountObject,$AccountObjectType"
        }

        if ($Account)
        {
            try
            {
                $Group.Add($Account.ADSPath)
                Write-Host ("Account {0} was added to Group {1} successfully!" -f $AccountObject,$LocalGroupName)
            }
            catch
            {
                Write-Warning ("An Error occured adding Account {0} to Group {1}!" -f $AccountObject,$LocalGroupName)
            }
        }
        else
        {
            Write-Warning ("Account {0} was not Added to Group {1} because the Account could not be found!" -f $AccountObject,$LocalGroupName)
        }
    }
}

Function Add-MicrosoftUpdates
{
    Param()

    try
    {
        $ServiceManager = New-Object -ComObject Microsoft.Update.ServiceManager
        $ServiceManager.ClientApplicationID = "Microsoft Update"

        [void]($ServiceManager.AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,""))
    
        Write-Host ("Successfully added Microsoft Update Service!")
    }
    Catch
    {
        Write-Warning ("Failed to add Microsoft Update Service!")
    }
}

Function Get-SQLIndexFragmentation
{
    Param(
        [Parameter(Mandatory=$False)]
        [String[]]$SQLServers = 'localhost',

        [Parameter(Mandatory=$False)]
        [String[]]$Indexes = '*',

        [Parameter(Mandatory=$False)]
        [String[]]$Tables = '*',
        
        [Parameter(Mandatory=$False)]
        [String[]]$Databases = '*'
    )

    Try
    {
        ##Import SQL Libraries
        [Void]([System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO'))

        $Array = @()

        ForEach ($SQLServer in $SQLServers)
        {
            ##TODO: Test Server

            ##Connect to SQL Server Instance
            $SMO = New-Object Microsoft.SQLServer.Management.SMO.Server $SQLServer

            ##Get Server Databases
            If (($Databases | Out-String).contains('*') -and $Databases.Count -eq 1)
            {
                $DBs = $SMO.Databases
            }
            Else
            {
                $DBs = $Databases | foreach{try {$SMO.Databases[$_]} Catch {$null}} | Where {$_ -ne $null}
            }

            ForEach ($DB in $DBs)
            {
                If (($Tables | Out-String).Contains('*') -and $Tables.Count -eq 1)
                {
                    $Tbls = $DB.Tables
                }
                Else
                {
                    $Tbls = $Tables | ForEach {Try {$DB.Tables[$_]} Catch {$null}} | Where {$_ -ne $null}
                }

                ForEach ($Table in $Tbls)
                {
                    If (($Indexes | Out-String).Contains('*') -and $Indexes.Count -eq 1)
                    {
                        $Indxs = $Table.Indexes
                    }
                    Else
                    {
                        $Indxs = $Indexes | ForEach {Try {$Tables.Indexes[$_]} Catch {$Null}} | Where {$_ -ne $null}
                    }

                    ForEach ($Index in $Indxs)
                    {
                        $Fragmentation = $Index.EnumFragmentation() | select *

                        $obj = New-Object PSObject -Property @{SQLServer=$SQLServer; Database=$DB.Name; Table=$Table.Name; TableRowCount=$Table.RowCount; Index=$Index.Name; Fragmentation=$Fragmentation.AverageFragmentation}

                        $obj

                        $Array += $obj
                    }
                }
            }
        }
    }
    Catch
    {
        Write-Warning ("Process Ended - An Error occured: {0}" -f $Error[0].Exception)   
    }
}

Function Test-Resolve
{
    Param(
        [Parameter(Mandatory=$True)]
        [Alias('DNSName','Server')]
        [String]$ComputerName,

        [Parameter(Mandatory=$False)]
        [Switch]$Quiet
    )

    Try
    {
        $result = [Net.DNS]::Resolve($ComputerName)
        If ($Quiet)
        {
            Return $True
        }
        Else
        {
            Return $result
        }
    }
    Catch
    {
        if ($Quiet)
        {
            Return $False
        }
        Else
        {
            Write-Host ("{0} was not resolvable" -f $ComputerName)
        }
    }
}

Function Speak-Phrase
{
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Phrase
    )

    $Speaker = New-Object -ComObject SAPI.SpVoice
    [Void]($Speaker.Speak($Phrase))
}

Function Get-WWN
{
    Param(
        [Parameter(Mandatory=$False)]
        [String]$ComputerName=($env:ComputerName),

        [Parameter(Mandatory=$false)]
        [Alias('Cred')]
        [System.Management.Automation.PSCredential]$Credential
    )
    try
    {
        $Class = 'MSFC_FibrePortNPIVAttributes'
        if ($Credential)
        {
            #$os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -Credential $Credential
        
            $Result = Get-WmiObject -Class $Class -Namespace 'root/WMI' -ComputerName $ComputerName -Credential $Credential
        }
        else
        {
            #$os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName

            $Result = Get-WmiObject -Class $Class -Namespace 'root/WMI' -ComputerName $ComputerName
        }


        $array = @()

        if ($result)
        {
            ForEach ($WWN in $result)
            {
                
                $obj = New-Object psobject -Property @{ComputerName=$Computername; WWPN=($wwn.wwpn | %{("{0:x}" -f $_).PadLeft(2,'0')}) -join ':'; WWNN=($wwn.wwnn | %{("{0:x}" -f $_).PadLeft(2,'0')}) -join ':'}
                
                $array += $obj
            }

            return $array
        }
    }
    catch
    {
        
    }
}

function New-SymbolicLink
{
    param
    (
        [Parameter(Mandatory=$true)]
        $OriginalPath,

        [Parameter(Mandatory=$true)]
        $MirroredPath,

        [ValidateSet('File', 'Directory')]
        $Type='Directory'

    )
    
    if(!([bool]((whoami /groups) -match "S-1-16-12288") ))
    {
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

function Get-RandomPassword 
{	
	param(
		[int]$length = 12,
		[string]$characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!$%&/()=?*+#_',
        [boolean]$Complex = $true
	)	
	if ($Complex)
    {
        $isComplex = $false
    }
    else
    {
        $isComplex = $true
    }

    while (!$isComplex)
    {
        # select random characters
	    $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
	    # output random pwd
	    $private:ofs=""
	    $pwd = [String]$characters[$random]
        
        if ($pwd -match [regex]'[A-Za-z]' -and $pwd -match [regex]'[0-9]' -and $pwd -match [regex]'[!$%&/()=?*+#_]')
        {
            $isComplex = $true
        }
    }

    return $pwd
    
}

function Set-PageFile
{
    <#
    .SYNOPSIS
        Sets Page File to custom size
 
    .DESCRIPTION
        Applies the given values for initial and maximum page file size.
 
    .PARAMETER Path
        The page file's fully qualified file name (such as C:\pagefile.sys)
 
    .PARAMETER InitialSize
        The page file's initial size [MB]
 
    .PARAMETER MaximumSize
        The page file's maximum size [MB]
 
    .EXAMPLE
        C:\PS> Set-PageFile "C:\pagefile.sys" 4096 6144
    #>
 
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,
        [Parameter(Mandatory=$true,Position=1)]
        [ValidateNotNullOrEmpty()]
        [Int]
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
    if ($ComputerSystem.AutomaticManagedPagefile)
    {
        $ComputerSystem.AutomaticManagedPagefile = $false
        if ($PSCmdlet.ShouldProcess("$($ComputerSystem.Path.Server)", "Disable automatic managed page file"))
        {
            $ComputerSystem.Put()
        }
    }
 
    $CurrentPageFile = Get-WmiObject -Class Win32_PageFileSetting
    if ($CurrentPageFile.Name -eq $Path)
    {
        # Keeps the existing page file
        if ($CurrentPageFile.InitialSize -ne $InitialSize)
        {
            $CurrentPageFile.InitialSize = $InitialSize
            $Modified = $true
        }
        if ($CurrentPageFile.MaximumSize -ne $MaximumSize)
        {
            $CurrentPageFile.MaximumSize = $MaximumSize
            $Modified = $true
        }
        if ($Modified)
        {
            if ($PSCmdlet.ShouldProcess("Page file $Path", "Set initial size to $InitialSize and maximum size to $MaximumSize"))
            {
                $CurrentPageFile.Put()
            }
        }
    }
    else
    {
        # Creates a new page file
        if ($PSCmdlet.ShouldProcess("Page file $($CurrentPageFile.Name)", "Delete old page file"))
        {
            $CurrentPageFile.Delete()
        }
        if ($PSCmdlet.ShouldProcess("Page file $Path", "Set initial size to $InitialSize and maximum size to $MaximumSize"))
        {
            Set-WmiInstance -Class Win32_PageFileSetting -Arguments @{Name=$Path; InitialSize = $InitialSize; MaximumSize = $MaximumSize}
        }
    }
}

Function Create-MyPSDrive
{
	Param(
		[String]$Root = ('\\il-svr-fs01\users\{0}' -f (($env:USERNAME).Trim('a_'))),
		[String]$Drive = (($env:USERNAME).Trim('a_'))
	)

	If (Test-Path -Path $Root)
	{
		New-PSDrive -Name $Drive -Root $Root -PSProvider FileSystem -Scope Global
	}
	
}

Function Add-TokenPrivilege
{
 
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

Function Get-PublicIP
{
    return (new-object psobject -Property @{PublicAddress=((Invoke-WebRequest -uri "http://ifconfig.me/ip").content.Trim())})
}

function Restart-RemoteService
{
    Param
    (
        [Parameter(Mandatory = $true)][String]$Server,
        [Parameter(Mandatory = $true)][String]$ServiceName,
	    #[Parameter(Mandatory = $true)][Boolean]$Force,
        [System.Management.Automation.PSCredential]$Credential
    )

    
    try
    {
        if ($Credential)
        {
            $svc = Get-WMIObject -Class Win32_Service -ComputerName $Server -Filter ("Name='$ServiceName'") -Credential $Credential
        }
        Else
        {
            $svc = Get-WMIObject -Class Win32_Service -ComputerName $Server -Filter ("Name='$ServiceName'")
        }

        $svc.StopService() | Out-Null
        Write-Host ('Service {0} Stopped on Server {1}' -f $ServiceName,$Server)
        $svc.StartService() | Out-Null
        Write-Host ('Service {0} Started on Server {1}' -f $ServiceName,$Server)
    }
    catch
    {
        Write-Error ('Error Restarting Service')
    }
}

function Create-Certificate
{
    <#
    .SYNOPSIS
    Create's SSL Certificates using openssl and certreq

    .DESCRIPTION
    Create-Certificate uses either local or provided path of openssl to create the csr and private key for requesting to certificate authority.

    Natively the tool also calls out to the windows certificate authority using certreq to make a query using specified template and Certificate authority all storing the results in a specified location/folder including the name of the certificate.
    
    .PARAMETER Name
    This should be the name of the system.  I many cases this could simply be the server name.  This value is used to derive the FQDN along with the domain name.
    
    .PARAMETER Domain
    Domain is the domain that will be used for DNS.  Name + domain = Fully Qualified domain name.
    
    .PARAMETER CommonName
    Default value is set to the name above, but can be specified as something else if desired.
    
    .PARAMETER IP
    Default valued is specified as the IP that resolves to the FQDN created by Name + Domain
    
    .PARAMETER SubjectAlternativeNames
    Value should be an Array.  If no type is specified the default type is used as DNS.  'DNS: server.domain.com' could be used or 'IP: 192.168.0.1' could be used to specify the type.  If just provided as an array of string's, the default will be DNS type.
    
    .PARAMETER CertificateAuthorityServer
    The name of the server or ip address of the server that the request will be submitted to.  You can find the Certificate Authorities available in your environment with certutil -ADCA command.
    
    .PARAMETER CertificateAuthorityName
    The Certificate authority name as defined on the server.  You can find the Certificate Authorities available in your environment with certutil -ADCA command.
    
    .PARAMETER CertificateTemplateName
    The name of the Template on the Certificate Authority.  A list of templates in your CA can be found with certutil -ADTemplate command.
    
    .PARAMETER CertificatePassword
    The password used to create the pfx file.  the default is "testpassword" without the quotes.
    
    .PARAMETER CertificateChainPath
    Path to the Cetificate Authority Trust Chain.  If no value is specified, the default will attempt to download the chain using the https://<server>/certsrv/certnew.p7b file.
    
    .PARAMETER Country
    Specific Country for certificate request, default is US
    
    .PARAMETER State
    State for certificate request, Default is IL.
    
    .PARAMETER Locality
    State or provinece of certificate
    
    .PARAMETER Organization
    The Organization the certificate is for.
    
    .PARAMETER OrganizationalUnit
    This can be the department or group the certificate is for or who is responsible for administering the certificate.
    
    .PARAMETER OpenSSLPath
    Path to openssl.  The default path is whatever is defined in Get-Command openssl*.  If no path is found, the script will error out.
    
    .PARAMETER OutputPath
    Default Path is the current directory put the name as specified in the function call.  Otherwise you can specifiy the location ot put all of the generated file.
    
    .PARAMETER OverWrite
    This will remove all files in the directory of the output path is set to true and generate a new certificate.
    
    .PARAMETER Regenerate
    This will move all existing files except the cfg file to a backup directory in the output folder if it already exists and then create the key and other objects.
    
    .PARAMETER UseDefaultSANs
    Default value is true where it will use the name, fqdn and IP address for the Subject Alternative names this includes using the IP address as DNS as well since IE has an issue recognizing an IP address as the IP type.
    
    .EXAMPLE
    Create-Certificate -Name server

    .EXAMPLE
    Create-Certificate -Name server -Domain mydomain.com -IP 192.168.2.2

    .EXAMPLE
    Create-Certificate -Name server -Domain mydomain.com -IP 192.168.2.2 -SubjectAlternativeNames ('alternative','192.168.2.3')

    .EXAMPLE
    Create-Certificate -Name server -CertificateAuthorityServer caserver -CertificateAuthorityName caname -CertificateTemplate cawebtemplate
    
    .NOTES
    No notes are available at this time.
    #>

    param(
        [Parameter(Mandatory=$True)]
        [Alias('Server','ServerName')]
        [string]$Name,
        [Alias('DomainName')]
        [string]$Domain = ($env:USERDNSDOMAIN),
        [String]$CommonName = ($Name + '.' + $Domain),
        [Alias('IPAddress','IP Address')]
        [String]$IP = ([net.dns]::GetHostEntry($CommonName).AddressList.IPAddresstoString),
        [Alias('SANs','SAN')]
        [String[]]$SubjectAlternativeNames = $null,
        [String]$CertificateAuthorityServer = ((certutil -ADCA | select-string dnshostname | select -first 1).tostring().split('=')[1]).Trim(),
        [String]$CertificateAuthorityName = ((certutil -ADCA | select-string displayName | select -first 1).tostring().split('=')[1]).Trim(),
        [Parameter(Mandatory=$True)]
        [String]$CertificateTemplateName = "",
        [String]$CertificatePassword = 'testpassword',
        [String]$CertificateChainPath = $null,
        [String]$Country = 'US',
        [String]$State = 'IL',
        [Parameter(Mandatory=$True)]
        [String]$Locality = "",
        [Parameter(Mandatory=$True)]
        [String]$Organization = "",
        [String]$OrganizationalUnit = 'N/A',
        [String]$OpenSSLPath = (Get-command openssl*).Source,
        [String]$OutputPath = "$((get-location).path)\$Name.$Domain",
        [switch]$OverWrite = $false,
        [switch]$Regenerate = $false,
        [switch]$UseDefaultSANs = $true
    )

    ## Generate the Fully Qualified Domain Name
    $FQDN = ($name + '.' + $Domain)

    ## Verify we have a valid openssl executable
    If ((Test-Path -Path $OpenSSLPath))
    {
        ## Clear Out folder if directed to OverWrite
        If ((Test-Path -Path $OutputPath\$name.cfg) -and $OverWrite)
        {
            Remove-Item $OutputPath\* -Force    
        }
        ## Move Existing files to backup folder is files exist
        if ((Test-Path -Path $OutputPath\$name.key) -and $Regenerate)
        {
            New-Item "$OutputPath\Backup-$((get-date).tostring('yyyy.MM.dd_hh.mm.ss'))" -ItemType Directory
            Get-ChildItem $Outputpath -Exclude *.cfg,backup | Move-Item -Destination $OutputPath\Backup\
        }
        ## Create Directory for Generating Certificate if it doesn't exist
        If (!(Test-Path -Path $OutputPath))
        {
            New-Item $OutputPath -ItemType Directory | Out-Null

            Write-Host "Created Directory location: $OutputPath"
        }

        if (!(Test-Path -Path $OutputPath\$name.cfg))
        {
            ## Create Config File
            $Template = "[ req ]" + [environment]::newline
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
            if ($UseDefaultSANs)
            {
                $Template += "DNS: $name, DNS: $FQDN, DNS: $IP, IP: $IP"
            }

            ## Add any additional SANs provided
            foreach ($san in $SubjectAlternativeNames)
            {
                ## Add DNS SAN type if not specified
                If ($san -notlike "*:*")
                {
                    $Template += ",DNS:$san"
                }
                Else
                {
                    $Template += ",$san"
                }
            }
            $Template += [environment]::NewLine + [environment]::newline
            $Template += "[ req_distinguished_name ]" + [environment]::newline
            $Template += "countryName = $Country" + [environment]::newline
            $Template += "stateOrProvinceName = $State" + [environment]::newline
            $Template += "localityName = $Locality" + [environment]::newline
            $Template += "0.organizationName = $Organization" + [environment]::newline
            $Template += "organizationalUnitName = $OrganizationalUnit" + [environment]::newline
            $Template += "commonName = $CommonName" + [environment]::newline

            $Template | Set-Content -Path "$OutputPath\$name.cfg" -Encoding Ascii

            Write-Host "Created Config file at $OutputPath\$Name.cfg"
        }

        ## Verify no existing private key or csr
        If ((Test-Path -Path $OutputPath\$Name.cfg) -and !(Test-Path -Path $Outputpath\$Name-orig.key) -and !(Test-Path -Path $OutputPath\$Name.csr))
        {
            ## Generate CSR and DSA Version of Private Key
            $exp = "& '$OpenSSLPath' req -new -nodes -out $OutputPath\$name.csr -keyout $OutputPath\$name-orig.key -config $OutputPath\$name.cfg -sha256"
            Invoke-Expression $exp | out-null

            ## Create RSA version of Private key
            $exp = " & '$OpenSSLPath' rsa -in $OutputPath\$Name-orig.key -out $OutputPath\$Name.key"
            Invoke-expression $exp | out-null
        }

        ## Submit Signing Request if Regenerating or non-existant
        If ($Regenerate -or !(Test-Path -Path $Outputpath\$Name.crt))
        {
            ## Submit Request to CA
            $exp = "certreq.exe -submit -config '$CertificateAuthorityServer\$CertificateAuthorityName' -attrib 'CertificateTemplate:$CertificateTemplateName' '$OutputPath\$Name.csr' '$OutputPath\$Name.crt'" 
            Invoke-expression $exp | out-null
        }

        if (!$CertificateChainPath)
        {
            ## download Certificate Chain
            Invoke-WebRequest -URI "http://$CertificateAuthorityServer/certsrv/certnew.p7b?ReqID=CACert&Renewal=6&Mode=inst&Enc=b64" -UseDefaultCredentials -OutFile $OutputPath\chain.p7b

            ## Convert p7b (pkcs7) to pem
            Invoke-expression "& '$OpensslPath' pkcs7 -in $OutputPath\chain.p7b -out $OutputPath\chain.pem -print_certs"

            Remove-item $OutputPath\chain.p7b -Force
        }

        ## Create PFX file
        If (Test-Path -Path $OutputPath\$name.crt)
        {
            $exp = "& '$OpensslPath' pkcs12 -export -in $OutputPath\$name.crt -inkey $OutputPath\$name.key -certfile $OutputPath\chain.pem -name $fqdn -passout pass:$certificatepassword -out $outputpath\$name.pfx"
            Invoke-expression $exp | out-null
        }

        
    }
    Else
    {
        Write-Error -Message "OpenSSL executable is not valid, either OpenSSL is not installed on your system or provided path to OpenSSL is unavailable!"
    }
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

function Test-PendingReboot
{
    Param(
        [string]$ComputerName = 'localhost'
    )
    $ErrorActionPreference = 'Ignore'

    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('localmachine',$ComputerName)
    if ($reg.opensubkey("Software\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\RebootPending").GetValueNames()) {return $true}
    if ($reg.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired").GetValueNames()) {return $true}
    if ($reg.OpenSubKey("SYSTEM\CurrentControlSet\Control\Session Manager").GetValue('PendingFileRenameOperations')) {return $true}
    try{ 
        $util = [wmiclass]"\\$Computername\root\ccm\clientsdk:CCM_ClientUtilities"
        $status = $util.DetermineIfRebootPending()
        if(($status -ne $null) -and $status.RebootPending){
            return $true
        }
    }catch{}
 
     return $false
}

function Get-ADUserMembership
{
    Param(
        [String]$ADUserName
    )

    $dn = (Get-ADUser $ADUserName).DistinguishedName

    (Get-ADGroup -LDAPFilter ("(member:1.2.840.113556.1.4.1941:={0})" -f $dn))
}

function Show-Alien
{
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
 
    Write-Host $block -ForegroundColor Green
}
