# Scripts
This is some of the work I've done up until this point with PowerShell.  My goal is to refine the scripts I've written for re-use.  While this is primarily for myself, you are welcome to use/re-use according to the license agreement.

## VM Provisioning
Refining the production scripts used to provision VM's.  The file "VM Provisioning Funciton.ps1" is the compilation with notes.

* New-VMfromTemplate
* Add-VMtoDomain
* Add-DisktoVM
* New-SSLCertificate
* Enable-WSMANwithSSL

Examples: [VM Provsioning Examples](https://github.com/davesil2/Scripts/wiki/vm-provisoning-examples)

## Global Functions
These are functions that I've had use for over the years.  The Script is put together to be run at powershell startup with Inovke-Expression from the PSHome paths.

```Powershell
Invoke-Expression ((Get-Content \\<domain>\netlogon\globalfunctions.ps1) -join [environment]::newline)
```

Placeing the file on the \\<domain>\netlogon\ network share of the domain and placing the above line in your $pshome.allusersallhosts will load the functions in the script without error or problems of remote script execution.

Some of the handy function in this script are below:

* Test-Port (instead of telnet)
* Test-Ping (returns object data)
* Get-Uptime (returns local or remote computer uptime)
* Get-WWN (Returns FiberChannel WWN's on computer)
* Get-RandomPassword
* ...and more...

### Additional documentation is located at https://github.com/davesil2/Scripts/wiki
