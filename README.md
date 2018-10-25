# Scripts

The scripts in here are defined as functions.  Each of the functions has been something I have spent time working through to allow me to perform tasks that are or at least were not native to PowerShell.

* Create-Certificate
* Create-NewVM
* Configure-IISServer
* Global Functions

Documentation is primarily provided in the Script itself.  However, one of the Scripts I've spent a lot of time and gathered over the years is the "Global Functions".  This "script" was designed to be used as an auto loaded file at powershell start up due to the fact that importing modules and all of that can prove to me frustrating.  By design, you could place the file in a central location (like \\<domain>\netlogon\) and have a script on the server side (possibly pushed via GPO) to read and invoke the script line by line (bypassing the script execution issues)

The above info is documented at the top of the script.

Further documentation is located at https://github.com/davesil2/Scripts/wiki
