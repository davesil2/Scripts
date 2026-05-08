#Requires -Version 7.0
<#
.SYNOPSIS
    HelloWorld PowerShell Module

.DESCRIPTION
    A simple PowerShell module demonstrating module structure
    with a Hello World function.

.NOTES
    Author: Your Name
    Version: 1.0.0
#>


#region Public Functions

function Invoke-HelloWorld {
    <#
    .SYNOPSIS
        Outputs a Hello World greeting.

    .DESCRIPTION
        Displays a customizable Hello World message to the console,
        or returns it as a string when -PassThru is used.

    .PARAMETER Name
        The name to greet. Defaults to "World".

    .PARAMETER PassThru
        If specified, returns the greeting string instead of
        writing directly to the host.

    .EXAMPLE
        Invoke-HelloWorld
        # Output: Hello, World!

    .EXAMPLE
        Invoke-HelloWorld -Name "Alice"
        # Output: Hello, Alice!

    .EXAMPLE
        $msg = Invoke-HelloWorld -Name "Bob" -PassThru
        # Stores "Hello, Bob!" in $msg

    .OUTPUTS
        [string] When -PassThru is used.
        [void]   When writing directly to host.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $Name = 'World',

        [Parameter()]
        [switch] $PassThru
    )

    process {
        $greeting = "Hello, $Name!"

        if ($PassThru) {
            return $greeting
        }
        else {
            Write-Host $greeting
        }
    }
}

#endregion


#region Module Exports

Export-ModuleMember -Function @(
    'Invoke-HelloWorld'
)

#endregion