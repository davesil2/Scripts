function Send-CitrixStats {
    param (
        [Parameter(Mandatory=$true)]
        [String]
        $CitrixDirector,

        [Parameter(Mandatory=$true)]
        [String]
        $SMTPServer,
        
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $Credentials,

        [Parameter(Mandatory=$false)]
        [String[]]
        $GroupSkipList = ('Developer Desktop'),

        [Parameter(Mandatory=$false)]
        [String]
        $FromEmail = 'noreply@domain.com',

        [Parameter(Mandatory=$true)]
        [String]
        $ToEmail,
        
        [Parameter(Mandatory=$false)]
        [String]
        $EmailSubject = ('Citrix Health Report - {0}' -f ((get-date).ToShortDateString()))
    )
    
    #Store Output into Array
    $Array = @()

    #HTML CSS info
    $header = "<style>table { border-collapse: collapse; width: 100%; } th, td { text-align: left;padding: 8px; } tr:nth-child(even){background-color: #f2f2f2} th { background-color: #4CAF50;color: white; } .problem { background-color: red } .warning { background-color: yellow } </style>"

    #use credentials if provided
    $URI = ('http://{0}/Citrix/Monitor/OData/v2/Data/DesktopGroups()' -f $CitrixDirector)
    if ($Credentials)
    {
        $DesktopGroups = Invoke-RestMethod -Uri $URI -Credential $Credentials
    } else {
        $DesktopGroups = Invoke-RestMethod -Uri $URI -UseDefaultCredentials
    }

    #Execute if any desktop groups are found
    if ($DesktopGroups)
    {
        foreach ($DesktopGroup in $DesktopGroups.Content.Properties)
        {
            ## Get list of machines for Group (removes null machine)
            $URI = ('http://{0}/Citrix/Monitor/OData/v2/Data/Machines()?$filter=DesktopGroup/Name eq ''{1}'' and CurrentLoadIndex ne null' -f $CitrixDirector,$desktopgroup.name) 
            if ($Credentials)
            {
                $Machines = Invoke-RestMethod -Uri $URI -Credential $Credentials | Where-Object{!$_.content.properties.name.null}
            } else {
                $Machines = Invoke-RestMethod -Uri $URI -UseDefaultCredentials | Where-Object{!$_.content.properties.name.null}
            }
            ## Get Session stats for today (only need the most current one)
            $URI = ('http://{0}/Citrix/Monitor/OData/v1/Data/SessionActivitySummaries()?$filter=DesktopGroup/Name eq ''{1}'' and SummaryDate gt datetime''{2}''' -f $CitrixDirector,$desktopgroup.name,(get-date).ToString('yyyy-MM-dd'))
            if ($Credentials)
            {
                $sessions = Invoke-RestMethod -Uri $URI -Credential $Credentials | Select-Object -last 1
            } else {
                $sessions = Invoke-RestMethod -Uri $URI -UseDefaultCredentials | Select-Object -last 1
            }
            ##Total Machines for Group
            $total = $null
            $total = $machines.content.properties.count
            ##Active machines that are healthy
            $ActiveHealthy = 0
            $ActiveHealthy = [int]($machines.content.properties | Where-Object{$_.isinmaintenancemode.'#text' -eq 'false'}).count
            ##Machines in Maintenance Mode
            $Maintenance = 0
            $Maintenance = [int]($machines.content.properties | Where-Object{$_.isinmaintenancemode.'#text' -eq 'true'}).count
            ##Machines that are Powered On
            $poweredon = 0
            $poweredon = [int]($machines.content.properties | Where-Object{$_.CurrentPowerState.'#text' -eq 3}).count
            ##Machines that are powered off
            $poweredoff = 0
            $poweredoff = [int]($machines.content.properties | Where-Object{$_.PowerState.'#text' -eq 2}).count
            ##Machines that are unregistered only (2 = unregistered)
            $RegState = 0
            $RegState = [int]($machines.content.properties | Where-Object{$_.CurrentRegistrationState.'#text' -eq 2}).count
            ##Total sessions for group
            $ActiveUsers = 0
            $ActiveUsers = [int]($sessions.content.properties.ConnectedSessionCount.'#text')

            if ($ActiveHealthy -gt 0 -and $DesktopGroup.Name -notin $GroupSkipList)
            {
                $Group = New-Object psobject -Property @{Group=($desktopgroup.name);Total=$Total;ActiveHealthy=$ActiveHealthy;InMaintenance=$Maintenance;PoweredOn=$poweredon; PoweredOff=$poweredoff;ActiveUsers=$activeUsers;Unregistered=$RegState}
                $Array += $Group
            }
        }
        ##Convert output to HTML and highlight
        [xml]$xml = $array | Select-Object Group,Total,ActiveHealthy,InMaintenance,PoweredOn,PoweredOff,ActiveUsers,Unregistered | sort-object Group | ConvertTo-Html -Fragment
        foreach ($tr in $xml.table.SelectNodes('tr'))
        {
            #write-host ('{0}: In Maint: {1}  - Total: {2}  - 50% of Total: {3}' -f $tr.td[0],$tr.td[3],$tr.td[1],(($tr.td[1])/2))
            #write-host ('In Maint {0} is greater than Half of Total {1}: {2}' -f $tr.td[3],($tr.td[1]/2),([int]$tr.td[3] -gt [int]($tr.td[1]/2)))
            try { if ($tr.td[7] -gt 0) {$tr.SelectNodes('td')[7].setattribute("class","problem")} } Catch {}
            try { if ($tr.td[5] -gt 0) {$tr.SelectNodes('td')[5].setattribute("class","problem")} } Catch {}
            try { if ([int]$tr.td[3] -gt [int](($tr.td[1])/2)) {$tr.SelectNodes('td')[3].setattribute("class","warning")} } Catch {}
        }

        $html = ConvertTo-Html -Head $header -Body ($xml.OuterXml)

        ##Send mail message
        if ($Credentials)
        {
            Send-MailMessage -Body ($html -join [environment]::newline) -BodyAsHtml -Subject $EmailSubject -To $ToEmail -From $FromEmail -SmtpServer $smtpserver -Credential $Credentials
        } else {
            Send-MailMessage -Body ($html -join [environment]::newline) -BodyAsHtml -Subject $EmailSubject -To $ToEmail -From $FromEmail -SmtpServer $smtpserver
        }
    } else {
        throw ('No Desktop Groups Found')
    }
}