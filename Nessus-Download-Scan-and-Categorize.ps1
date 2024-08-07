
## Supporting Values
$Headers = @{
    'accept' = 'application/json'
    'X-ApiKeys' = 'accessKey=e23559857ab9b47e78e77e17f4ce0d41cbcf07e64485e6be0a27bc727006dbc5; secretKey=268b29605ca741eed4ed41f540c85089df1c9477350704ad28f186f68b8912da'
}

$Categories = @(
    [pscustomobject]@{
        Label = 'Unsupported'
        SearchTerms = @(
            '*unsupported*',
            '*eol*'
        )
    },
    [pscustomobject]@{
        Label = 'TLS-Untrusted'
        SearchTerms = @(
            '*SSL Certificate*'
        )
    },
    [pscustomobject]@{
        Label = 'TLS-Weak'
        SearchTerms = @(
            '*TLS Version*',
            '*SSL DROWN*',
            '*ssl self-signed*',
            '*ssl rc4*',
            '*SSL Version*',
            '*SSL Weak Cipher*',
            '*TLS*Freak*',
            '*SSL*Sweet*',
            '*SSL Null*'
        )
    },
    [pscustomobject]@{
        Label = 'Apache'
        SearchTerms = @(
            'Apache 2.*',
            'Apache HTTP*'
        )
    },
    [pscustomobject]@{
        Label = 'Log4j'
        SearchTerms = @(
            '*log4j*'
        )
    },
    [pscustomobject]@{
        Label = 'Tomcat'
        SearchTerms = @(
            '*tomcat*'
        )
    },
    [pscustomobject]@{
        Label = 'JRE'
        SearchTerms = @(
            '*java*'
        )
    },
    [pscustomobject]@{
        Label = 'Cisco'
        SearchTerms = @(
            '*cisco*'
        )
    },
    [pscustomobject]@{
        Label = 'VMware'
        SearchTerms = @(
            '*esx*',
            '*vCenter*',
            '*vmware*tools*'
        )
    },
    [pscustomobject]@{
        Label = 'WebServer'
        SearchTerms = @(
            '*HSTS*'
        )
    },
    [pscustomobject]@{
        Label = 'WebSphere'
        SearchTerms = @(
            '*websphere*'
        )
    },
    [pscustomobject]@{
        Label = 'Windows-Security'
        SearchTerms = @(
            'Terminal Services*',
            '*ICMP*',
            '*windows service*',
            '*remote desktop protocol*',
            '*smb signing*',
            '*speculative*',
            '*certpadding*',
            '*unquoted service path*',
            '*uncredentialed*',
            '*font*',
            '*reboot*',
            '*trace*'
        )
    },
    [pscustomobject]@{
        Label = 'Windows-Update'
        SearchTerms = @(
            'KB*',
            'MS*',
            '*update for .NET*',
            '*update for sysinternals*',
            '*updates for microsoft .net framework*',
            '*Updates for Windows Malicious Software Removal*'
        )
    },
    [pscustomobject]@{
        Label = 'MySQL'
        SearchTerms = @(
            '*mysql*'
        )
    },
    [pscustomobject]@{
        Label = 'OpenSSH'
        SearchTerms = @(
            'openssh*'
        )
    },
    [pscustomobject]@{
        Label = 'OpenSSL'
        SearchTerms = @(
            'OpenSSL*'
        )
    },
    [pscustomobject]@{
        Label = 'PeopleSoft'
        SearchTerms = @(
            '*weblogic*',
            '*tuxedo*',
            '*coherance*',
            '*Oracle Global Lifecycle Managemen*'
        )
    },
    [pscustomobject]@{
        Label = 'SQL-Server'
        SearchTerms = @(
            '*sql server*'
        )
    },
    [pscustomobject]@{
        Label = '3rd Party Apps'
        SearchTerms = @(
            '*Updates for SQL Server Management Studio*',
            '*Updates for Microsoft Visual Studio Products*',
            '*Updates for Microsoft Team Foundation Server*',
            '*Updates for Azure Pipelines Agent*',
            '*firefox*',
            '*chrome*',
            '*adobe*'
        )
    },
    [pscustomobject]@{
        Label = 'SNMP'
        SearchTerms = @(
            '*SNMP*DDOS*'
        )
    }
)

foreach ($Location in ('NORAM','EMEA')) {

    (Invoke-WebRequest `
        -Uri 'https://ord-prdnessap01.bpcdomain.berlinpackaging.com:8834/scans/234/export/formats' `
        -Method GET `
        -Headers $Headers `
        -SkipCertificateCheck).content | convertfrom-json | fl *


    # Get Nessus Scan List
    $response = Invoke-WebRequest `
        -Uri 'https://ord-prdnessap01.bpcdomain.berlinpackaging.com:8834/scans' `
        -Method GET `
        -Headers $Headers `
        -SkipCertificateCheck

    $Scan = ($Response.Content | ConvertFrom-Json).scans | ?{$_.Name -like ('{0}*datacenter*' -f $Location)}

    # Export Nessus CSV
    $response = Invoke-WebRequest `
        -URI ('https://ord-prdnessap01.bpcdomain.berlinpackaging.com:8834/scans/{0}/export?format=csv&' -f $Scan.ID) `
        -Method POST `
        -Headers $Headers `
        -SkipCertificateCheck `
        -Body ((@{
            "format" = "csv";
        }) | convertto-json) `
        -ContentType 'application/json'

    # Wait on file creation from Nessus
    Do {
        $status = Invoke-WebRequest `
            -URI ('https://ord-prdnessap01.bpcdomain.berlinpackaging.com:8834/scans/{0}/export/{1}/status' -f $Scan.ID,($response.Content | convertfrom-json).file) `
            -Method GET `
            -SkipCertificateCheck `
            -Headers $Headers
        Start-Sleep 30
    } While (($Status | Convertfrom-Json).status -ne 'Ready')

    # Download file from Nessus
    $TempFileOutput = [system.io.path]::GetTempFileName()
    Invoke-WebRequest `
        -URI ('https://ord-prdnessap01.bpcdomain.berlinpackaging.com:8834/scans/{0}/export/{1}/download' -f $Scan.ID,($response.Content | convertfrom-json).file) `
        -Method GET `
        -SkipCertificateCheck `
        -Headers $Headers `
        -OutFile $TempFileOutput

    # import csv data to memory
    $DC = import-csv $TempFileOutput
    Remove-Item $TempFileOutput

    # add Category field to scan results
    $DC | Add-Member -MemberType NoteProperty -Name 'Category' -Value $null

    # Update item level categories
    foreach ($Category in $Categories | ?{$_.ipaddress -notlike '*.0' -or $_.ipaddress -notlike '*.255'}) {
        foreach ($term in $category.SearchTerms){
            $DC | ?{$_.name -like $term} | %{$_.Category = $Category.Label}
        }
    }

    $DC | Export-CSV "~/Downloads/$location-$((get-date).tostring('yyyyddmm-hhmm')).csv"
}
