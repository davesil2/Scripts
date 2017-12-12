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
    The name of the server or ip address of the server that the request will be submitted to.
    
    .PARAMETER CertificateAuthorityName
    The Certificate authority name as defined on the server.
    
    .PARAMETER CertificateTemplateName
    The name of the Template on the Certificate Authority.
    
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
        [string]$Domain = 'midlandsb.com',
        [String]$CommonName = ($Name + '.' + $Domain),
        [Alias('IPAddress','IP Address')]
        [String]$IP = ([net.dns]::GetHostEntry($CommonName).AddressList.IPAddresstoString),
        [Alias('SANs','SAN')]
        [String[]]$SubjectAlternativeNames = $null,
        [String]$CertificateAuthorityServer = "ADCS-SUB01",
        [String]$CertificateAuthorityName = "MSB-SUB01-CA",
        [String]$CertificateTemplateName = "MSBWebServerAuto",
        [String]$CertificatePassword = 'testpassword',
        [String]$CertificateChainPath = $null,
        [String]$Country = 'US',
        [String]$State = 'IL',
        [String]$Locality = 'Effingham',
        [String]$Organization = 'Midland States Bank',
        [String]$OrganizationalUnit = 'N/A',
        [String]$OpenSSLPath = (Get-command openssl*).Source,
        [String]$OutputPath = "$((get-location).path)\$Name",
        [switch]$OverWrite = $false,
        [switch]$Regenerate = $false,
        [switch]$UseDefaultSANs = $true
    )

    <#
        [string]$Name = 'www'
        [string]$Domain = 'midlandfa.com'
        [String]$CommonName = ($Name + '.' + $Domain)
        [String]$IP = '192.168.69.211'
        [String[]]$SubjectAlternativeNames = $null
        [String]$CertificateAuthorityServer = "ADCS-SUB01"
        [String]$CertificateAuthorityName = "MSB-SUB01-CA"
        [String]$CertificateTemplateName = "MSBWebServerAuto"
        [String]$CertificatePassword = 'testpassword'
        [String]$CertificateChainPath = $null
        [String]$Country = 'US'
        [String]$State = 'IL'
        [String]$Locality = 'Effingham'
        [String]$Organization = 'Midland States Bank'
        [String]$OrganizationalUnit = 'N/A'
        [String]$OpenSSLPath = ((Get-command openssl*).Source)
        [String]$OutputPath = "$((get-location).path)\$Name"
        [switch]$OverWrite = $false
        [switch]$Regenerate = $false
        [switch]$UseDefaultSANs = $true
    #>

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

            Set-Content -Value $Template -Path $OutputPath\$name.cfg

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
            $exp = "certreq.exe -submit -config '$CertificateAuthorityServer\$CertificateAuthorityName' -attrib 'CertificateTemplate:$CertificateTemplateName' $OutputPath\$Name.csr $OutputPath\$Name.crt" 
            Invoke-expression $exp | out-null
        }

        if (!$CertificateChainPath)
        {
            ## download Certificate Chain
            Invoke-WebRequest -URI "https://$CertificateAuthorityServer/certsrv/certnew.p7b?ReqID=CACert&Renewal=6&Mode=inst&Enc=b64" -UseDefaultCredentials -OutFile $OutputPath\chain.p7b

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