##########################################################################################
# CHANGE THESE SETTINGS
##########################################################################################
$devices=@(
    '172.16.48.12'
    ,'172.16.48.36'
    ,'172.16.48.39'
);

$sslCountry="US"
$sslState="California"
$sslLocality="La Mirada"
$sslOrg="Spinitar"
$sslOrgUnit="Programming"
$sslEmail="programming@spinitar.com"
$sslRootCN="Spinitar Programming TB RCert"
$sslIntermediateCN="Spinitar Programming TB ICert"

# Root CA passphrase
$rootPassword="certificaterootpassword"

# Intermediate Cert passphrase
$intermediatePassword="certificateintermediatepassword"

# Device Cert passphrase
$devicePassword="agenericpasswordfordevices"

# Password for PFX export
$exportPassword="spinitar"

##########################################################################################
# CHANGE ONLY IF NEEDED
##########################################################################################
#OUTPUT FOLDER NAMES
$outputFolder="ProgrammingTB"
$rootFolder="Root"
$intFolder="Intermediate"

$sslsha="sha256"
$sslrootdays="7300" #20 years
$sslintdays="3650"  #10 years
$sslsrvdays="800"   #about 2 years


##########################################################################################
## DO NOT CHANGE
##########################################################################################
$outputDirectory="$PSScriptRoot\$outputFolder"
$rootDirectory="$outputDirectory\$rootFolder"
$intDirectory="$outputDirectory\$intFolder"

############################################################################################
# Some global vars
############################################################################################
$StepThroughAll = $false

############################################################################################
# do the press any key to continue
############################################################################################
function Pause(){
    write-host "Press any key to continue..."
    [void][System.Console]::ReadKey($true)
}
function PressAnyKeyToContinue(){
    if ($StepThroughAll -eq $false) {
        Pause
    }
}

############################################################################################
# Creates the directory if needed
############################################################################################
function New-Directory($directory){
    $exists = Test-Path -Path $directory
    if ($exists -eq $false){
        New-Item -Path $directory -ItemType directory
    }
}

############################################################################################
# Create a file at the given directory. Overwrites any contents with the given argument
############################################################################################
function New-File($directory,$filename,$contents){
    $filepath="$directory\$filename"
    $exists = Test-Path $filepath -PathType Leaf
    if ($exists -eq $false){
        New-Item -path $filepath -ItemType file
        Write-Host "File created: $filepath" -ForegroundColor Green
        Set-Content -Path $filepath -Value $contents
        $size = (Get-Item $filepath).length
        Write-Host "File Size:$size" -ForegroundColor Green
    }
    else{
        Set-Content -Path $filepath -Value $contents
        $size = (Get-Item $filepath).length
        Write-Host "File already exists: $filepath" -ForegroundColor Yellow
        Write-Host "File Size:$size" -ForegroundColor Green
    }
}

############################################################################################
# Creates a new key.pem
############################################################################################
function New-Key($outputfile,$passphrase){
    Write-Host "Generating Key $outputfile with passphrase $passphrase"
    &openssl genpkey -algorithm RSA -out $outputfile -aes-256-cbc -pkeyopt rsa_keygen_bits:2048 -pass pass:$passphrase
    if ((Test-Path -path $outputfile) -eq $false) {
        Write-Host "ERROR: Key file not found - $outputfile" -ForegroundColor Magenta
        PressAnyKeyToContinue
        return
    }
    Write-Host "Generating Key Completed" -ForegroundColor Green
}

############################################################################################
# Executes the SSL to show the cert on the screen
############################################################################################
function Show-Cert($file) {
    if ($StepThroughAll -eq $false){
        $response = Read-Host -Prompt "View the Cert y/[n]"
        if($response.ToLower() -eq 'y'){
            &openssl x509 -noout -text -in $file
            PressAnyKeyToContinue
        }
    }
}

############################################################################################
# Executes the SSL to create a new Root Cert
############################################################################################
function New-RootCert($outputfile,$passphrase,$configfile,$days,$keyfile){
    Write-Host "Generating Root Cert $outputfile"
    Write-Host "using Passphrase:$passphrase"
    Write-Host "using Config:    $configfile"
    Write-Host "using Days:      $days"
    Write-Host "using KeyFile:   $keyfile"
    &openssl req -passin pass:$passphrase -config $configfile -key $keyfile -new -x509 -days $days -$sslsha -extensions v3_ca -out $outputfile
    if ((Test-Path -path $outputfile) -eq $false){
        Write-Host "ERROR: Root Cert creation failed" -ForegroundColor Magenta
        PressAnyKeyToContinue
        return
    }
    Write-Host "Generating Root Cert Completed." -ForegroundColor Green
}

############################################################################################
# Create the Root Cert
############################################################################################
function Write-RootCert() {
    Clear-Host
    Write-Host "Writing Root Cert"
    $rootConfig=@"
[ ca ]
default_ca             = CA_default

[CA_default]
default_md             = sha256
policy                 = policy_strict

[ policy_strict ]
# The root CA should only sign intermediate certificates that match.
# See the POLICY FORMAT section of man ca.
countryName            = match
stateOrProvinceName    = match
organizationName       = match
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional

[ req ]
# Options for the req tool (man req).
prompt                 = no
default_bits           = 2048
distinguished_name     = req_distinguished_name
string_mask            = utf8only

[ req_distinguished_name ]
C                      = $sslCountry
ST                     = $sslState
L                      = $sslLocality
O                      = $sslOrg
#OU                    = $sslOrgUnit
CN                     = $sslRootCN
#emailAddress          = $sslEmail

[ v3_ca ]
# Extensions for a typical CA (man x509v3_config).
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

"@

    if ((Test-Path $rootDirectory) -eq $true){
        Remove-Item $rootDirectory -Force -Recurse
    }

    $outputFile="$rootDirectory\cert.pem"
    $configFile="$rootDirectory\ssl.cnf"
    $keyFile="$rootDirectory\key.pem"

    $dirResult = New-Directory -directory $rootDirectory
    $ndxResult = New-File -directory $rootDirectory -filename "index.txt" -contents $null
    $attResult = New-File -directory $rootDirectory -filename "index.txt.attr" -contents $null
    $serResult = New-File -directory $rootDirectory -filename "serial" -contents "1000"
    $cnfResult = New-File -directory $rootDirectory -filename "ssl.cnf" -contents $rootConfig

    $keyResult = New-Key -outputfile $keyFile -passphrase $rootPassword

    $cerResult = New-RootCert -outputfile $outputFile -passphrase $rootPassword -config $configFile -days $sslrootdays -key $keyFile

    Show-Cert -file $outputFile
    return
}

############################################################################################
# Executes the SSL to create a CSR
############################################################################################
function New-IntermediateCSR($outputfile, $passphrase, $configfile, $keyfile){
    Write-Host "Generating Intermediate CSR $outputfile"
    &openssl req -passin pass:$passphrase -config $configfile -new -$sslsha -key $keyfile -out $outputfile
    if ((Test-Path -path $outputfile) -eq $false){
        Write-Host "ERROR: Intermediate Cert creation failed" -ForegroundColor Magenta
        PressAnyKeyToContinue
        return
    }
    Write-Host "Generating Intermediate CSR Completed." -ForegroundColor Green
}

############################################################################################
# Create the Intermediate or Signing Cert
############################################################################################
function Write-IntermediateCert() {
    Clear-Host
    Write-Host "Writing Intermediate Cert"
    $path = "$outputFolder/$intFolder"
    $intConfig = @"
[ ca ]
default_ca             = CA_default

[CA_default]
default_md             = sha256
database               = $path/index.txt
serial                 = $path/serial
policy                 = policy_loose

[ policy_loose ]
# The signer CA should only sign intermediate certificates that match.
# See the POLICY FORMAT section of man ca.
countryName            = optional
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional

[ req ]
# Options for the req tool (man req).
prompt                 = no
default_bits           = 2048
distinguished_name     = req_distinguished_name
string_mask            = utf8only

[ req_distinguished_name ]
C                      = $sslCountry
ST                     = $sslState
L                      = $sslLocality
O                      = $sslOrg
#OU                    = $sslOrgUnit
CN                     = $sslIntermediateCN
#emailAddress          = $sslemail

[ v3_intermediate_ca ]
# Extensions for a typical CA (man x509v3_config).
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign
"@
    Set-Location $PSScriptRoot
    $dirResult = New-Directory $intDirectory
    $ndxResult = New-File -directory $intDirectory -filename "index.txt" -contents $null
    # this caused errors during cert creation
    # $attResult = New-File -directory $intDirectory -filename "index.txt.attr" -contents $null
    $attResult = New-File -directory $intDirectory -filename "index.txt.attr" -contents "unique_subject = no"
    $serResult = New-File -directory $intDirectory -filename "serial" -contents "1000"

    $intCnf = "$intDirectory\ssl.cnf"
    $intCsr = "$intDirectory\csr.pem"
    $intKey = "$intDirectory\key.pem"
    $intCert = "$intDirectory\cert.pem"

    $rootCert = "$rootDirectory\cert.pem"
    $rootKey = "$rootDirectory\key.pem"

    $keyResult = New-Key -outputfile $intKey -passphrase $intermediatePassword
    $cnfResult = New-File -directory $intDirectory -filename "ssl.cnf" -contents $intConfig
    $csrResult = New-IntermediateCSR -outputfile $intCsr -passphrase $intermediatePassword -configfile $intCnf -keyfile $intKey

    if ((Test-Path $intCsr) -eq $false){
        Write-Host "ERROR: Intermediate CSR not found." -ForegroundColor Magenta
        PressAnyKeyToContinue
        return
    }

    if ((Test-Path $rootCert) -eq $false){
        Write-Host "ERROR: Root Cert not found." -ForegroundColor Magenta
        PressAnyKeyToContinue
        return
    }

    Write-Host "Creating Intermediate Cert and Signing it with Root Cert"
    &openssl.exe ca -batch -passin pass:$rootPassword -config $intCnf -cert $rootCert -keyfile $rootKey -outdir $intDirectory -extensions v3_intermediate_ca -days $sslintdays -notext -md $sslsha -in $intCsr -out $intCert
    Write-Host "Creating Intermediate Cert and Signing it with Root Cert done."

    if ((Test-Path $intCert) -eq $false){
        Write-Host "ERROR: Intermediate Cert not created" -ForegroundColor Magenta
        PressAnyKeyToContinue
        return
    }

    Write-Host "Creating chain.pem"
    $chaincontents = Get-Content $intCert
    $chaincontents += Get-Content $rootCert
    $chainResults = New-File -directory $intDirectory -filename "chain.pem" -contents $chaincontents
    Write-Host "Creating chain.pem done"

    Write-Host "Verifying Cert"
    $result = &openssl verify -CAfile $rootCert $intCert
    Write-Host $result
    if ($result.Contains(': OK')){
        Write-Host "Intermediate Cert Verification Successful" -ForegroundColor Green
    }
    else{
        Write-Host "Intermediate Cert Verification Failed" -ForegroundColor Magenta
    }

    Show-Cert -file $intCert
    return
}

############################################################################################
# Create the Intermediate or Signing Cert
############################################################################################
Function Remove-InvalidFileNameChars {
    param(
      [Parameter(Mandatory=$true,
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
      [String]$Name
    )

    $invalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
    $re = "[{0}]" -f [RegEx]::Escape($invalidChars)
    return ($Name -replace $re)
}

############################################################################################
# Create the Device CSR Config
############################################################################################
function New-DeviceCsrConfig($outputDir) {
    $config = @"
[ ca ]
default_ca         = CA_default

[CA_default]
default_md         = $sslsha

[ req ]
# Options for the req tool (man req).
default_bits       = 2048
distinguished_name = req_distinguished_name
string_mask        = utf8only
prompt             = no

[ req_distinguished_name ]
# See https://en.wikipedia.org/wiki/Certificate_signing_request
C                  = $sslCountry
ST                 = $sslState
L                  = $sslLocality
O                  = $sslOrg
#OU                = $sslOrgUnit
CN                 = $deviceHostName
#emailAddress      = $sslemail
"@
    #create the config file
    $outfile = "$outputDir\csr-ssl.cnf"
    $result = New-File -directory $outputDir -filename 'csr-ssl.cnf' -contents $config
    if ((Test-Path -path $outfile) -eq $false){
        Write-Host "ERROR: CSR Config file not found - $outfile" -ForegroundColor Magenta
        PressAnyKeyToContinue
        return #continue with the loop
    }
    else {
        Write-Host "CSR Config File Completed" -ForegroundColor Green
    }
}

############################################################################################
# Create the Device CSR
############################################################################################
function New-DeviceCsr($outputDir){
    Write-Host "Generating Device csr.pem"
    $key = "$outputDir\key.pem"
    $config = "$outputDir\csr-ssl.cnf"
    $outfile = "$outputDir\csr.pem"
    $result = &openssl req -passin pass:$devicePassword -config $config -key $key -new -$sslsha -out $outfile
    if ((Test-Path -path $outfile) -eq $false) {
        Write-Host "ERROR: CSR file not found - $outfile" -ForegroundColor Magenta
        PressAnyKeyToContinue
        return #continue with the loop
    }
    else {
        Write-Host "CSR Completed" -ForegroundColor Green
    }
}

############################################################################################
# Create the Device Config
############################################################################################
function New-DeviceConfig($outputDir){

    #path here is used in the config file to refer to the signing cert which is the intermediate cert
    $path = "$outputFolder/$intFolder"
    $config = @"
[ ca ]
default_ca             = CA_default

[CA_default]
default_md             = $sslsha
database               = $path/index.txt
serial                 = $path/serial
policy                 = policy_loose
copy_extensions        = copy

[ policy_loose ]
# Allow the intermediate CA to sign a more diverse range of certificates
# See the POLICY FORMAT section of man ca.
countryName            = optional
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional

[ req ]
# Options for the req tool (man req).
prompt                 = no
default_bits           = 2048
distinguished_name     = req_distinguished_name
string_mask            = utf8only

[ req_distinguished_name ]
C                      = $sslCountry
ST                     = $sslState
L                      = $sslLocality
O                      = $sslOrg
#OU                    = $sslOrgUnit
CN                     = $deviceHostName
#emailAddress          = $sslEmail

[server_cert]
# Extensions for server certs(man x509v3_config).
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = CA:FALSE
keyUsage               = critical, digitalSignature, keyEncipherment
nsCertType             = server
nsComment              = "openssl.exe Generated Server Certificate"
extendedKeyUsage       = serverAuth
"@
    $outputfile = "$outputDir\ssl.cnf"
    $result = New-File -directory $outputDir -filename 'ssl.cnf' -contents $config
    if ((Test-Path -path $outputfile) -eq $false){
        Write-Host "ERROR: Config file not found - $outputfile" -ForegroundColor Magenta
        PressAnyKeyToContinue
        return #continue with the loop
    }
    else {
        Write-Host "Device Config File Completed" -ForegroundColor Green
    }
}

############################################################################################
# Generate a single Device Cert
############################################################################################
function Write-DeviceCert($deviceHostName){
    Write-Host ""
    Write-Host "------------------------------------------------------" -ForegroundColor Yellow
    Write-Host "Writing Cert for $deviceHostName" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------" -ForegroundColor Yellow

    #create the output folder
    $deviceFolder = Remove-InvalidFileNameChars -Name $deviceHostName
    $deviceFolder = $deviceFolder.Replace('.','-')

    $deviceDirectory = "$outputDirectory\$deviceFolder"
    $result = New-Directory $deviceDirectory

    #create the key file
    $devKeyFile = "$deviceDirectory\key.pem"
    $result = New-Key -outputfile $devKeyFile -passphrase $devicePassword

    #create the device csr config
    New-DeviceCsrConfig -outputDir $deviceDirectory

    #create the CSR
    New-DeviceCsr -outputDir $deviceDirectory

    #create the device Config
    New-DeviceConfig -outputDir $deviceDirectory

    #create the cert
    Write-Host "Generating cert.pem"
    $devCnfFile = "$deviceDirectory\ssl.cnf"
    $devCertFile = "$deviceDirectory\cert.pem"
    $devCsrFile = "$deviceDirectory\csr.pem"
    $intKeyFile = "$intDirectory\key.pem"
    $intCertFile = "$intDirectory\cert.pem"

    $result = &openssl ca `
        -batch `
        -passin pass:$intermediatePassword `
        -config $devCnfFile `
        -cert $intCertFile `
        -keyfile $intKeyFile `
        -outdir $deviceDirectory `
        -extensions server_cert `
        -days $sslsrvdays `
        -notext `
        -md $sslsha `
        -in $devCsrFile `
        -out $devCertFile

    if ((Test-Path -path $devCertFile) -eq $false){
        Write-Host "ERROR: Device Cert file not found - $devCertFile" -ForegroundColor Magenta
        PressAnyKeyToContinue
        return #continue with the loop
    }
    else {
        Write-Host "Device Cert Completed" -ForegroundColor Green
    }

    #create the srv_key.pem (unencrypted key)
    Write-Host "Generating srv_key.pem"
    $srvkeyFile = "$deviceDirectory\srv_key.pem"
    $result = &openssl rsa -passin pass:$devicePassword -in $devKeyFile -out $srvkeyFile
    if ((Test-Path -path $srvkeyFile) -eq $false){
        Write-Host "ERROR: srv_key.pem file not found - $srvkeyFile" -ForegroundColor Magenta
        PressAnyKeyToContinue
        return #continue with the loop
    }
    else {
        Write-Host "srv_key.pem Completed" -ForegroundColor Green
    }

    #create the pfx file
    Write-Host "Generating webserver_cert.pfx"
    $pfxFile = "$deviceDirectory\webserver_cert.pfx"
    $result = &openssl pkcs12 -export -passin pass:$devicePassword -passout pass:$exportPassword -out $pfxFile -inkey $devKeyFile -in $devCertFile
    if ((Test-Path -path $pfxFile) -eq $false){
        Write-Host "ERROR: webserver_cert.pfx file not found - $pfxFile" -ForegroundColor Magenta
        PressAnyKeyToContinue
        return #continue with the loop
    }
    else {
        Write-Host "webserver_cert.pfx Completed" -ForegroundColor Green
    }

    PressAnyKeyToContinue
    return;
}

############################################################################################
# Generate Device Certs for all in $devices
############################################################################################
function Write-DeviceCerts() {
    Clear-Host

    $devices | ForEach-Object {
        Write-DeviceCert($_)
    }
}

############################################################################################
# Prompt & Run Menu Choice
############################################################################################
function Read-Menu(){
    $choice=Read-Host -Prompt "Enter choice"
    switch($choice)
    {
        1 {
            Write-RootCert
            break;

        }
        2 {
            Write-IntermediateCert
            break;
        }
        3 {
            Write-DeviceCerts
            break;
        }
        4 {

            $confirm = Read-Host -Prompt "Are you sure [y]"
            if ($confirm -eq 'y'){
                Remove-Item -Path $outputDirectory -Force -Recurse
                Write-Host "Output Directory Deleted" -ForegroundColor Yellow
                PressAnyKeyToContinue
            }
            break;
        }
        5 {
            $StepThroughAll = $true
            Remove-Item -Path $outputDirectory -Force -Recurse
            Write-Host "Output Directory Deleted" -ForegroundColor Yellow
            Pause
            Write-RootCert
            Pause
            Write-IntermediateCert
            Pause
            Write-DeviceCerts
            Pause
        }
        6 {
            Write-Host ""
            $ip = Read-Host -Prompt "Enter Device Ip Address or Hostname"
            Write-DeviceCert -deviceHostName $ip
        }
        7 {
            Write-Host ""
            $ipstart = Read-Host -Prompt "Enter Device Starting Ip Address"
            if ($ipstart -match "^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"){
                [int] $qty = Read-Host -Prompt "Enter quantity"
                $ips = $ipstart -split "\."
                [int]$start = [int]$ips[3];
                [int]$end = $start + $qty - 1;
                for($i=$start; $i -le $end; $i++){
                    $ip = $ips[0]+'.'+$ips[1]+'.'+$ips[2]+'.'+$i
                    Write-DeviceCert $ip
                }
            }
            else{
                Write-Host "invalid ip address" -ForegroundColor Yellow
                PressAnyKeyToContinue
            }
        }
        x {
            Clear-Host
            Exit
        }

    }
}

############################################################################################
# Show Menu
############################################################################################
function Show-Menu(){
    Clear-Host
    Write-Host "===================================="
    Write-Host "Certificate Generator"
    Write-Host "Output Directory: $outputDirectory"
    Write-Host "===================================="
    Write-Host "1. Create Root Cert"
    Write-Host "2. Create Intermediate Cert"
    Write-Host "3. Create Devices' Cert"
    Write-Host "4. Clear output directory and contents"
    Write-Host "5. Do Step 4 then 1 through 3"
    Write-Host "6. Create a Cert for single device"
    Write-Host "7. Create Certs for a range of Ip"
    Write-Host "x. Exit";
    Read-Menu
}

############################################################################################
# MAIN
############################################################################################
Set-Location $PSScriptRoot
do {
    Show-Menu
}while($true)