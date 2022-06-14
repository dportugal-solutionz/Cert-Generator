# Cert-Generator
## Requires OpenSSL.exe
- Download it from https://slproweb.com/download/Win64OpenSSL-3_0_3.msi
- Add the openssl.exe installed into your computer's environment path.

This runs using powershell.


Ideas taken from Crestron COSU (https://github.com/Crestron/cosu)
modified to run on powershell
modified because COSU ran into too many errors and typos

## Modify the Powershell
```powershell
##########################################################################################
# CHANGE THESE SETTINGS
##########################################################################################
$devices=@(
    '10.50.99.*'
    ,'10.50.99.29'
    ,'10.50.99.30'
    ,'10.50.99.31'
    ,'10.50.99.32'
    ,'10.50.99.33'
    ,'10.50.99.34'
    ,'10.50.99.35'
    ,'10.50.99.36'
);

$sslCountry="US"
$sslState="California"
$sslLocality="Irvine"
$sslOrg="Edwards-Spinitar"
$sslOrgUnit="AV"
$sslEmail="av@edwards.com"
$sslIntermediateCN="EdwardsAV Signing Cert"
$sslRootCN="EdwardsAV Root Cert"

# Root CA passphrase
$rootPassword="spinitar"

# Intermediate Cert passphrase
$intermediatePassword="spinitar"

# Device Cert passphrase
$devicePassword="spinitar"

# Password for PFX export
$exportPassword="spinitar"
```

## Output Folder
- Root Folder
  - **cert.pem**       this is the root certificate, upload this to all devices. This is used to sign the intermediate certificate
  - **key.pem**        this is the encrypted key
  - **serial**         this is used by openssl when generating the cert, to keep track of certificates signed serial numbers
  - **index.txt**      this is used by openssl when generating the cert, to keep track of certificates signed 
  - **index.txt.attr** this is used by openssl when generating the cert
  - **ssl.cnf**        this is used by openssl when generating the cert, its a config file
- Intermediate Folder
  - **cert.pem**       this is the intermediate certificate, upload this to all devices. This is used to sign all the device certificates
  - **####.pem**       same as the cert.pem, automatic output by openssl
  - **chain.pem**      contains both the intermediate cert and the root cert
  - **csr.pem**        the certificate signing request
  - **key.pem**        the key used by the intermediate cert
  - **serial**         this is used by openssl when generating the cert, to keep track of certificates signed serial numbers
  - **index.txt**      this is used by openssl when generating the cert, to keep track of certificates signed 
  - **index.txt.attr** this is used by openssl when generating the cert
  - **ssl.cnf**        this is used by openssl when generating the cert, its a config file
- Device Folders
  - **cert.pem**            this is the device's certificate
  - **webserver_cert.pfx**  upload this as the device's webserver certificate
  - **####.pem**            same as the cert.pem, automatic output by openssl
  - **csr.pem**             the certificate signing request
  - **srv_key.pem**         unencrypted key
  - **ssl.cnf**        this is used by openssl when generating the cert, its a config file



## Crestron's Upload Instructions
```
rootCA_cert.cer may be added to your local certificate store as a trusted certificate

**********************************************
***** 3 Series Instructions
***** Firmware 1.601 or higher!!
**********************************************
Please place rootCA_cert.cer, intermediate_cert.cer,
srv_cert.cer and srv_key.pem
into the control system \User folder using SFTP

Execute the following commands

>del \sys\rootCA_cert.cer
>del \sys\srv_cert.cer
>del \sys\srv_key.pem

>del \ROMDISK\User\Cert\intermediate_cert.cer
>move \User\intermediate_cert.cer \ROMDISK\User\Cert\intermediate_cert.cer
>certificate add intermediate

>move User\rootCA_cert.cer \sys\rootCA_cert.cer
>move User\srv_cert.cer \sys
>move User\srv_key.pem \sys

>ssl ca

**********************************************
***** 4 Series Instructions
**********************************************
Please place rootCA_cert.cer, intermediate_cert.cer, srv_cert.cer and srv_key.pem
into the control system \Sys folder using SFTP

Execute the following commands

>del \romdisk\user\cert\intermediate.cer
>move sys\intermediate_cert.cer \romdisk\user\cert

>certificate add intermediate
>ssl ca


**********************************************
***** Other Devices (NVX, TSW, etc)
**********************************************
Please place rootCA_cert.cer, intermediate_cert.cer, webserver_cert.pfx
into the /User/Cert folder using SFTP (first remove any root_cert.cer that might be present)

>move /User/Cert/rootCA_cert.cer /User/Cert/root_cert.cer
>certificate add root
>certificate add intermediate
>certificate add webserver <password>
>ssl ca
```
