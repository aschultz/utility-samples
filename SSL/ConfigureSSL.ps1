#Requires -version 4
#Requires -RunAsAdministrator

################################################################################
#
# Resources
#
################################################################################
#
# https://support.microsoft.com/en-us/kb/245030
# https://msdn.microsoft.com/en-us/library/windows/desktop/aa374757(v=vs.85).aspx
#
# https://github.com/qinxgit/azure-ssl-configure/blob/master/AzureCloudServiceSample/WebRoleSample/Startup/SSLConfigure.ps1
#
# https://www.hass.de/content/setup-your-iis-ssl-perfect-forward-secrecy-and-tls-12
# https://wiki.mozilla.org/Security/Server_Side_TLS
# https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices#23-use-secure-cipher-suites
# 

################################################################################
#
#    Helpers
#
################################################################################

function Set-CryptoSetting($Key, $Name, $Type, $Value) {
        
    $Key = $Key.Replace('HKLM:\','HKEY_LOCAL_MACHINE\').Replace('HKCU:\','HKEY_CURRENT_USER\')
        
    $oldValue = [Microsoft.Win32.Registry]::GetValue($Key, $Name, $null)

    if(($oldValue -eq $null) -or ($oldValue -ne $Value))
    {
        $kind = [Microsoft.Win32.RegistryValueKind]$Type
        [Microsoft.Win32.Registry]::SetValue($Key, $Name, $Value, $kind)
        return 1
    }
    return 0
}

function Configure-Protocol($Protocol, [switch]$Enable, [switch]$Disable) {

    $key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\" + $Protocol
    $result = 0
    if($Disable)
    {
        $result += Set-CryptoSetting "$key\Server" 'Enabled' 'Dword' 0
        $result += Set-CryptoSetting "$key\Server" 'DisabledByDefault' 'Dword' 1
        $result += Set-CryptoSetting "$key\Client" 'Enabled' 'Dword' 0
        $result += Set-CryptoSetting "$key\Client" 'DisabledByDefault' 'Dword' 1
        Write-Host "Protocol $Protocol has been disabled"
    } 
    elseif($Enable)
    {
        $result += Set-CryptoSetting "$key\Server" 'Enabled' 'Dword' 0xffffffff
        $result += Set-CryptoSetting "$key\Server" 'DisabledByDefault' 'Dword' 0
        $result += Set-CryptoSetting "$key\Client" 'Enabled' 'Dword' 1
        $result += Set-CryptoSetting "$key\Client" 'DisabledByDefault' 'Dword' 0
        Write-Host "Protocol $Protocol has been enabled"
    }
    return $result
}

function Configure-Cipher($Cipher, [switch]$Enable, [switch]$Disable) {

    $key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\" + $Cipher

    $result = 0
    if($Disable)
    {
        $result += Set-CryptoSetting $key 'Enabled' 'Dword' 0
        Write-Host "Cipher $cipher has been disabled"
    } 
    elseif($Enable)
    {
        $result += Set-CryptoSetting $key 'Enabled' 'Dword' 0xffffffff
        Write-Host "Cipher $cipher has been enabled"
    }
    return $result
}

function Configure-Hash($Hash, [switch]$Enable, [switch]$Disable) {

    $key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\" + $Hash
    
    $result = 0
    if($Disable)
    {
        $result += Set-CryptoSetting $key 'Enabled' 'Dword' 0
        Write-Host "Hash $Hash has been disabled"
    } 
    elseif($Enable)
    {
        $result += Set-CryptoSetting $key 'Enabled' 'Dword' 0xffffffff
        Write-Host "Hash $Hash has been enabled"
    }
    return $result
}

function Configure-KeyExchange($Algorithm, [switch]$Enable, [switch]$Disable) {

    $key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\" + $Algorithm
    
    $result = 0
    if($Disable)
    {
        $result += Set-CryptoSetting $key 'Enabled' 'Dword' 0
        Write-Host "KeyExchangeAlgorithm $Algorithm has been disabled"
    } 
    elseif($Enable)
    {
        $result += Set-CryptoSetting $key 'Enabled' 'Dword' 0xffffffff
        Write-Host "KeyExchangeAlgorithm $Algorithm has been enabled"
    }
    return $result
}

function Configure-CipherSuites($CipherSuites)
{
    $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'

    $result = Set-CryptoSetting $key 'Functions' 'String' ($CipherSuites -join ',')
    Write-Host "Cipher suite set to:"
    $CipherSuites | Format-List | Out-String | Write-Host
    return $result
}


################################################################################
#
#    Configure protocols
#
################################################################################

$badProtocols = @(
    'Multi-Protocol Unified Hello',
    'PCT 1.0'
    'SSL 2.0'
    'SSL 3.0')

$goodProtocols = @(
    'TLS 1.0',
    'TLS 1.1',
    'TLS 1.2'
)

################################################################################
#
#    Configure ciphers
#
################################################################################

$badCiphers = @(
    'NULL',
    'RC2 40/128',
    'RC2 56/128',
    'RC2 128/128',
    'RC4 40/128',
    'RC4 56/128',
    'RC4 64/128',
    'DES 56/56'
)

$goodCiphers = @(
    'AES 128/128',
    'AES 256/256',
    'Triple DES 168'
)

################################################################################
#
#    Configure hashes
#
################################################################################

$badHashes = @(
  'MD5'
)

$goodHashes = @(
  'SHA',
  'SHA256',
  'SHA384',
  'SHA512'
)

################################################################################
#
#    Configure key exchange
#
################################################################################

$badKeyExchange = @(

)

$goodKeyExchange = @(
  'Diffie-Hellman',
  'ECDH',
  'PKCS'
)

################################################################################
#
#    Configure cipher suites. Order matters.
#
################################################################################

$osVersion = [Environment]::OSVersion.Version

if($osVersion -lt [System.Version]'10.0')
{
    # Older OS versions included ECC curve in the cipher suite name, hence the separate list here

    $cipherList = @(
        
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P512',   # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256',

        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521',   # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384',
        
                                                          # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 unavailable
                                                          # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 unavailable


        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521',   # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256',

        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521',   # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384',        

        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521',     # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256',

        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521',     # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256',

        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P521',      # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256',

        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P521',      # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256'

        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521'         # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256'

        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521',        # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256',

        'TLS_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_RSA_WITH_AES_128_GCM_SHA256',
        'TLS_RSA_WITH_AES_256_CBC_SHA256',
        'TLS_RSA_WITH_AES_128_CBC_SHA256',
        'TLS_RSA_WITH_AES_256_CBC_SHA',
        'TLS_RSA_WITH_AES_128_CBC_SHA'
    )
}
else
{
    $cipherList = @(
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',               
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',        
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
        'TLS_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_RSA_WITH_AES_128_GCM_SHA256',
        'TLS_RSA_WITH_AES_256_CBC_SHA256',
        'TLS_RSA_WITH_AES_128_CBC_SHA256',
        'TLS_RSA_WITH_AES_256_CBC_SHA',
        'TLS_RSA_WITH_AES_128_CBC_SHA'
    )
}

################################################################################
#
#    Execution
#
################################################################################

Write-Warning "################################################################################"
Write-Warning "" 
Write-Warning " SSL CONFIG"
Write-Warning ""
Write-Warning "################################################################################"
Write-Warning ""
Write-Warning "This script will configure machine-wide settings to ensure SSL connections adhere"
Write-Warning "to best practices. A reboot will be automatically scheduled if necessary."
Write-Warning ""
Write-Warning "Are  you sure you want to continue?"
Write-Warning ""
[void](Read-Host "Press enter to continue and CTRL-C to exit")

$reboot = 0
$badProtocols     | % { Configure-Protocol -Protocol $_ -Disable } | % { $reboot += $_ }
$goodProtocols    | % { Configure-Protocol -Protocol $_ -Enable } | % { $reboot += $_ }
$badCiphers       | % { Configure-Cipher -Cipher $_ -Disable } | % { $reboot += $_ }
$goodCiphers      | % { Configure-Cipher -Cipher $_ -Enable } | % { $reboot += $_ }
$badHashes        | % { Configure-Hash -Hash $_ -Disable } | % { $reboot += $_ }
$goodHashes       | % { Configure-Hash -Hash $_ -Enable } | % { $reboot += $_ }
$badKeyExchange   | % { Configure-KeyExchange -Algorithm $_ -Disable } | % { $reboot += $_ }
$goodKeyExchange  | % { Configure-KeyExchange -Algorithm $_ -Enable } | % { $reboot += $_ }
$reboot += Configure-CipherSuites $cipherList


if($reboot -ne 0) {
    
    Write-Warning "A reboot is needed"
    [void](Read-Host "Press enter to reboot")
    #shutdown.exe /r /t 5 /c "Crypto settings changed" /f /d p:2:4
}