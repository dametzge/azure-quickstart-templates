[cmdletbinding()]
param (
    [string]$NIC1IPAddress,
    [string]$NIC2IPAddress,
    [string]$GhostedSubnetPrefix,
    [string]$VirtualNetworkPrefix
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module Subnet -Force

New-VMSwitch -Name "NestedSwitch" -SwitchType Internal

$NIC1IP = Get-NetIPAddress | Where-Object -Property AddressFamily -EQ IPv4 | Where-Object -Property IPAddress -EQ $NIC1IPAddress
$NIC2IP = Get-NetIPAddress | Where-Object -Property AddressFamily -EQ IPv4 | Where-Object -Property IPAddress -EQ $NIC2IPAddress

$NATSubnet = Get-Subnet -IP $NIC1IP.IPAddress -MaskBits $NIC1IP.PrefixLength
$HyperVSubnet = Get-Subnet -IP $NIC2IP.IPAddress -MaskBits $NIC2IP.PrefixLength
$NestedSubnet = Get-Subnet $GhostedSubnetPrefix
$VirtualNetwork = Get-Subnet $VirtualNetworkPrefix

New-NetIPAddress -IPAddress $NestedSubnet.HostAddresses[0] -PrefixLength $NestedSubnet.MaskBits -InterfaceAlias "vEthernet (NestedSwitch)"
New-NetNat -Name "NestedSwitch" -InternalIPInterfaceAddressPrefix "$GhostedSubnetPrefix"

Add-DhcpServerv4Scope -Name "Nested VMs" -StartRange $NestedSubnet.HostAddresses[1] -EndRange $NestedSubnet.HostAddresses[-1] -SubnetMask $NestedSubnet.SubnetMask
Set-DhcpServerv4OptionValue -DnsServer 168.63.129.16 -Router $NestedSubnet.HostAddresses[0]

Install-RemoteAccess -VpnType RoutingOnly
cmd.exe /c "netsh routing ip nat install"
cmd.exe /c "netsh routing ip nat add interface ""$($NIC1IP.InterfaceAlias)"""
cmd.exe /c "netsh routing ip add persistentroute dest=$($NatSubnet.NetworkAddress) mask=$($NATSubnet.SubnetMask) name=""$($NIC1IP.InterfaceAlias)"" nhop=$($NATSubnet.HostAddresses[0])"
cmd.exe /c "netsh routing ip add persistentroute dest=$($VirtualNetwork.NetworkAddress) mask=$($VirtualNetwork.SubnetMask) name=""$($NIC2IP.InterfaceAlias)"" nhop=$($HyperVSubnet.HostAddresses[0])"

Get-Disk | Where-Object -Property PartitionStyle -EQ "RAW" | Initialize-Disk -PartitionStyle GPT -PassThru | New-Volume -FileSystem NTFS -AllocationUnitSize 65536 -DriveLetter F -FriendlyName "Hyper-V"

New-Item -Path "C:\" -Name "SCT" -ItemType Directory
New-Item -Path "C:\" -Name "ISO" -ItemType Directory

$url1 = "https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip"
$url2 = "https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/Windows%2010%20Version%201809%20and%20Windows%20Server%202019%20Security%20Baseline.zip"
# $url3 = "https://software-download.microsoft.com/download/pr/17763.737.190906-2324.rs5_release_svc_refresh_SERVER_EVAL_x64FRE_en-us_1.iso"
$output1 = "C:\SCT\LGPO.zip"
$output2 = "C:\SCT\Baseline2019.zip"
# $output3 = "C:\ISO\WindowsServer2019ENUS.iso"

Invoke-WebRequest -Uri $url1 -OutFile $output1
Invoke-WebRequest -Uri $url2 -OutFile $output2

Expand-Archive -Path C:\SCT\LGPO.zip -DestinationPath C:\SCT\LGPO -Verbose
Remove-Item -Path C:\SCT\LGPO.zip -Force
Expand-Archive -Path C:\SCT\Baseline2019.zip -DestinationPath C:\SCT\Baseline2019 -Verbose
Remove-Item -Path C:\SCT\Baseline2019.zip -Force

Copy-Item "C:\SCT\LGPO\LGPO_30\LGPO.exe" -Destination "C:\SCT\Baseline2019\Local_Script\Tools"

Set-ExecutionPolicy RemoteSigned

cd C:\SCT\Baseline2019\Local_Script\

.\BaselineLocalInstall.ps1 -WS2019NonDomainJoined

# Invoke-WebRequest -Uri $url3 -OutFile $output3

$Switch = "ADRes"
$RootVM1 = "ROOTDC01"
$RootVM2 = "ROOTDC02"
$ChildVM1 = "CHILDDC01"
$ChildVM2 = "CHILDDC02"
$VMPath = "F:\Hyper-V\"

New-VMSwitch -Name $Switch -SwitchType Internal
New-VM -Name $RootVM1 -MemoryStartupBytes 6GB -NewVHDPath $VMPath\$RootVM1\$RootVM1.vhdx -NewVHDSizeBytes 100GB -BootDevice CD -SwitchName $Switch
New-VM -Name $RootVM2 -MemoryStartupBytes 6GB -NewVHDPath $VMPath\$RootVM2\$RootVM2.vhdx -NewVHDSizeBytes 100GB -BootDevice CD -SwitchName $Switch
New-VM -Name $ChildVM1 -MemoryStartupBytes 6GB -NewVHDPath $VMPath\$ChildVM1\$ChildVM1.vhdx -NewVHDSizeBytes 100GB -BootDevice CD -SwitchName $Switch
New-VM -Name $ChildVM2 -MemoryStartupBytes 6GB -NewVHDPath $VMPath\$ChildVM2\$ChildVM2.vhdx -NewVHDSizeBytes 100GB -BootDevice CD -SwitchName $Switch

