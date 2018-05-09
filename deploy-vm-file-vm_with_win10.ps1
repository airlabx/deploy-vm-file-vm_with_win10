# To Do
# Add Email notifications
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/send-mailmessage?view=powershell-5.1
# Enable RDP
# set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0
# Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
# set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 1   

# https://www.altaro.com/hyper-v/powershell-script-deploy-vms-configure-guest-os-one-go/
# https://charbelnemnom.com/2015/10/powershell-direct-deep-dive-hyperv-ws2016-powershell/ - try
# http://flemmingriis.com/create-mutiple-vm-from-powershell-in-hyper-v-2016-and-powershell-direct/ - try

# https://blogs.technet.microsoft.com/heyscriptingguy/2014/02/11/set-up-a-lab-with-windows-powershell-and-free-microsoft-software-part-2/ - for unattened file
# https://azurestack.blog/2015/05/imagine-what-you-could-do-with-powershell-direct/ - copy and try

# https://richardspowershellblog.wordpress.com/2016/02/22/ip-default-gateways-by-cmdlet/ - set gateway by powershell
# DISCLAIMER: There are no warranties or support provided for this script. Use at you're own discretion. Andy Syrewicze and/or Altaro Software are not liable for any
# damage or problems that misuse of this script may cause.
 
# Script is Written by Andy Syrewicze - Tech. Evangelist with Altaro Software and is free to use as needed within your organization.
 
# This Script is a deployment script, it will first copy a pre-prepared VHDX, and create a new VM with it based on the settings below. Then the script deploys Active
# Directory to then VM and then provisions a new forest. Once complete, another new VM is created in the same manner and it is provisioned as a file server and a new
# Share is created. 
 
# Assumptions
# Your Hyper-V host is running Windows Server 2016 TP5, Windows 10 or newer
# Your Target Guest OS is running Windows Server 2016 TP5, Windows 10 or newer
# You have a pre-created "Golden Image" VHDX that has been syspreped with the /generalize /oobe and /mode:VM switches.
#       
# You have created an answer file using the Windows SIM (System Image Manager) which is part of the Windows 10 ADK 
# https://developer.microsoft.com/en-us/windows/hardware/windows-assessment-deployment-kit#winADK 
# You have placed your answer file inside of the VHDX by mounting it in Windows 10 and then placing the unattend.xml file in the path
# C:\Windows\Panther
 
# First we set some targeting variables for the Host environment
# The $vSwitch Variable is the Name of the vSwitch you'd like the new VMs to use for network connectivity
# $VHDXPath is the root path of your VHDX storage 
$vSwitch = "Deployment Test"
$VHDXPath = "H:\gold\server-2016\" # location of gold image
$VMVHDPath = "H:\VM\" #where to put the VM's
$CompanyName = "aspera" 
$CompanyDomain = "airideas.net" # eg aspera[$CompanyName].airideas[$CompanyDomain].net
# default save location C:\ProgramData\Microsoft\Windows\Hyper-V\Virtual Machines
$Win10VHDXPath = "H:\gold\windows-10\"


# Global IP Settings Below
# NOTE: The cmdlets below reference the subnet mask bit for configuration of the IP Settings. Currently this script is configured for a standard
# Class C /24 subnet. 
$SubMaskBit = "24"
 
# Domain Controller Settings Below
# NOTE: As of the time of this writing, with 2016 TP5, the Domain Mode and Forest Mode are called "WinThreshold" I Expect this to change
# Once GA for 2016 is released. It will likely follow the previous naming scheme and be something like "win2016"
$DCVMName = "$CompanyName-dc1"
$DCIP = "10.20.1.10"
$DomainMode = "WinThreshold"; # https://docs.microsoft.com/en-us/powershell/module/addsdeployment/install-addsforest?view=win10-ps
$ForestMode = "WinThreshold";
$DomainName = "$CompanyName.$CompanyDomain";
$DSRMPWord = ConvertTo-SecureString -String "P@ssw0rd" -AsPlainText -Force
$NewAdminUserName = "TestAdmin"
$NewAdminUserPWord = ConvertTo-SecureString -String "P@ssw0rd" -AsPlainText -Force
 
# File Server Settings Below
$FSVMName = "$CompanyName-fs1"
$FSIP = "10.20.1.20"
$SharePath = "C:\ShareTest"
$FolderName = "Public"
$ShareName = "Public"

# Windows 10 Settings
$W10Name = "$CompanyName-win10-1"
$W10IP = "10.20.1.123"
 
# Then we setup some credentials to be called throughout the script
# NOTE: These are the credentials used within the guest VM.
# NOTE: If you only have a single image, you can likely get by with a single set of local credentials, instead of one for each
# workload.
$DCLocalUser = "$DCVMName\Administrator"
$DCLocalPWord = ConvertTo-SecureString -String "P@ssw0rd" -AsPlainText -Force
$DCLocalCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $DCLocalUser, $DCLocalPWord
 
# Below Credentials are used by the File Server VM for first login to be able to add the machine to the new Domain.
$FSLocalUser = "$FSVMName\administrator"
$FSLocalPWord = ConvertTo-SecureString -String "P@ssw0rd" -AsPlainText -Force
$FSLocalCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $FSLocalUser, $FSLocalPWord
 
# The below credentials are used by operations below once the domain controller virtual machine and the new domain are in place. These credentials should match the credentials
# used during the provisioning of the new domain. 
$DomainUser = "$DomainName\administrator"
$DomainPWord = ConvertTo-SecureString -String "P@ssw0rd" -AsPlainText -Force
$DomainCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $DomainUser, $DomainPWord 
 
############################# Command Execution Starts Below ###################################
 
 
# The below section Provisions and Configures the Domain Controller with the Variables defined above
 
# First we make a copy of the sysprepped "Gold Image" VHDX file. Also, note that a Unattend.XML file has been placed within the image as well.
# Write-Verbose "Copying Master VHDX and Deploying new VM with name $DCVMName" -Verbose 
# Copy-Item "$VHDXPath\MASTER.vhdx" "$VHDXPath\$DCVMNAME.vhdx"
# Write-Verbose "VHDX Copied, Building VM...." -Verbose
# New-VM -Name $DCVMName -MemoryStartupBytes 1GB -VHDPath "$VHDXPath\$DCVMName.vhdx" -Generation 2 -SwitchName $vSwitch
# Write-Verbose "VM Creation Completed. Starting VM [$DCVMName]" -Verbose
# Start-VM -Name $DCVMName
 
# Added to change the location of where the VM is made

Write-Verbose "Made folder for $DCVMName" -Verbose 
New-Item -Path "$VMVHDPath\$DCVMName\Virtual Hard Disks\" -ItemType directory | Out-Null
Write-Verbose "Copying Master VHDX and Deploying new VM with name $DCVMName" -Verbose 
Copy-Item "$VHDXPath\MASTER.vhdx" "$VMVHDPath\$DCVMName\Virtual Hard Disks\$DCVMName.vhdx"
Write-Verbose "VHDX Copied, Building VM...." -Verbose
New-VM -Name $DCVMName -MemoryStartupBytes 1GB -VHDPath "$VMVHDPath\$DCVMName\Virtual Hard Disks\$DCVMName.vhdx" -Path $VMVHDPath -Generation 2 -SwitchName $vSwitch
Set-VMProcessor $DCVMName -Count 2
Write-Verbose "VM Creation Completed. Starting VM [$DCVMName]" -Verbose
Start-VM -Name $DCVMName
 

# After the inital provisioning, we wait until PowerShell Direct is functional and working within the guest VM before moving on.
# Big thanks to Ben Armstrong for the below useful Wait code 
Write-Verbose "Waiting for PowerShell Direct to start on VM [$DCVMName]" -Verbose
   while ((Invoke-Command -VMName $DCVMName -Credential $DCLocalCredential {"Test"} -ea SilentlyContinue) -ne "Test") {Sleep -Seconds 1}
 
Write-Verbose "PowerShell Direct responding on VM [$DCVMName]. Moving On...." -Verbose
 
# Next we configure the networking for the new DC VM. 
# NOTE: that the host variables are passed through by making use of the param command along with the -ArgumentList Paramater at the end of
#       the ScriptBlock.
# NOTE: The InterfaceAlias value may be different for your gold image, so adjust accordingly.
# NOTE: InterfaceAlias can be found by making use of the Get-NetIPAddress Cmdlet  
Invoke-Command -VMName $DCVMName -Credential $DCLocalCredential -ScriptBlock {
    param ($DCVMName, $DCIP, $SubMaskBit, $DFGW)
    New-NetIPAddress -IPAddress "$DCIP" -InterfaceAlias "Ethernet 2" -PrefixLength "$SubMaskBit" | Out-Null
    New-NetRoute -InterfaceAlias "Ethernet 2" -DestinationPrefix "0.0.0.0/0" -NextHop "10.20.0.1" | Out-Null
    $DCEffectiveIP = Get-NetIPAddress -InterfaceAlias "Ethernet 2" | Select-Object IPAddress
    Write-Verbose "Assigned IPv4 and IPv6 IPs for VM [$DCVMName] are as follows" -Verbose 
    Write-Host $DCEffectiveIP | Format-List
    Write-Verbose "Updating Hostname for VM [$DCVMName]" -Verbose
    Rename-Computer -NewName "$DCVMName"
    } -ArgumentList $DCVMName, $DCIP, $SubMaskBit, $DFGW
 
Write-Verbose "Rebooting VM [$DCVMName] for hostname change to take effect" -Verbose
Stop-VM -Name $DCVMName
Start-VM -Name $DCVMName
 
Write-Verbose "Waiting for PowerShell Direct to start on VM [$DCVMName]" -Verbose
   while ((Invoke-Command -VMName $DCVMName -Credential $DomainCredential {"Test"} -ea SilentlyContinue) -ne "Test") {Sleep -Seconds 1}
 
Write-Verbose "PowerShell Direct responding on VM [$DCVMName]. Moving On...." -Verbose
 
# Next we'll proceed by installing the Active Directory Role and then configuring the machine as a new DC in a new AD Forest
Invoke-Command -VMName $DCVMName -Credential $DCLocalCredential -ScriptBlock {
    param ($DCVMName, $DomainMode, $ForestMode, $DomainName, $DSRMPWord) 
    Write-Verbose "Installing Active Directory Services on VM [$DCVMName]" -Verbose
    Install-WindowsFeature -Name "AD-Domain-Services" -IncludeManagementTools
    Write-Verbose "Configuring New Domain with Name [$DomainName] on VM [$DCVMName]" -Verbose
    Install-ADDSForest -ForestMode $ForestMode -DomainMode $DomainMode -DomainName $DomainName -InstallDns -NoDNSonNetwork -SafeModeAdministratorPassword $DSRMPWord -Force -NoRebootOnCompletion
    } -ArgumentList $DCVMName, $DomainMode, $ForestMode, $DomainName, $DSRMPWord
 
Write-Verbose "Rebooting VM [$DCVMName] to complete installation of new AD Forest" -Verbose
Stop-VM -Name $DCVMName
Start-VM -Name $DCVMName
 
Write-Verbose "Waiting for PowerShell Direct to start on VM [$DCVMName]" -Verbose
   while ((Invoke-Command -VMName $DCVMName -Credential $DomainCredential {"Test"} -ea SilentlyContinue) -ne "Test") {Sleep -Seconds 1}
 
Write-Verbose "PowerShell Direct responding on VM [$DCVMName]. Moving On...." -Verbose
 
Write-Verbose "DC Provisioning Complete!!!!" -Verbose
 
# We're going to setup an AD Administrative user based on the variables above that will have access to the file share we create below
# Note that we do this in a loop as it will take some time for AD to be ready inside of the new DC VM. As such this command will execute
# Until it is successful, and as a result, we know that AD is ready for the rest of the script. 
 
Write-Verbose "Creating new Administrative User within Domain [$DomainName] That will have access to Share [$ShareName] on VM [$FSVMName]" -Verbose
 
Invoke-Command -VMName $DCVMName -Credential $DomainCredential -ScriptBlock {
    param ($NewAdminUserName, $NewAdminUserPWord)
    Write-Verbose "Waiting for AD Web Services to be in a running state" -Verbose
    $ADWebSvc = Get-Service ADWS | Select-Object *
    while($ADWebSvc.Status -ne "Running")
            {
            Start-Sleep -Seconds 1
            }
    Do {
    Start-Sleep -Seconds 30
    Write-Verbose "Waiting for AD to be Ready for User Creation" -Verbose
    New-ADUser -Name "$NewAdminUserName" -AccountPassword $NewAdminUserPWord
    Enable-ADAccount -Identity "$NewAdminUserName"
    $ADReadyCheck = Get-ADUser -Identity $NewAdminUserName
    }
    Until ($ADReadyCheck.Enabled -eq "True")
    Add-ADGroupMember -Identity "Domain Admins" -Members "$NewAdminUserName"
    } -ArgumentList $NewAdminUserName, $NewAdminUserPWord
 
Write-Verbose "User [$NewAdminUserName] Created." -Verbose
 
 
 
 
# The below section is used to Provision a new file server VM, add it to the new domain, and configure a basic share.
 
# First we make a copy of the sysprepped "Gold Image" VHDX file. Also, note that a Unattend.XML file has been placed within the image as well.
# Write-Verbose "Copying Master VHDX and Deploying new VM with name [$FSVMName]" -Verbose 
# Copy-Item "$VHDXPath\MASTER.vhdx" "$VHDXPath\$FSVMNAME.vhdx"
# Write-Verbose "VHDX Copied, Building VM...." -Verbose
# New-VM -Name $FSVMName -MemoryStartupBytes 1GB -VHDPath "$VHDXPath\$FSVMName.vhdx" -Generation 2 -SwitchName $vSwitch
# Write-Verbose "VM Creation Completed. Starting VM [$FSVMName]" -Verbose
# Start-VM -Name $FSVMName

# Added to change the location of where the VM is made
Write-Verbose "Copying Master VHDX and Deploying new VM with name [$FSVMName]" -Verbose 
New-Item -Path "$VMVHDPath\$FSVMName\Virtual Hard Disks\" -ItemType directory 
Copy-Item "$VHDXPath\MASTER.vhdx" "$VMVHDPath\$FSVMName\Virtual Hard Disks\$FSVMName.vhdx"
Write-Verbose "VHDX Copied, Building VM...." -Verbose
New-VM -Name $FSVMName -MemoryStartupBytes 2GB -VHDPath "$VMVHDPath\$FSVMName\Virtual Hard Disks\$FSVMName.vhdx" -Path $VMVHDPath -Generation 2 -SwitchName $vSwitch
Set-VMProcessor $FSVMName -Count 2 
Write-Verbose "VM Creation Completed. Starting VM [$FSVMName]" -Verbose
Start-VM -Name $FSVMName
 
 
# After the inital provisioning, we wait until the PowerShell Direct is functional and working within the guest VM before moving on.
# Big thanks to Ben Armstrong for the below useful Wait code 
Write-Verbose "Waiting for PowerShell Direct to start on VM [$FSVMName]" -Verbose
   while ((Invoke-Command -VMName $FSVMName -Credential $FSLocalCredential {"Test"} -ea SilentlyContinue) -ne "Test") {Sleep -Seconds 1}
 
Write-Verbose "PowerShell Direct responding on VM [$FSVMName]. Moving On...." -Verbose
 
 
# Next we configure the networking for the new FS VM. 
# NOTE: that the host variables are passed through by makinguse of the param command along with the -ArgumentList Paramater at the end of
#       the ScriptBlock.
# NOTE: The InterfaceAlias value may be different for your gold image, so adjust accordingly.  
Invoke-Command -VMName $FSVMName -Credential $FSLocalCredential -ScriptBlock {
    param ($FSVMName, $FSIP, $SubMaskBit, $DFGW, $DCVMName, $DCIP)
    New-NetIPAddress -IPAddress "$FSIP" -InterfaceAlias "Ethernet 2" -PrefixLength "$SubMaskBit" | Out-Null
    New-NetRoute -InterfaceAlias "Ethernet 2" -DestinationPrefix "0.0.0.0/0" -NextHop "10.20.0.1"  | Out-Null
    $FSEffectiveIP = Get-NetIPAddress -InterfaceAlias "Ethernet 2" | Select-Object IPAddress
    Write-Verbose "Assigned IPv4 and IPv6 IPs for VM [$FSVMName] are as follows" -Verbose 
    Write-Host $FSEffectiveIP | Format-List
    Write-Verbose "Setting DNS Source to [$DCVMName] with IP [$DCIP]" -Verbose
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet 2" -ServerAddresses "$DCIP"
    Write-Verbose "Updating Hostname for VM [$FSVMName]" -Verbose
    Rename-Computer -NewName "$FSVMName"
    } -ArgumentList $FSVMName, $FSIP, $SubMaskBit, $DFGW, $DCVMName, $DCIP
 
Write-Verbose "Rebooting VM [$FSVMName] for hostname change to take effect" -Verbose
Stop-VM -Name $FSVMName
Start-VM -Name $FSVMName
 
Write-Verbose "Waiting for PowerShell Direct to start on VM [$FSVMName]" -Verbose
   while ((Invoke-Command -VMName $FSVMName -Credential $FSLocalCredential {"Test"} -ea SilentlyContinue) -ne "Test") {Sleep -Seconds 1}
 
Write-Verbose "PowerShell Direct responding on VM [$FSVMName]. Moving On...." -Verbose
 
# The below Adds the File Server VM to the newly Created Domain. 
 
Write-Verbose "Adding VM [$FSVMName] to domain [$DomainName]" -Verbose
 
Invoke-Command -VMName $FSVMName -Credential $FSLocalCredential -ScriptBlock {
    param ($DomainName, $DomainCredential)
    Add-Computer -DomainName $DomainName -Credential $DomainCredential
    } -ArgumentList $DomainName, $DomainCredential
 
Write-Verbose "Initiating Reboot of VM [$FSVMName] to complete domain join to domain [$DomainName]" -Verbose
Stop-VM -Name $FSVMName
Start-VM -Name $FSVMName
 
Write-Verbose "Waiting for PowerShell Direct to start on VM [$FSVMName]" -Verbose
   while ((Invoke-Command -VMName $FSVMName -Credential $DomainCredential {"Test"} -ea SilentlyContinue) -ne "Test") {Sleep -Seconds 1}
 
Write-Verbose "PowerShell Direct responding on VM [$FSVMName]. Moving On...." -Verbose
 
# Now we install the File Server Role and Create the Share
 
Write-Verbose "Installing File-Server Role on VM [$FSVMName]." -Verbose
 
Invoke-Command -VMName $FSVMName -Credential $DomainCredential -ScriptBlock {
    param ($SharePath, $FolderName, $ShareName, $DomainName, $NewAdminUserName)
    Install-WindowsFeature -Name "FS-FileServer" -IncludeManagementTools
    Write-Verbose "Creating File Share [$ShareName] at path [$SharePath\$Foldername]." -Verbose
    New-Item -Path $SharePath -Name $FolderName -ItemType "Directory";
    New-SmbShare -Name "$ShareName" -Path "$SharePath\$FolderName" -FullAccess "$DomainName\$NewAdminUserName"
    } -ArgumentList $SharePath, $FolderName, $ShareName, $DomainName, $NewAdminUserName

# ==================
# Added to make a win10 VM

Write-Verbose "Copying Master VHDX and Deploying new VM with name [$W10Name]" -Verbose 
New-Item -Path "$VMVHDPath\$W10Name\Virtual Hard Disks\" -ItemType directory 
Copy-Item "$Win10VHDXPath\MASTER.vhdx" "$VMVHDPath\$W10Name\Virtual Hard Disks\$W10Name.vhdx"
Write-Verbose "VHDX Copied, Building VM...." -Verbose
New-VM -Name $W10Name -MemoryStartupBytes 2GB -VHDPath "$VMVHDPath\$W10Name\Virtual Hard Disks\$W10Name.vhdx" -Path $VMVHDPath -Generation 2 -SwitchName $vSwitch
Set-VMProcessor $W10Name -Count 2 
Write-Verbose "VM Creation Completed. Starting VM [$W10Name]" -Verbose
Start-VM -Name $W10Name
 

# After the inital provisioning, we wait until the PowerShell Direct is functional and working within the guest VM before moving on.
# Big thanks to Ben Armstrong for the below useful Wait code 
Write-Verbose "Waiting for PowerShell Direct to start on VM [$W10Name]" -Verbose
   while ((Invoke-Command -VMName $W10Name -Credential $FSLocalCredential {"Test"} -ea SilentlyContinue) -ne "Test") {Sleep -Seconds 1}
 
Write-Verbose "PowerShell Direct responding on VM [$W10Name]. Moving On...." -Verbose
 
 
# Next we configure the networking for the new FS VM. 
# NOTE: that the host variables are passed through by makinguse of the param command along with the -ArgumentList Paramater at the end of
#       the ScriptBlock.
# NOTE: The InterfaceAlias value may be different for your gold image, so adjust accordingly.  


Invoke-Command -VMName $W10Name -Credential $FSLocalCredential -ScriptBlock {
    param ($W10Name, $W10IP, $SubMaskBit, $DFGW, $DCVMName, $DCIP)
    New-NetIPAddress -IPAddress "$W10IP" -InterfaceAlias "Ethernet 2" -PrefixLength "$SubMaskBit" | Out-Null
    New-NetRoute -InterfaceAlias "Ethernet 2" -DestinationPrefix "0.0.0.0/0" -NextHop "10.20.0.1"  | Out-Null
    $W10EffectiveIP = Get-NetIPAddress -InterfaceAlias "Ethernet 2" | Select-Object IPAddress
    Write-Verbose "Assigned IPv4 and IPv6 IPs for VM [$W10Name] are as follows" -Verbose 
    Write-Host $W10EffectiveIP | Format-List
    Write-Verbose "Setting DNS Source to [$DCVMName] with IP [$DCIP]" -Verbose
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet 2" -ServerAddresses "$DCIP"
    Write-Verbose "Updating Hostname for VM [$W10Name]" -Verbose
    Rename-Computer -NewName "$W10Name"
    } -ArgumentList $W10Name, $W10IP, $SubMaskBit, $DFGW, $DCVMName, $DCIP
 
Write-Verbose "Rebooting VM [$W10Name] for hostname change to take effect" -Verbose
Stop-VM -Name $W10Name
Start-VM -Name $W10Name
 
Write-Verbose "Waiting for PowerShell Direct to start on VM [$W10Name]" -Verbose
   while ((Invoke-Command -VMName $W10Name -Credential $FSLocalCredential {"Test"} -ea SilentlyContinue) -ne "Test") {Sleep -Seconds 1}
 
Write-Verbose "PowerShell Direct responding on VM [$W10Name]. Moving On...." -Verbose

# The below Adds the File Server VM to the newly Created Domain. 
 
Write-Verbose "Adding VM [$W10Name] to domain [$DomainName]" -Verbose
 
Invoke-Command -VMName $W10Name -Credential $FSLocalCredential -ScriptBlock {
    param ($DomainName, $DomainCredential)
    Add-Computer -DomainName $DomainName -Credential $DomainCredential
    } -ArgumentList $DomainName, $DomainCredential
 
Write-Verbose "Initiating Reboot of VM [$W10Name] to complete domain join to domain [$DomainName]" -Verbose
Stop-VM -Name $W10Name
Start-VM -Name $W10Name

Write-Verbose "Environment Setup Complete. End of Script" -Verbose

# END OF SCRIPT