# Deploy a DC a File server and Windows 10 VM

Setup a quick Lab with a few Windows Server 2016 server and a Windows 10 VM on Hyper-V

### Prerequisites

- Syspreped Windows Server 2016 and Windows 10 Image 
	- syspreps.exe /oobe /generalize /shutdown /mode:vm
- Hyper-V test network name

### Running
Check the variable paths and the execution policy and run the Powerhsell deploy-vm-file-vm_with_win10.ps1.

```
PS C:\Users\User> .\deploy-vm-file-vm_with_win10.ps1
```

## Acknowledgments

* Adapted from  Andy Syrewicze awesome [post](https://www.altaro.com/hyper-v/powershell-script-deploy-vms-configure-guest-os-one-go/) on scripting a lab.
* Also used [Win10 Forums](https://www.tenforums.com/tutorials/96683-create-media-automated-unattended-install-windows-10-a.html) for unattended file creation.