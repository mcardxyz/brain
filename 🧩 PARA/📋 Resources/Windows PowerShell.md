---
tags:
  - windows/powershell
  - powershell
  - "#windows"
date: 2026-02-25
---
# Windows PowerShell
From the official Microsoft [page](https://learn.microsoft.com/en-us/powershell/scripting/overview?view=powershell-7.4): _“PowerShell is a cross-platform task automation solution made up of a command-line shell, a scripting language, and a configuration management framework.”_

___
## Basics

**Discovering what commands one can use**
```powershell
Get-Command

# Filter by type
Get-Command -CommandType "Function"
```

**Detailed information about cmdlets**
```powershell
Get-Help Get-Command
```

**Lists all aliases available**
```powershell
Get-Alias
```

**Where to Find and Download Cmdlets**
We can extend PowerShell functionality by downloading additional cmdlets from online repositories.
```powershell
# Search for modules
Find-Module -Name "PowerShell*" 

# Install a module
Install-Module -Name "PowerShellGet"
```

The `Invoke-Command` is essential for executing commands on remote systems.
```powershell
Invoke-Command
```


___
## Navigating and Working with Files

**Lists the files and directories in a location specified with the `-Path` parameter**
```powershell
Get-ChildItem
```

**Navigate to a different directory**
```powershell
Set-Location -Path ".\Documents"
```

**Create a new item**
```powershell
New-Item -Path ".\captain-cabin\captain-wardrobe" -ItemType "Directory"
```

**Remove an item**
Works for both directories and files.
```powershell
Remove-Item -Path ".\captain-cabin\captain-wardrobe\captain-boots.txt"
```

**Copy or Move files**
```powershell
# Copy
Copy-Item -Path .\captain-cabin\captain-hat.txt -Destination .\captain-cabin\captain-hat2.txt

# Move
Move-Item -Path .\captain-cabin\captain-hat.txt -Destination .\captain-cabin\captain-hat2.txt
```

**Display contents of a file**
```powershell
Get-Content -Path ".\captain-hat.txt"
```



___
## Piping, Filtering and Sorting Data

**Get a list of files in a directory and sort them by size**
```powershell
Get-ChildItem | Sort-Object Length
```

**Filter objects based on specified conditions**
```powershell
Get-ChildItem | Where-Object -Property "Extension" -eq ".txt" 
```

**Conditions:**
`-ne`: "not equal"
`-gt`: "greater than"
`-ge`: "greater than or equal to"
`-lt`: "less than"
`-le`: "less than or equal to"

**Filter by selecting properties that match a specified pattern**
```powershell
Get-ChildItem | Where-Object -Property "Name" -like "ship*"  
```

**Select specific properties from objects or limit the number of objects returned**
```powershell
Get-ChildItem | Select-Object Name,Length 
```

**Search for text patterns within files, similar to `grep`**
```powershell
Select-String -Path ".\captain-hat.txt" -Pattern "hat" 
```



___
## System and Network Information

**Retrieve comprehensive system information**
```powershell
Get-ComputerInfo
```

**List all local user accounts**
```powershell
Get-LocalUser
```

**Retrieve Network Configuration**
Detailed information about the network interfaces on the system, including IP addresses, DNS servers, and gateway configurations
```powershell
Get-LocalUser
```
In case we need specific details about the IP addresses assigned to the network interfaces:
```powershell
Get-NetIPAddress
```



____
## Real-Time System Analysis

**Show current running processes**
```powershell
Get-Process
```

**Show information about the status of services**
```powershell
Get-Service
```

**Monitor active network connections**
```powershell
Get-NetTCPConnection
```



____
## Others

**Generate file hash**
```powershell
Get-FileHash -Path .\ship-flag.txt
```

**View the Alternate Data Streams (ADS)**
```powershell
Get-Item -Path "C:\House\house_log.txt" -Stream *
```
