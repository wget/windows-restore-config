<#
.SYNOPSIS

A PowerShell script allowing to reset the configuration of a computer to the needs of a power user.

.DESCRIPTION

As a developer or a power user, we often need a bunch of tools to work in a consistent way. Reinstalling a computer requires us to reapply all our advanced configuration. This script aims at automating this.

.PARAMETER with-chocolatey
Install and use chocolatey to install further packages. If you install a package and the latter requires chocolatey but you didn't specify to use cocolatey, the package will not be installed.

.PARAMETER with-chococolatey-apps
Install some useful apps available as chocolatey packages: 

	choco install 7zip bleachbit chocolateygui conemu filezilla firefox gimp googlechrome hashcheck inkscape libreoffice mpv nextcloud-client notepadplusplus python qbittorrent sdio --yes
	
.PARAMETER with-rdp
Enable rdp access to this computer (if supported by the Windows license).

.PARAMETER with-posh-upgrade
Force the installation of the latest Powershell version available.

.PARAMETER with-all
Enable all the flags except those explicitly forced to false in the command prompt.

.LINK
http://github.com/wget/windows-restore-config

#>

param(
	[switch]$with-chocolatey = $false,
	[switch]$with-chocolatey-apps = $false,
	[switch]$with-rdp = $false,
	[switch]$with-posh-upgrade = $false,
	[switch]$with-all = $false)

function usage() {
	$scriptName = $(split-path $MyInvocation.PSCommandPath -Leaf)
	Write-Host "in usage"
	Write-Host $scriptName

}

function IsAdmin() {
<#
.DESCRIPTION   
Check whether the script is run as administrator or not.

.OUTPUTS
A boolean value: $true if run as admin, $false if not run as admin.      
#>
	if (-not ([Security.Principal.WindowsPrincipal]
			  [Security.Principal.WindowsIdentity]::GetCurrent())
			  .IsInRole([Security.Principal.WindowsBuiltInRole]
			  "Administrator")) {
		Write-Verbose "Not running as administrator."
		return $false
	}
	return $true
}

function EnableRDP() {
	# src.: https://www.windows-commandline.com/enable-remote-desktop-command-line/
	reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
}


function InstallGitPreferences() {

	Write-Host "Adding git to the PATH..."

	# By default, git isn't available in the Path
	[Environment]::SetEnvironmentVariable(
		"Path",
		$env:Path + ";C:\Program Files\Git\bin",
		[EnvironmentVariableTarget]::Machine)
		
	# Update environment
	foreach($level in "Machine","User") {
		[Environment]::GetEnvironmentVariables($level)
	}
	
	Write-Host "Testing if git is available..."
	try {
		git --version >$null 2>&1
	} catch {
		Write-Error "Git is not available exiting..."
		exit
	}
		
	Write-Host "Installing git preferences..."
	
}

function InstallPowerShellPreferences() {

	Write-Host "Installing ConEmu preferences..."
	Copy-Item ConEmu.xml $env:APPDATA\ConEmu.xml
}

usage
exit


# Open a PowerShell prompt as admin and type
# PowerShell.exe -ExecutionPolicy AllSigned
# execute this script
# iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/wget/powershell-windows-install/master/install.ps1'))

# Display .NET framework installed on the machine.
# src.: http://stackoverflow.com/a/3495491/3514658
Write-Host "The versions ot the .NET framework installed on this machine:"
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse |
Get-ItemProperty -name Version,Release -EA 0 |
Where { $_.PSChildName -match '^(?!S)\p{L}'} |
Select PSChildName, Version, Release, @{
  name="Product"
  expression={
      switch -regex ($_.Release) {
        "378389" { [Version]"4.5" }
        "378675|378758" { [Version]"4.5.1" }
        "379893" { [Version]"4.5.2" }
        "393295|393297" { [Version]"4.6" }
        "394254|394271" { [Version]"4.6.1" }
        "394802|394806" { [Version]"4.6.2" }
        {$_ -gt 394806} { [Version]"4.6.2 or higher" }
      }
    }
}

Write-Host "The PowerShell version you are running:"
$PSVersionTable.PSVersion

Write-Host "Press any key to continue and install chocolatey..."
Write-Host "Note: This might take some time if at least .NET framework 4 is not installed."
# src.: https://technet.microsoft.com/en-us/library/ff730938.aspx
$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

Write-Host "Installing chocolatey..."
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

Write-Host "Installing some chocolatey packages..."
choco install `
    7zip.install `
    bleachbit `
    chocolateygui `
    ccleaner `
    conemu `
    filezilla `
    firefox `
    git `
    googlechrome `
    hashcheck `
    libreoffice `
    mpv `
    notepadplusplus.install `
    qbittorrent `
    python ` # A qbittorrent dependency
    skype `
    vlc `
    --yes


Start-Process -FilePath "git" -ArgumentList "clone --recursive https://github.com/wget/powershell-windows-install.git" -NoNewWindow -Wait -Passthru
Set-Location powershell-windows-install




Write-Host "Installing PowerShell preferences..."
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host "Support for PowerShell 2.0 is deprecated in posh-git. The latter will not be installed."
    Write-Host "As the dependency posh-git can not be satisfied, oh-my-posh cannot be installed either."
    Write-Host "While both could be installed on PowerShell versions 3.0 and 4.0, this requires to much hassle."
    Write-Host "Please update to the latest PowerShell version available."
    Write-Host "We are thus exiting here. Bye."
    exit
}

Write-Host "Trusting the PSGallery..."
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

Write-Host "Installing posh-git..."
Install-Module posh-git -Scope CurrentUser

Write-Host "Installing oh-my-posh..."
Install-Module oh-my-posh -Scope CurrentUser
"Import-Module oh-my-posh" | Out-File -Append $Home\Documents\WindowsPowerShell\profile.ps1

Write-Host "Installing Get-PackageUpdates"
Install-Module Get-PackageUpdates -Scope CurrentUser
# Creating a scheduled task requires administrator priviledges and requires
# either really recent Cmdlets or a .NET wrapper to discuss with the Win32 API.
# src.: https://taskscheduler.codeplex.com/
Unregister-ScheduledTask -TaskName 'DisplayUpdates' -Confirm:$false
# Register-ScheduledJob -Name 'DisplayUpdates' -Trigger $jobTrigger -FilePath $(Join-Path $([Environment]::GetFolderPath('MyDocuments')) 'WindowsPowerShell\Scripts\DisplayUpdates.ps1')
# While the following line is working, it does require to specify a password on
# the command line. Things cannot be automated properly.
# schtasks /Create /S "$env:computername" /U "$([Environment]::UserName)" /TN 'DisplayUpdates' /SC ONLOGON /TR "$(Join-Path $([Environment]::GetFolderPath('MyDocuments')) 'WindowsPowerShell\Scripts\DisplayUpdates.ps1')"
$script = "$(Join-Path $([Environment]::GetFolderPath('MyDocuments')) 'WindowsPowerShell\Scripts\DisplayUpdates.ps1')"
$action = New-ScheduledTaskAction -Execute "$PsHome\powershell.exe" -Argument "-NonInteractive -NoLogo -NoProfile -File $script"
$trigger = New-ScheduledTaskTrigger -AtLogon
$task = New-ScheduledTask -Action $action -Trigger $trigger -Settings (New-ScheduledTaskSettingsSet)
Register-ScheduledTask -TaskName 'DisplayUpdates' -InputObject $task -User 'pixinko' -Password 'ObBah1XzAieEdQzcC74XW0ImBKd6dn'

# If using an account like 'NT AUTHORITY\SYSTEM', this does not work. If
# specifiying the exact username, without password, this is working but a
# powershell window pops up. If we specify the password of the account, this is
# working silently.
#
Add-Type -Path './v4.0/Microsoft.Win32.TaskScheduler.dll'



# Ideas
#
# Install Windows 7 updates
# Set Windows Update to Manual, if they are set on Automatic, it will fail with the code 0x8024800C src.: https://blogs.technet.microsoft.com/trentsh/2010/08/12/error-number-0x8024800c-running-windows-update/
# Or you go in Windows Update and let the install automatically install the required WIndows Update install.
#https://download.microsoft.com/download/5/D/0/5D0821EB-A92D-4CA2-9020-EC41D56B074F/Windows6.1-KB3020369-x64.msu
# http://download.windowsupdate.com/d/msdownload/update/software/updt/2016/05/windows6.1-kb3125574-v4-x64_2dafb1d203c8964239af3048b5dd4b1264cd93b9.msu

# https://www.appveyor.com/docs/packaging-artifacts/#permalink-to-the-last-successful-build-artifact
# https://ci.appveyor.com/api/projects/lzybkr/psreadline/artifacts/bin/Release/PSReadline.zip?branch=master

# We need to sign this script now:
# https://blogs.technet.microsoft.com/heyscriptingguy/2010/06/16/hey-scripting-guy-how-can-i-sign-windows-powershell-scripts-with-an-enterprise-windows-pki-part-1-of-2/
# https://blogs.technet.microsoft.com/heyscriptingguy/2010/06/17/hey-scripting-guy-how-can-i-sign-windows-powershell-scripts-with-an-enterprise-windows-pki-part-2-of-2/
