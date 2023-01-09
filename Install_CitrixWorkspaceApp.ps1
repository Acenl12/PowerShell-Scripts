#==========================================================================
#
# CITRIX WORKSPACE APP FOR WINDOWS version 1909 (released September 2019)
#
# AUTHOR: Dennis Span (https://dennisspan.com)
# DATE  : 11.09.2018
#
# COMMENT: This script installs and configured Citrix Workspace app for Windows version 1909 (released in September 2019)
#
# This script has been created for Windows 10 (all versions) and Windows Server 2016 version 1607 and higher
# This script has been tested on Windows Server 2016 version 1607 and Windows 10 version 1803
#          
# Change log:
# -----------
# 24.09.2018 Dennis Span: added registry value change to prevent unexpected MSI repairs from starting (line 225)
# 27.12.2018 Dennis Span: updated script for Citrix Workspace app version 1812
# 04.05.2019 Dennis Span: updated script for Citrix Workspace app version 1904
# 29.07.2019 Dennis Span: updated script for Citrix Workspace app version 1907
#                         Note: I also had to make some changes concerning the output of the Workspace app installer (see the article 'https://support.citrix.com/article/CTX257546' for more information). 
#                               And don't worry, the changes I made to this script also work with older versions of Citrix Workspace app
# 02.10.2019 Dennis Span: updated script for Citrix Workspace app version 1909
#==========================================================================
 
# Get the script parameters if there are any
param
(
    # The only parameter which is really required is 'Uninstall'
    # If no parameters are present or if the parameter is not
    # 'uninstall', an installation process is triggered
    [string]$Installationtype
)
 
# define Error handling
# note: do not change these values
$global:ErrorActionPreference = "Stop"
if($verbose){ $global:VerbosePreference = "Continue" }
 
############################
# Preparation              #
############################
 
# Disable File Security
$env:SEE_MASK_NOZONECHECKS = 1
 
# Custom variables [edit]
$BaseLogDir = "C:\Logs"                       # [edit] add the location of your log directory here
$PackageName = "Citrix Workspace app"         # [edit] enter the display name of the software (e.g. 'Arcobat Reader' or 'Microsoft Office')
 
# Global variables
$StartDir = $PSScriptRoot # the directory path of the script currently being executed
if (!($Installationtype -eq "Uninstall")) { $Installationtype = "Install" }
$LogDir = (Join-Path $BaseLogDir $PackageName).Replace(" ","_")
$LogFileName = "$($Installationtype)_$($PackageName).log"
$LogFile = Join-path $LogDir $LogFileName
 
# Create the log directory if it does not exist
if (!(Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType directory | Out-Null }
 
# Create new log file (overwrite existing one)
New-Item $LogFile -ItemType "file" -force | Out-Null
 
# Import the Dennis Span PowerShell Function Library
Import-Module "C:\Temp\DS_PowerShell_Function_Library.psm1"
 
DS_WriteLog "I" "START SCRIPT - $Installationtype $PackageName" $LogFile
DS_WriteLog "-" "" $LogFile
 
############################
# Pre-launch commands      #
############################
 
# Delete old log folders in the TEMP directory (in case there are any)
DS_WriteLog "I" "Delete old log folders" $LogFile
$Folders = Get-ChildItem $env:Temp -filter "CTXReceiverInstallLogs*"
if ( $Folders.Count -gt 0 ) {
    Foreach ( $Folder in $Folders ) {
        DS_DeleteDirectory -Directory $Folder.FullName
    }
} else {
    DS_WriteLog "I" "No existing log folders were found. Nothing to do." $LogFile
}
 
DS_WriteLog "-" "" $LogFile
 
# Only execute the following section during installation, not uninstallation
if (! ( $Installationtype -eq "Uninstall" )) {
    # Prevent the 'Add account' button right after installation
    # Note 1: this section is not required in case you rename 'CitrixWorkspaceApp.exe' to 'CitrixWorkspaceAppWeb.exe' (but it also does no harm so you can leave it as it is)
    # Note 2: 'CitrixWorkspaceAppWeb.exe' does NOT set the value 'EnableX1FTU' in the registry: it merely shows a Window at the end of the installation without the 'Add Account' button
    DS_WriteLog "I" "Prevent the 'Add account' button right after installation" $LogFile
    DS_SetRegistryValue -RegKeyPath "hklm:\SOFTWARE\Wow6432Node\Policies\Citrix" -RegValueName "EnableX1FTU" -RegValue "00000000" -Type "DWORD"
 
    DS_WriteLog "-" "" $LogFile
}
 
############################
# Installation             #
############################
 
# Install or uninstall software
$FileName = "CitrixWorkspaceApp.exe"                                                                    # [edit] enter the name of the installation file (e.g. 'MyApp.msi' or 'setup.exe')
if ( $Installationtype -eq "Uninstall" ) {   
    $Arguments = "/silent /uninstall"                                                                   # [edit] enter arguments (for MSI file the following arguments are added by default: /i #File# /qn /norestart / l*v #LogFile#)
} else {
    $Arguments = "/silent /includeSSON /FORCE_LAA=1 EnableCEIP=false /AutoUpdateCheck=disabled"         # [edit] enter arguments (for MSI file the following arguments are added by default: /i #File# /qn /norestart / l*v #LogFile#)
}
$FileSubfolder = "Files"                                                                                # [edit] enter the name of the subfolder which contains the installation file (e.g. 'Files' or 'MSI')
$FileFullPath = Join-Path $StartDir $FileSubfolder                                                      # Concatenate the two directories $StartDir and $InstallFileFolder
$File = Join-Path $FileFullPath $FileName
 
# Input for logging
if ( $Installationtype -eq "Uninstall" ) {
    $Result0 = "Uninstall"
    $Result1 = "uninstalled"
    $Result2 = "uninstallation"
} else {
    $Result0 = "Install"
    $Result1 = "installed"
    $Result2 = "installation"
}
 
# Logging
DS_WriteLog "I" "$Result0 Citrix Workspace app" $LogFile
DS_WriteLog "I" "-File name: $FileName" $LogFile
DS_WriteLog "I" "-File full path: $File" $LogFile
 
# Check if the installation file exists
if (! (Test-Path $File) ) {    
    DS_WriteLog "E" "The file '$File' does not exist!" $LogFile
    Exit 1
}
 
DS_WriteLog "I" "-Command: Start-Process -FilePath $File -ArgumentList $arguments -PassThru -ErrorAction Stop" $LogFile
DS_WriteLog "I" "Run the $Result2..." $LogFile
try {
    $process = Start-Process -FilePath $File -ArgumentList $arguments -PassThru -ErrorAction Stop
    try { 
        Wait-Process -InputObject $process
        switch ($Process.ExitCode)
        {        
            0 { DS_WriteLog "S" "The software was $Result1 successfully (exit code: 0)" $LogFile }
            3 { DS_WriteLog "S" "The software was $Result1 successfully (exit code: 3)" $LogFile } # Some Citrix products exit with 3 instead of 0
            1603 { DS_WriteLog "E" "A fatal error occurred (exit code: 1603). Some applications throw this error when the software is already (correctly) installed! Please check." $LogFile }
            1605 { DS_WriteLog "I" "The software is not currently installed on this machine (exit code: 1605)" $LogFile }
            1619 { 
                DS_WriteLog "E" "The installation files cannot be found. The PS1 script should be in the root directory and all source files in the subdirectory 'Files' (exit code: 1619)" $LogFile 
                Exit 1
                }
            3010 { DS_WriteLog "W" "A reboot is required (exit code: 3010)!" $LogFile }
            default { 
                [string]$ExitCode = $Process.ExitCode
                DS_WriteLog "E" "The $Result2 ended in an error (exit code: $ExitCode)!" $LogFile
                Exit 1
            }
        }
    } catch {
        DS_WriteLog "E" "An error occurred while trying to wait for the $Result2 process (error: $($Error[0]))." $LogFile
    }
} catch {
    switch ($Process.ExitCode)
    {        
        0 { DS_WriteLog "S" "The software was $Result1 successfully (exit code: 0)" $LogFile }
        3 { DS_WriteLog "S" "The software was $Result1 successfully (exit code: 3)" $LogFile } # Some Citrix products exit with 3 instead of 0
        1603 { DS_WriteLog "E" "A fatal error occurred (exit code: 1603). Some applications throw this error when the software is already (correctly) installed! Please check." $LogFile }
        1605 { DS_WriteLog "I" "The software is not currently installed on this machine (exit code: 1605)" $LogFile }
        1619 { 
            DS_WriteLog "E" "The installation files cannot be found. The PS1 script should be in the root directory and all source files in the subdirectory 'Files' (exit code: 1619)" $LogFile 
            Exit 1
            }
        3010 { DS_WriteLog "W" "A reboot is required (exit code: 3010)!" $LogFile }
        default { 
            [string]$ExitCode = $Process.ExitCode
            DS_WriteLog "E" "The $Result2 ended in an error (exit code: $ExitCode)!" $LogFile
            Exit 1
        }
    }
}
 
#DS_InstallOrUninstallSoftware -File $File -InstallationType $Installationtype -Arguments $Arguments
 
DS_WriteLog "-" "" $LogFile
 
############################
# Post-launch commands     #
############################
 
if ( $Installationtype -eq "Uninstall" ) {
    # POST-CONFIGURATION FOR UNINSTALLATIONS
 
    # Cleanup remaining registry entries:
    # Reference: https://docs.citrix.com/en-us/citrix-workspace-app-for-windows/install/ica-install-manual.html#to-uninstall-citrix-workspace-app-for-windows-using-the-command-line-interface
    DS_WriteLog "I" "Cleanup: delete the Citrix Workspace app local machine keys" $LogFile
    DS_DeleteRegistryKey -RegKeyPath "hklm:\SOFTWARE\Policies\Citrix\ICA Client"
    DS_DeleteRegistryKey -RegKeyPath   "hklm:\SOFTWARE\Wow6432Node\Policies\Citrix\ICA Client"
    DS_DeleteRegistryValue -RegKeyPath "hklm:\SOFTWARE\Wow6432Node\Policies\Citrix" -RegValueName "EnableX1FTU"
    DS_DeleteRegistryValue -RegKeyPath "hklm:\SYSTEM\CurrentControlSet\Control\NetworkProvider\ProviderOrder" -RegValueName "PnSson"   # This is merely an additional check/cleanup. Under normal circumstances this is not required.
 
    DS_WriteLog "-" "" $LogFile
} else {
    # POST-CONFIGURATION FOR INSTALLATIONS
 
    # Import the Client Selective Trust registry keys and values. This prevents annoying security popup message regarding permissions for access to files, microphones, cameras, scanners, etc. in the local intranet and trusted sites.
    # Reference: How to Configure Default Device Access Behavior of Receiver, XenDesktop and XenApp (https://support.citrix.com/article/CTX133565)
    DS_WriteLog "I" "Import the Client Selective Trust registry keys and values. This prevents security popup messages during logon" $LogFile
    $RegFile = Join-Path $StartDir "Files\CitrixWorkspaceApp_Client_Selective_Trust_x86_Dennisspan.com.reg"
    DS_ImportRegistryFile -FileName $RegFile
 
    DS_WriteLog "-" "" $LogFile
 
    # Prevent unexpected MSI repairs from starting
    # -Delete the value data from the WEB_CLIENT registry value (part of the Citrix Online Plug-in MSI)
    # -Each version of Citrix Workspace app has its own product ID:
    #    -AC1889E2C14E5E540855164ACCB19FF3 -> Citrix Receiver 4.12 (this is the latest and last version of Receiver. The replacement for Receiver is Workspace app)
    #    -D40311B1F8DD0004B8715A85DAECC4CF -> Citrix Workspace app version 1808
    #    -65DDBF745D30EBA42B298EB9F8EF598B -> Citrix Workspace app version 1809
    #    -230369BA6C7C7464683823509A70DF6E -> Citrix Workspace app version 1810
    #    -691BFE598F3E06243B378CC91B536771 -> Citrix Workspace app version 1812
    #    -52593DD2E7A97DE41BF6EED7F1579FA5 -> Citrix Workspace app version 1902
    #    -9BBCC4F9C00B64B4990698B41BB1A3AF -> Citrix Workspace app version 1903
    #    -88759762CEE8CF04C85B2D3727441362 -> Citrix Workspace app version 1904
    #    -D2C5650F878893E40B9B9562ED9373CA -> Citrix Workspace app version 1904.1
    #    -6A325AD5754E1B044A29EBB5065A2C67 -> Citrix Workspace app version 1905
    #    -195324F90296A2B46A9766A17E548F7D -> Citrix Workspace app version 1907
    #    -ACD95015F191DC94A873EF5561AE259C -> Citrix Workspace app version 1909
    $ProductID = "ACD95015F191DC94A873EF5561AE259C"
    DS_WriteLog "I" "Prevent unexpected MSI repairs from starting" $LogFile
    DS_SetRegistryValue -RegKeyPath "hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\$($ProductID)\Features" -RegValueName "WEB_CLIENT" -RegValue "" -Type "String"
    
    DS_WriteLog "-" "" $LogFile
      
    # This section only runs on Windows 10 and higher
    [int]$WindowsVersion = ([environment]::OSVersion.Version).Major
    if ( $WindowsVersion -ge 10 ) {
 
        # Prevent the Win+G popup on Windows 10 machines
        # Reference: -https://support.citrix.com/article/CTX226423
        #            -http://www.carlstalhood.com/receiver-for-windows/#registryvalues
        DS_WriteLog "I" "Prevent the Win+G popup on Windows 10 machines" $LogFile
        DS_SetRegistryValue -RegKeyPath "hklm:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -RegValueName "AllowGameDVR" -RegValue "00000000" -Type "DWORD"
 
        DS_WriteLog "-" "" $LogFile
 
        # Fix the error ‘Failed to get network providers’ under Advanced Settings of the Network Adaptor when Citrix Workspace app with Single Sign-on (SSON) is installed (reference: https://support.citrix.com/article/CTX229052)
        # Note 1: this issue is fixed from Windows 10 version 1803. That is why this section only runs on Windows 10 version 1709.
        # Note 2: in Windows 10, the provider order is based on the value of the particular item in the registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\NetworkProvider\ProviderOrder'
        #         By default, each network provider item gets a value of one thousands or higher, always an even 1000 value. For example: 1000, 2000, 3000, etc.
        [string]$WindowsVersionRelease = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" -Name ReleaseID).ReleaseId
        if ( $WindowsVersionRelease -eq "1709" ) {
            DS_WriteLog "I" "Fix the error 'Failed to get network providers' under Advanced Settings of the Network Adapter (for Windows 10 version 1709 only!)" $LogFile
            DS_SetRegistryValue -RegKeyPath "hklm:\SYSTEM\CurrentControlSet\Control\NetworkProvider\ProviderOrder" -RegValueName "PnSson" -RegValue "3001" -Type "DWORD"
 
            DS_WriteLog "-" "" $LogFile
        }
    }
 
    # Remove the shortcut from the 'Programs\Startup' folder (if exist)
    DS_WriteLog "I" "Remove the Citrix Workspace app shortcut from the 'Programs\Startup' folder" $LogFile
    $File = Join-Path $env:AllUsersProfile "Start Menu\Programs\Startup\Citrix Workspace.lnk"
    DS_DeleteFile -File $File
 
    DS_WriteLog "-" "" $LogFile
        
    # Remove the shortcut from the 'Programs' folder (if exist)
    DS_WriteLog "I" "Remove the Citrix Workspace app shortcut from the 'Programs' folder" $LogFile
    $File = Join-Path $env:AllUsersProfile "Start Menu\Programs\Citrix Workspace.lnk"
    DS_DeleteFile -File $File
 
    DS_WriteLog "-" "" $LogFile
}
 
# Do the following for both installations and uninstallations
# Determine the folder name containing the Citrix log files (e.g. C:\Windows\Temp\CTXReceiverInstallLogs-20160218-202413)
DS_WriteLog "I" "Copy the log files from the TEMP directory to '$LogDir'" $LogFile
$CitrixLogPath = (gci -directory -path $env:Temp -filter "CTXReceiverInstallLogs*").FullName
if ( Test-Path ( $CitrixLogPath + "\*.log" ) ) {
    $Source = Join-Path $CitrixLogPath "*.log"
    DS_WriteLog "I" "Source files          = $Source" $LogFile
    DS_WriteLog "I" "Destination directory = $LogDir " $LogFile
    DS_CopyFile -SourceFiles $Source -Destination $LogDir
} else {
    DS_WriteLog "I" "There are no log files in the directory '$CitrixLogPath'. Nothing to copy." $LogFile
}
 
############################
# Finalize                 #
############################
 
# Enable File Security  
Remove-Item env:\SEE_MASK_NOZONECHECKS
 
DS_WriteLog "-" "" $LogFile
DS_WriteLog "I" "End of script" $LogFile

