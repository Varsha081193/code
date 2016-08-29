#############################################################################################################
# Name: run_main_reports.ps1 
# Description: Main script to run reports, backup, restore, profiles, templates, POWER ON/OFF..etc
# 
# Date: Mar 2016 
#############################################################################################################
Import-Module .\OneViewServerManagementModule.psm1
Import-Module .\OneViewApplianceSettings.psm1
Import-Module .\OneViewJsonToSyslog.psm1
Import-Module .\OneViewServerReportsModule.psm1
Import-Module .\Utility.psm1
Import-Module .\HPOneView.200.psm1

$Global:UserName        = "administrator"
$Global:ipAddress       = "15.218.153.211"
$Global:authProvider    = "LOCAL"
$Global:Password        = $null

if ($Global:Password -eq $null){
    [System.Security.SecureString]$tempPassword = Read-Host "Enter onetime OneView Appliance Password to be connected! " -AsSecureString
    $Global:Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($tempPassword))

}



try
{  

    $version = (Get-HPOVXApiVersion -appliance $global:ipAddress).currentVersion    

    if($version -eq 300)
    {
        if((Get-Module -Name HPOneView.300) -ne $null){
            Remove-Module HPOneView.300
        } else {
            Remove-Module HPOneView.200
        }
        Import-Module .\HPOneView.300.psm1
        $return = connectFusion -ipAddress $Global:ipAddress -appUname $Global:UserName -appPwd $Global:Password -authProvider $Global:authProvider 
        validateConnection
    }
    elseif($version -eq 200)
    {
        
        $return = connectFusion -ipAddress $Global:ipAddress -appUname $Global:UserName -appPwd $Global:Password -authProvider $Global:authProvider 
        validateConnection
    }
}
catch
{
    $ErrorMessage = $_.Exception.Message
    Write-Host $ErrorMessage -ForegroundColor Red
    writeLog -message $ErrorMessage -debuglevel "ERROR"
    exit 

}


#*****************************************************************************************************************************************
#                                     OneView ServerManagement Module
#*****************************************************************************************************************************************

#Function to remove server profiles
#Remove-serverProfiles -ServerProfileNamesInput "$Global:root\Input_Files\input_to_Remove-serverProfiles.csv" 

#Function to remove server profile template
#Remove-serverProfileTemplate -ServerProfileTemplatesNamesInput "$Global:root\Input_Files\input_to_Remove-serverProfileTemplate.csv"

#Function to remove server hardware
#Remove-Servers -ServerNamesInput "$Global:root\Input_Files\input_to_Remove-servers.csv" 

#Function to remove enclosures
#Remove_enclosures -enclosureInputs "C:\Users\avars\Desktop\modified 2.0 and 3.0\Input_Files\input_to_RemoveEnclosures.csv"

#Function to create server profile templates via json input
#Create_ServerProfileTemplate -BasetemplateName "spt1" -ProfileTemplateInputs spt2 -TargetIpAddresses 16.91.21.11

#Function to create server profiles
#CreateServerProfile -ProfileInputs "$Global:root\Input_Files\input_to_CreateServerProfile.csv" -version $version

#Function to update the server profile in "INCONSISTENT" state
#UpdateServerProfile -ServerProfileTemplatesList "$Global:root\Input_Files\input_to_UpdateServerProfile.csv"

#Function to change the power state of the server 
#PowerState -PowerInput "$Global:root\Input_Files\input_to_PowerState.csv"

#Function to add enclosures
#Add_Enclosures -enclosureInputs "$Global:root\Input_Files\input_to_addEnclosures.csv" 

#Function to remove enclosures
#Remove_enclosures -enclosureInputs "$Global:root\Input_Files\input_to_RemoveEnclosures.csv"

#Function to add enclosures groups
#Add_EnclosureGroup -enclosureGroupInputs "$Global:root\Input_Files\input_to_AddEnclosureGroup.csv"

#Function to remove enclosures groups
#Remove_EnclosureGroups -enclosureGroupInputs "$Global:root\Input_Files\input_to_RemoveEnclosuresGroups.csv"

#Function to add LogicalInterconnectGroups
#Add_LogicalInterconnectGroups -Name "LIG1" -LogicalInterconnectGroups "$Global:root\Input_JSON_files\Add_LIG.json"

#Function to add networks(ethernet, FC, FCoE)
#AddNetworks -Network_List "$Global:root\Input_Files\input_to_AddNetworks.csv"

#Function to remove networks
#Remove-Networks -Network_List "$Global:root\Input_Files\input_to_removeNetworks.csv"

#Function to add ethernet networks in bulk
#Add-EthernetNetworksBulk -Name "Oneview" -vlanRange "110-200"

#Function to create NetworkSet
#Create_NetworkSet -Networks_List "$Global:root\Input_Files\input_to_createNetworkSet.json"

#Function to remove NetworkSets
#Remove-NetworkSet -NetworkSet_List "$Global:root\Input_Files\input_to_removeNetworkSet.csv"

#Function to add Storage Systems
#Add-StorageSystem -StorageSytemInput "$Global:root\Input_Files\input_to_AddStorageSystem.csv" -username "dcs"

#Function to remove Storage System
#Remove-StorageSystem -StorageSystem_List "$Global:root\Input_Files\input_to_removeStorageSystem.csv"

#Function to add storage pool
#Add-StoragePool -Storagepool_List "$Global:root\Input_Files\input_to_AddStoragePool.csv"

#Function to remove Storage Pool
#Remove-StoragePool -StoragePool_List "$Global:root\Input_Files\input_to_removeStoragePool.csv"

#Function to add volume template
#Add-VolumeTemplate -volumeInputs "$Global:root\Input_Files\input_to_AddVolumeTemplate.csv"

#Function to remove volume template
#Remove-VolumeTemplate -VolumeTemplate_List "$Global:root\Input_Files\input_to_removeVolumeTemplate.csv"

#Function to add Storage volume
#Add-StorageVolume -volumeDetails "$Global:root\Input_Files\input_to_AddStorageVolume.csv"

#Function to remove storage volume
#Remove-StorageVolume -StorageVolume_List "$Global:root\Input_Files\input_to_removeStorageVolume.csv"





#*****************************************************************************************************************************************
#                                     OneViewServerReportsModule Module
#*****************************************************************************************************************************************

#Function to check for profiles in consistent and inconsistent state  
#Get-ProfileState -ServerDetails  "$Global:root\Input_Files\input_to_Get-ProfileState.csv"

#Function to retrieve the profiles names based on the firmware version given
#Get-ServerProfileHavingGivenFirmware -firmwareVersionList "$Global:root\Input_Files\input_to_Get-ServerProfileHavingGivenFirmware.csv"

#Function to retrieve server hardware details
#Get-ServerInventory 

#Function to get the current firmware status for all servers for a given appliance
#Get-ServersWaitingForPendingReboot -AppliancesList "$Global:root\Input_Files\input_to_Get-ServersWaitingForPendingReboot.csv"

#Function to list the server profiles and its respective firmware versions 
#Get-ServerProfileFirmwareCompliance -firmwareVersionList "$Global:root\Input_Files\input_to_Get-ServerProfileFirmwareCompliance.csv"

Get-ServerHardwarePowerState

#*****************************************************************************************************************************************
#                                     OneViewApplianceSettings Module
#*****************************************************************************************************************************************

#Function to create and download backup of the appliance
#Create_and_downloadBackups -Location "$Global:root\Output_File"

#Function to restore the backup ( "Enter the backup file without the extension (eg:ci-000c2968c373_backup_2016-04-07_000810)")
#Restore_BackUp -BackUpFile ci-000c2968c373_backup_2016-04-07_000810


Disconnect-HPOVMgmt
if((Get-Module -Name HPOneView.300) -ne $null){
    Remove-Module HPOneView.300
} else {
    Remove-Module HPOneView.200
}
Remove-Module OneViewServerManagementModule
Remove-Module OneViewApplianceSettings
Remove-Module OneViewServerReportsModule
Remove-Module Utility