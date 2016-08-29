##############################################################################
# Name: OneViewServerReportsModule.psm1 
# 
# Description: Wrapper functions to achieve oneview server and server profiles
#              functionalities. It uses HPOneView.200.psm1 module to
#              to invoke rest api of oneview
# 
# Date: Mar 2016 
##############################################################################

Import-Module .\Utility.psm1


#-------------------------------------------
#List of all resource URIs:
#-------------------------------------------
$Global:serverhardwareuri             = "/rest/server-hardware"
$Global:serverProfilesUri             = "/rest/server-profiles"
$Global:serverProfileTemplateUri      = "/rest/server-profile-templates"
$Global:audit_logsUri                 = "/rest/audit-logs"
$Global:alertsUri                     = "/rest/alerts"
$Global:reportsUri                    = "/rest/index/resources?category=server-hardware&sort=bay:asc"
$Global:firmwareBundleUri             = "/rest/firmware-drivers"
$Global:serverhardwaretypeUri         = "/rest/server-hardware-types" 

#------------------------------------------
#Output Files path :
#------------------------------------------
$Global:root                          = $PWD
$Global:reportsCsvFile                = "$Global:root\Output_File\Get-ServerInventory"+  "." + "$Global:ipAddress"
$Global:firmwareStatusCsvFile         = "$Global:root\Output_File\Get-ServersWaitingForPendingReboot"+  "." + "$Global:ipAddress"
$Global:InconsistentServers           = "$Global:root\Output_File\Get-ProfileState"+  "." + "$Global:ipAddress"
$Global:ServerReports                 = "$Global:root\Output_File\Get-ServerProfileHavingGivenFirmware"+  "." + "$Global:ipAddress"
$Global:profileFirmwareVersion        = "$Global:root\Output_File\Get-ServerProfileFirmwareCompliance"+  "." + "$Global:ipAddress"
$Global:ServerHardwarePowerState      = "$Global:root\Output_File\Get-ServerHardwarePowerState"+  "." + "$Global:ipAddress"

function DownloadAuditLog
{
    <#
      function to download audit logs from OneView
      It is not used. Kept here for future need        
    #>

    Process 
    {
        writeLog "FUNCTION BEGIN : DownloadAuditLog"

        $folder = Read-Host "Do you want to store audit_log file in a specified directory? choose Y/N" 

        if ($folder -eq "y" -or $folder -eq "Y")
        {
            $loc=Read-Host "Enter the directory to store audit_log file"
            $audit_log=Get-HPOVAuditLog $loc
            Write-Host "Succesfully Downloaded"
            writeLog "Audit log downloaded in $loc"
        }
        elseif($folder -eq "n" -or $folder -eq "N" -or $folder -eq $null)
        {
            Write-Host "audit-log file is stored in present working directory"
            writeLog "audit-log file is stored in present working directory"

            $audit_log=Get-HPOVAuditLog 
        }
        writeLog "FUNCTION END : DownloadAuditLog"
    }
}

function Get-ServerInventory
{
    <#
      Server inventory report
    #>

    Process 
    {
        writeLog "FUNCTION BEGIN : GET-SERVER INVENTORY"
            
        CreateNewGetFile $Global:reportsCsvFile
            
        $header = "Status, Name, Bay, Model, Processor_Type, Memory(Mb), Serial_Number, Mezzanine_Slot_Number, Mezzanine_Card_Model, RomVersion, iLO_IP_Address, iLO_Firmware_Version, Part_Number"
        $header | Add-Content $Global:reportsCsvFile 
                              
        $ret_json = Send-HPOVRequest -uri $Global:reportsUri GET

        if ($ret_json.members -ne 'null')
        {              
            foreach($name in $ret_json.members.getEnumerator())
            {
                $status = $name.status
                $names = $name.name
                $model = $name.attributes.model
                $partnum =  $name.attributes.partNumber
                $Serial_Number = $name.attributes.serial_number
                $bay = $name.attributes.bay
                $Memory = $name.attributes.memoryMb
                $Processor_Type = $name.attributes.processorType
                $RomVersion = $name.attributes.romVersion
                $iLO_IP_Address = $name.attributes.mpHostName
                $iLO_Firmware_Version = $name.attributes.mpFirmwareVersion
                $Mezzanine_Slot_Number = $name.multiAttributes.mezzSlots
                $Mezzanine_Card_Model = $name.multiAttributes.mezzNames          
                $status + "," +$names+ "," +$bay + "," +$model + "," + $Processor_Type + "," +$Memory + "," +$Serial_Number + "," + $Mezzanine_Slot_Number + "," +$Mezzanine_Card_Model+ "," +  $RomVersion + "," +$iLO_IP_Address  + "," +$iLO_Firmware_Version + "," +$partnum | Add-Content $Global:reportsCsvFile -force
            } 
            writeLog "The hardware details report is present in $Global:reportsCsvFile" 
            Write-Host "The hardware details report is present in $Global:reportsCsvFile" 
        }
        writeLog "FUNCTION END : GET-SERVER INVENTORY" 
    }
}

function Get-ServersWaitingForPendingReboot
{
    <#
        To get list of servers are in Pending Reboot state
        Servers will go this state after firmware is applied through SUT
        but not activated yet.
    #>
    
    Param
    (               
        [parameter(Mandatory = $false, HelpMessage = "Enter the inventory list")]
        [ValidateNotNullOrEmpty()]
        [System.String]$AppliancesList         
     )
       
    Process 
    {
        writeLog "FUNCTION BEGIN : GET-FIRMWARESTATUS"

        CreateNewGetFile $Global:firmwareStatusCsvFile
            
        if ( $AppliancesList )
        {
            $header = "appliance_address,serverName,installState"
            $header | Add-Content $Global:firmwareStatusCsvFile

            #importing the input csv file
            $inputFile = Import-csv $AppliancesList   
            foreach ($input in $inputFile)
            {
                $csvApplianceName = $input.applianceName
               
		        if ($csvApplianceName -eq $null)
                {
                    Write-Host " Please verify the Inventory File. "
                    writeLog " Please verify the Inventory File. "
                    exit    
                }
                Disconnect-HPOVMgmt
                $Global:Pswd = $null 
                if ($Global:Pswd -eq $null){
                    [System.Security.SecureString]$tempPassword = Read-Host "Enter onetime OneView Appliance Password to be connected! " -AsSecureString
                    $Global:Pswd = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($tempPassword))
                }
                $returnCode = connectFusion $csvApplianceName $Global:UserName  $Global:Pswd  $Global:authProvider
                validateConnection $returnCode                           
                    		
			    $serverHardwareUri = Send-HPOVRequest -uri $Global:serverhardwareuri GET  
                
                    foreach($serverName in $serverHardwareUri.members.GetEnumerator())
                    {
                        #check for the condition "installState": "InstalledPendingReboot"
                        if($serverName.serverSettings.firmwareAndDriversInstallState.installState -ne "null" -and $serverName.serverSettings.firmwareAndDriversInstallState.installState -eq "InstalledPendingReboot")
                        {
                            $serverHardwareName = $name.name
                            $installState = $name.serverSettings.firmwareAndDriversInstallState.installState 
                            $csvApplianceName + "," + $serverHardwareName + "," + $installState | Add-Content $Global:firmwareStatusCsvFile -Force  
                        }
                    }

                Write-Host "View the report in $Global:firmwareStatusCsvFile "
                writeLog "View the report in $Global:firmwareStatusCsvFile" 
            }
        }         
        writeLog "FUNCTION END : GET-FIRMWARESTATUS"
    }
}

function Get-ServerProfileHavingGivenFirmware
{
    <#
      To get the server profile names having 
      given the firmware baseline version .
    #>

    Param
    (               
        [parameter(Mandatory = $true, HelpMessage = "Enter the Inventory List")]
        [ValidateNotNullOrEmpty()]
        [System.String]$firmwareVersionList       
    )

    Process 
    {
        writeLog "FUNCTION BEGIN : GET-SERVER PROFILE FIRMWARE CHECK"

        CreateNewGetFile $Global:ServerReports
            
        $firmwareBundles = Send-HPOVRequest -uri $Global:firmwareBundleUri GET
        $serverProfiles = Send-HPOVRequest -uri $Global:serverProfilesUri GET
        $serverProfileTemplates = Send-HPOVRequest -uri $Global:serverProfileTemplateUri GET

        $header = "Server_Profile,Server_Profile_Template,Firmware_Version"
        $header | Add-Content $Global:ServerReports
          
        if ( $firmwareVersionList )
        {
            $inputData = Import-csv $firmwareVersionList
            foreach ($input in $inputData )
            {
			    $found = $false
                $csvFirmwareVersion = $input.firmware_version
                if ( $csvFirmwareVersion -eq $null )
                {
                    Write-Host " Please verify the Inventory File "
                    writeLog " Please verify the Inventory File "
                    exit
                }
                foreach($firmwares in $firmwareBundles.members.GetEnumerator())
                {
                    if($csvFirmwareVersion -eq $firmwares.version) 
                    {
                        $firmwareUri = $firmwares.uri            
                        foreach($serverProfile in $serverProfiles.members.GetEnumerator())
                        {
                            foreach($profileTemplates in $serverProfileTemplates.members.GetEnumerator())
                            {
                                if($profileTemplates.uri -eq $serverProfile.serverProfileTemplateUri -and $firmwareUri -eq $serverProfile.firmware.firmwareBaselineUri)
                                {
                                    $message = $serverProfile.name + "," + $profileTemplates.name +"," + $csvFirmwareVersion | Add-Content $Global:ServerReports -Force
                                }
                            }
							$found = $true
                        } 
                    }
					
                }
                if ($found -eq $false) 
                {
				    Write-Host "ERROR FOUND : Entered firmware version: $csvFirmwareVersion is not present in appliance." -ForegroundColor Red
                    writeLog "ERROR FOUND : Entered firmware version is not present in appliance."
			    }
            } 
            Write-Host "The report is in $Global:ServerReports path"
            writeLog "The report is in $Global:ServerReports path"
        }
        writeLog "FUNCTION END : GET-SERVER PROFILE FIRMWARE CHECK"
    }
}


function Get-ProfileState
{
<#
    
    Function to provide the list of server profile names which are in inconsistent state.    
    
#>
    
    Param(               
       
        [parameter(Mandatory = $true, HelpMessage = "Enter the inventory list")]
        [ValidateNotNullOrEmpty()]
        [System.String]$ServerDetails        

       )

    Process 
    {
        writeLog "FUNCTION BEGIN : GET-PROFILE STATE"

        CreateNewGetFile $Global:InconsistentServers
            
        $serverProfiles = Send-HPOVRequest -uri $Global:serverProfilesUri GET
        $serverProfileTemplates = Send-HPOVRequest -uri $Global:serverProfileTemplateUri GET

        $header = "Server_Name,Server_Profile_Template,State,Reason"
        $header | Add-Content $Global:InconsistentServers

        if ( $ServerDetails )
        {
            $inputFile = Import-csv $ServerDetails   
            foreach ($input in $inputFile)
            {
                $csvServerProfileTemplate = $input.serverProfileTemplate
                if ($csvServerProfileTemplate -eq $null)
                {
                    Write-Host " Please verify the Inventory File. "
                    writeLog " Please verify the Inventory File. "
                    exit    
                }  
                foreach($serverProfile in $serverProfiles.members.GetEnumerator())
                {
                    foreach($profileTemplates in $serverProfileTemplates.members.GetEnumerator())
                    {
                        #check for Inconsistent State
                        if (($serverProfile.templateCompliance -eq "NonCompliant") -and ($serverProfile.serverProfileTemplateUri -eq $profileTemplates.uri) -and ($profileTemplates.name -eq $csvServerProfileTemplate))
                        {
                            $spuri = $serverProfile.uri
                            $spname = $serverProfile.name 
                            $sptname = $profileTemplates.name
                            [system.string]$spState = "Inconsistent"
                            $response = Send-HPOVRequest -uri $spuri/compliance-preview  GET 
                            $resp = $response.automaticUpdates
                            $spname + "," + $sptname + "," + $spState +"," + $resp | Add-Content $Global:InconsistentServers -Force
                         }
                         #check for Consistent State
                         elseif (($serverProfile.templateCompliance -eq "Compliant") -and ($serverProfile.serverProfileTemplateUri -eq $profileTemplates.uri) -and ($profileTemplates.name -eq $csvServerProfileTemplate))
                         {
                            $spname = $serverProfile.name 
                            $sptname = $serverProfile.name
                            [system.string]$spState = "consistent" 
                            $spname + "," +$sptname + "," +$spState+","+ "-" | Add-Content $Global:InconsistentServers -Force
                         }
                     }
                }                             
            }
            Write-Host "The report is present in  $Global:InconsistentServers path."
            writeLog "The report is present in  $Global:InconsistentServers path."
        }
        writeLog "FUNCTION END : GET-PROFILE STATE"                
    }
} 

function Get-ServerProfileFirmwareCompliance
{
    <#
      Function to retrieve  the server profile names based on the firmware version provided.
    #>

    Param
    (               
        [parameter(Mandatory = $true, HelpMessage = "Enter the Inventory List")]
        [ValidateNotNullOrEmpty()]
        [System.String]$firmwareVersionList       
    )

    Process 
    {
        writeLog "FUNCTION BEGIN : GET-SERVER PROFILE FIRMWARE VERSION"

        CreateNewGetFile $Global:profileFirmwareVersion
            
        $firmwareBundles = Send-HPOVRequest -uri $Global:firmwareBundleUri GET
        $serverProfiles = Send-HPOVRequest -uri $Global:serverProfilesUri GET
            
        $header = "Server_Profile,Expected_Firmware_Version,Present_Firmware_Version,status"
        $header | Add-Content $Global:profileFirmwareVersion
          
        if ( $firmwareVersionList )
        {
            $inputData = Import-csv $firmwareVersionList
            foreach ($input in $inputData )
            {
                $found = $false
                $csvFirmwareVersion = $input.firmware_version
                if ( $csvFirmwareVersion -eq $null )
                {
                    Write-Host " Please verify the Inventory File "
                    writeLog " Please verify the Inventory File "
                    exit
                }
                foreach($firmware in $firmwareBundles.members.getEnumerator())
                {
                    $firmwareUri = $firmware.uri
                    $firmwareVersion = $firmware.version

                    Write-Host "Firmware bundle versions in OneView : $firmwareVersion"
                    writeLog "Firmware bundle versions in OneView : $firmwareVersion"

                    foreach($serverProfile in $serverProfiles.members.getEnumerator())
                    {
                        if($firmwareUri -eq $serverProfile.firmware.firmwareBaselineUri)
                        {
                            Write-Host "Firmware version in OneView bundle: $firmwareVersion"
                            Write-Host "Firmware version in input file : $csvFirmwareVersion"
                            Write-Host "Firmware version in profile page : $firmwareUri"
                            if($firmwareVersion -eq $csvFirmwareVersion)
                            {
                                $serverProfile.name + "," +  $csvFirmwareVersion +","+ $firmwareversion + "," + "In Compliance"| Add-Content $Global:profileFirmwareVersion -Force
                            }
                            else
                            {
                                $serverProfile.name + "," + $csvFirmwareVersion + "," +  $firmwareversion + "," + "Out Of Compliance" | Add-Content $Global:profileFirmwareVersion -Force
                            }
                            $found = $true
                        }                        
                    } 
                }
                if ($found -eq $false) 
                {
				    Write-Host "ERROR FOUND : Entered firmware version: $csvFirmwareVersion is not present in appliance." -ForegroundColor Red
                    writeLog "ERROR FOUND : Entered firmware version is not present in appliance."
			    }
            }
            Write-Host "The report is in $Global:profileFirmwareVersion path"
            writeLog "The report is in $Global:profileFirmwareVersion path" 
        }
        writeLog "FUNCTION END : GET-SERVER PROFILE FIRMWARE VERSION"    
    }
}


function Get-ServerHardwarePowerState
{
<#
    
    Function to provide the list of servers with power on/off state.    
    
#>   

    Process 
    {
        writeLog "FUNCTION BEGIN : Get-ServerHardwarePowerState"

        CreateNewGetFile $Global:ServerHardwarePowerState
            
        $serverHardwareResponse = Send-HPOVRequest -uri $Global:serverhardwareuri GET        

        $header = "Server_Name,Power_On,Power_Off"
        $header | Add-Content $Global:ServerHardwarePowerState

        if($serverHardwareResponse)
        {
            foreach($server in $serverHardwareResponse.members.getEnumerator())
            {
                $serverName = $server.name
                $powerState = $server.powerState
                if($powerState -eq "Off")
                {
                     $serverName + "," + " - " + "," + $powerState | Add-Content $Global:ServerHardwarePowerState -Force
                }
                elseif($powerState -eq "On")
                {
         
                     $serverName + "," + $powerState + "," + "-" | Add-Content $Global:ServerHardwarePowerState -Force
                }                
            }
            Write-Host "View the report in : $ServerHardwarePowerState"            
        }
    }
}